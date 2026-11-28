package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// A plan is a list of actions on findings, applied at once (docs/tui.md 5-7).
// The TUI builds one; the allow and ignore commands make one-action plans.

type actKind byte

const (
	actIgnore    actKind = 'I' // file -> .gitignore (and out of the index)
	actAllowFile actKind = 'F' // file -> path: line of the allowlist
	actAllowFP   actKind = 'A' // fingerprint -> allowlist
	actMarker    actKind = 'M' // segscan:allow in a comment on the line
)

type action struct {
	Kind actKind
	File string // repository path, from the top
	Line int    // actMarker; for actAllowFP the line shown in the comment
	FP   string // actAllowFP
	// Hash of the file when it was scanned (hex sha256); "" skips the
	// check. A file that changed since keeps its actions unapplied.
	Hash string
	// History: actIgnore of a file in HEAD is confirmed (the value is in
	// the history anyway).
	History bool
}

type plan struct {
	top       string // repository top
	allowPath string // the allowlist the scan uses
	actions   []action
}

// fileHash is what action.Hash holds.
func fileHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// applyResult lists what was done (or, dry, would be done) and what not.
type applyResult struct {
	Done    []string
	Skipped []string // not applied, with the reason
	Warn    []string
}

// apply carries the plan out, or only reports it when dry. Writes go
// through a temporary file and a rename. Order (docs/tui.md 6): the files
// themselves, then the allowlist and .gitignore, then git rm --cached. On
// an error it stops; every action is idempotent, so applying again is safe.
func (p *plan) apply(dry bool) (applyResult, error) {
	var r applyResult
	verb := func(done, would string) string {
		if dry {
			return would
		}
		return done
	}

	// Files that changed since the scan keep their actions.
	changed := map[string]bool{}
	current := map[string][]byte{}
	for _, a := range p.actions {
		if a.Hash == "" || changed[a.File] || current[a.File] != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(p.top, a.File))
		if err != nil || fileHash(data) != a.Hash {
			changed[a.File] = true
			r.Skipped = append(r.Skipped, a.File+": changed since the scan; rescan and mark it again")
			continue
		}
		current[a.File] = data
	}
	var acts []action
	for _, a := range p.actions {
		if !changed[a.File] {
			acts = append(acts, a)
		}
	}

	// 1. Markers in the files themselves.
	byFile := map[string][]int{}
	for _, a := range acts {
		if a.Kind == actMarker {
			byFile[a.File] = append(byFile[a.File], a.Line)
		}
	}
	for _, f := range sortedKeys(byFile) {
		full := filepath.Join(p.top, f)
		if err := repoDir(p.top, filepath.Dir(full)); err != nil {
			r.Skipped = append(r.Skipped, f+": "+err.Error())
			continue
		}
		st, err := os.Lstat(full)
		if err != nil {
			return r, err
		}
		if !st.Mode().IsRegular() {
			r.Skipped = append(r.Skipped, f+": not a regular file; no marker")
			continue
		}
		data := current[f]
		if data == nil {
			if data, err = os.ReadFile(full); err != nil {
				return r, err
			}
		}
		lines := byFile[f]
		sort.Sort(sort.Reverse(sort.IntSlice(lines))) // bottom-up
		out, bad := data, false
		for _, no := range lines {
			next, err := markLine(f, out, no)
			if err != nil {
				r.Skipped = append(r.Skipped, err.Error())
				bad = true
				break
			}
			out = next
		}
		if bad || bytes.Equal(out, data) {
			if !bad {
				r.Done = append(r.Done, f+": already marked")
			}
			continue
		}
		if !dry {
			if err := atomicWrite(full, out, st.Mode().Perm()); err != nil {
				return r, err
			}
		}
		r.Done = append(r.Done, fmt.Sprintf("%s: %s segscan:allow on line(s) %s", f, verb("put", "would put"), joinInts(lines)))
	}

	// 2. The allowlist and .gitignore.
	var allowLines, ignoreLines []string
	var untrack []action
	untracked := map[string]bool{}
	for _, a := range acts {
		switch a.Kind {
		case actAllowFP:
			line := strings.ToLower(a.FP)
			if a.File != "" {
				line += fmt.Sprintf("  # %s:%d", a.File, a.Line) // where it was seen, never the text
			}
			allowLines = append(allowLines, line)
		case actAllowFile:
			line, err := allowPathLine(a.File)
			if err != nil {
				r.Skipped = append(r.Skipped, err.Error())
				continue
			}
			allowLines = append(allowLines, line)
		case actIgnore:
			if strings.ContainsAny(a.File, "\n\r") {
				r.Skipped = append(r.Skipped, fmt.Sprintf("%q: a newline in the name; not ignored", a.File))
				continue
			}
			if st, err := os.Lstat(filepath.Join(p.top, a.File)); err == nil && st.IsDir() {
				r.Skipped = append(r.Skipped, a.File+": a directory; name its files, or add it to .gitignore by hand")
				continue
			}
			tracked, inHead := p.gitState(a.File)
			if tracked && p.stagedDiffers(a.File, inHead) {
				// git rm --cached refuses it; say so before .gitignore
				// changes, so nothing is half done.
				r.Skipped = append(r.Skipped, a.File+": the staged version differs from both the file and HEAD; unstage it first (git restore --staged)")
				continue
			}
			if inHead && !a.History {
				r.Skipped = append(r.Skipped, a.File+": committed in HEAD, its content is in the history; confirm to ignore it anyway")
				continue
			}
			if inHead {
				r.Warn = append(r.Warn, a.File+": in HEAD, the value stays in the history")
			}
			if p.inManifest(a.File) {
				r.Warn = append(r.Warn, a.File+": has a .sec/manifest entry; check will miss the file in a clean clone")
			}
			ignoreLines = append(ignoreLines, "/"+gitignoreEscape(a.File))
			if tracked && !untracked[a.File] {
				untracked[a.File] = true // a file named twice leaves the index once
				untrack = append(untrack, a)
			}
		}
	}
	allowRel := p.allowPath
	if rel, err := filepath.Rel(p.top, p.allowPath); err == nil && !strings.HasPrefix(rel, "..") {
		allowRel = rel
	}
	for _, w := range []struct {
		path, name string
		lines      []string
		present    func(existing []byte, line string) bool
	}{
		{p.allowPath, allowRel, allowLines, allowHas},
		{filepath.Join(p.top, ".gitignore"), ".gitignore", ignoreLines, lineHas},
	} {
		if len(w.lines) > 0 {
			// A directory of the checkout may be a symlink (.sec itself):
			// never write through one, as the other .sec/ writers.
			if err := repoDir(p.top, filepath.Dir(w.path)); err != nil {
				return r, err
			}
		}
		added, err := appendLines(w.path, w.lines, w.present, dry)
		if err != nil {
			return r, err
		}
		for _, l := range added {
			r.Done = append(r.Done, fmt.Sprintf("%s: %s %s", w.name, verb("added", "would add"), l))
		}
	}

	// 3. Out of the index.
	for _, a := range untrack {
		if !dry {
			cmd := exec.Command("git", "-C", p.top, "--literal-pathspecs", "rm", "--cached", "-q", "--", a.File)
			if out, err := cmd.CombinedOutput(); err != nil {
				return r, fmt.Errorf("git rm --cached %s: %v %s", a.File, err, bytes.TrimSpace(out))
			}
		}
		r.Done = append(r.Done, fmt.Sprintf("%s: %s from the index (the file stays on disk)", a.File, verb("removed", "would be removed")))
	}
	return r, nil
}

// gitState reports whether a repository path is in the index and in HEAD.
func (p *plan) gitState(f string) (tracked, inHead bool) {
	out, _ := exec.Command("git", "-C", p.top, "--literal-pathspecs", "ls-files", "-z", "--", f).Output()
	tracked = len(out) > 0
	inHead = exec.Command("git", "-C", p.top, "cat-file", "-e", "HEAD:"+f).Run() == nil
	return
}

// stagedDiffers reports a file whose index version differs from both the
// working tree and HEAD (or that is new in the index and changed since):
// git rm --cached refuses to drop such a version.
func (p *plan) stagedDiffers(f string, inHead bool) bool {
	diff := func(args ...string) bool {
		cmd := exec.Command("git", append([]string{"-C", p.top, "--literal-pathspecs", "diff", "--quiet"}, args...)...)
		return cmd.Run() != nil
	}
	worktree := diff("--", f)
	return worktree && (!inHead || diff("--cached", "--", f))
}

func (p *plan) inManifest(f string) bool {
	data, err := os.ReadFile(filepath.Join(p.top, secDir, "manifest"))
	if err != nil {
		return false
	}
	es, _ := parseManifest(data)
	for _, e := range es {
		if e.Path == f {
			return true
		}
	}
	return false
}

// appendLines adds the lines not yet present to the file (creating it),
// keeping what is there. It returns the lines added.
func appendLines(path string, lines []string, present func([]byte, string) bool, dry bool) ([]string, error) {
	if len(lines) == 0 {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	out := append([]byte{}, data...)
	var added []string
	for _, l := range lines {
		if present(out, l) {
			continue
		}
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(append(out, l...), '\n')
		added = append(added, l)
	}
	if len(added) == 0 || dry {
		return added, nil
	}
	return added, atomicWrite(path, out, mode)
}

func lineHas(data []byte, line string) bool {
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimRight(l, "\r") == line {
			return true
		}
	}
	return false
}

// allowHas compares the entry (fp, word: or path:glob) of each allowlist
// line, without comments. Fingerprints and words are compared as the
// allowlist reads them, in lower case; path: globs as written, since paths
// are matched with their case.
func allowHas(data []byte, line string) bool {
	entry := func(l string) string {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		f := strings.Fields(l)
		if len(f) == 0 {
			return ""
		}
		if strings.HasPrefix(f[0], "path:") {
			return f[0]
		}
		return strings.ToLower(f[0])
	}
	want := entry(line)
	for _, l := range strings.Split(string(data), "\n") {
		if entry(l) == want {
			return true
		}
	}
	return false
}

// allowPathLine makes the path: line that skips exactly this file, and
// checks it with the allowlist's own parser: a name it cannot express
// (white space, '#') is refused rather than written wrong.
func allowPathLine(f string) (string, error) {
	line := "path:/" + globEscape(f)
	a := &allowList{fp: map[string]bool{}}
	a.add([]byte(line))
	if len(a.paths) != 1 || !a.skipPath(f) {
		return "", fmt.Errorf("%q: an allowlist path: line cannot name this file (white space or #); use the fingerprint", f)
	}
	return line, nil
}

// globEscape escapes the characters path.Match treats specially.
func globEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`*?[]\`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// gitignoreEscape escapes a repository path for an anchored .gitignore line.
func gitignoreEscape(s string) string {
	var b strings.Builder
	// After the leading "/" of an anchored line, # and ! are not special.
	for _, c := range s {
		if strings.ContainsRune(`*?[]\`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	out := b.String()
	// Trailing spaces are dropped by git unless escaped.
	trimmed := strings.TrimRight(out, " ")
	return trimmed + strings.Repeat(`\ `, len(out)-len(trimmed))
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	c := append([]int{}, v...)
	sort.Ints(c)
	for i, n := range c {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ", ")
}

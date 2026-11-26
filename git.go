package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

func gitOut(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	return strings.TrimRight(string(out), "\n"), err
}

func gitDir() string {
	d, err := gitOut("rev-parse", "--git-dir")
	if err != nil {
		return ""
	}
	return d
}

func gitFiles() ([]string, error) {
	out, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range bytes.Split(out, []byte{0}) {
		if len(f) > 0 {
			files = append(files, string(f))
		}
	}
	return files, nil
}

// scanDiff parses a unified diff (git diff, git log -p) and yields the added lines.
func scanDiff(r io.Reader, fn func(commit, file string, line int, text []byte)) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var commit, file string
	var remOld, remNew, newLine int
	for {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		line = bytes.TrimRight(line, "\n")
		if remOld > 0 || remNew > 0 {
			if len(line) == 0 {
				remOld--
				remNew--
				newLine++
				continue
			}
			switch line[0] {
			case '+':
				if file != "" {
					fn(commit, file, newLine, line[1:])
				}
				newLine++
				remNew--
				continue
			case '-':
				remOld--
				continue
			case ' ':
				remOld--
				remNew--
				newLine++
				continue
			case '\\':
				continue
			}
			remOld, remNew = 0, 0 // malformed hunk: treat the line as a header
		}
		switch {
		case bytes.HasPrefix(line, []byte("commit ")):
			commit = string(bytes.Fields(line[7:])[0])
		case bytes.HasPrefix(line, []byte("+++ ")):
			p := string(line[4:])
			if i := strings.IndexByte(p, '\t'); i >= 0 {
				p = p[:i]
			}
			if p == "/dev/null" {
				file = ""
			} else {
				file = strings.TrimPrefix(p, "b/")
			}
		case bytes.HasPrefix(line, []byte("@@ ")):
			f := bytes.Fields(line)
			if len(f) < 3 {
				continue
			}
			_, remOld = hunkRange(f[1])
			newLine, remNew = hunkRange(f[2])
		}
	}
}

// hunkRange parses "-12,3" or "+7" into (start, count).
func hunkRange(b []byte) (start, n int) {
	s := string(b[1:])
	n = 1
	if i := strings.IndexByte(s, ','); i >= 0 {
		n, _ = strconv.Atoi(s[i+1:])
		s = s[:i]
	}
	start, _ = strconv.Atoi(s)
	return
}

// ---------- allowlist ----------

var defaultExcludes = []string{
	"go.sum", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
	"composer.lock", "poetry.lock", "Gemfile.lock", "*.lock", "*.min.js", "*.min.css", "*.map",
	".segscan-allow",
	// .sec/ files are structured and validated by check; their paths, uuids
	// and globs only make noise in the statistical scan.
	".sec/allow", ".sec/config", ".sec/names", ".sec/manifest", ".sec/hooks/*",
}

type allowList struct {
	fp    map[string]bool
	paths []string
}

// loadAllow reads the file: each line is a fingerprint (fp) or "path:glob"; # starts a comment.
func loadAllow(path string, defaults bool) *allowList {
	a := &allowList{fp: map[string]bool{}}
	if defaults {
		a.paths = append(a.paths, defaultExcludes...)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return a
	}
	a.add(data)
	return a
}

// add reads allowlist lines: an fp, or path:glob; # starts a comment.
func (a *allowList) add(data []byte) {
	for _, l := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if p, ok := strings.CutPrefix(f[0], "path:"); ok {
			a.paths = append(a.paths, p)
		} else {
			a.fp[strings.ToLower(f[0])] = true
		}
	}
}

// skipPath reports whether a path:<glob> line covers the repository path p,
// the way .gitignore does: a glob that matches a directory on the way
// covers everything below it (path:data/*, path:data/ban/, path:vendor); a
// glob without "/" is matched against each name on the path, one with "/"
// against the path from the repository top; "**" stands for any depth.
func (a *allowList) skipPath(p string) bool {
	p = cleanRel(p)
	parts := strings.Split(p, "/")
	for _, pat := range a.paths {
		dirOnly := strings.HasSuffix(pat, "/")
		// A leading "/" anchors the glob at the repository top, as in
		// .gitignore: path:/data/ is data/ at the top only.
		anchored := strings.HasPrefix(pat, "/")
		pat = strings.TrimSuffix(cleanRel(strings.TrimLeft(pat, "/")), "/")
		if pat == "" || pat == "." {
			continue
		}
		for i := len(parts); i >= 1; i-- {
			if dirOnly && i == len(parts) {
				continue // a directory pattern never names the file itself
			}
			cand := strings.Join(parts[:i], "/")
			var ok bool
			switch {
			case strings.Contains(pat, "**"):
				ok = matchPath(pat, cand)
			case anchored || strings.Contains(pat, "/"):
				ok, _ = filepath.Match(pat, cand)
			default:
				ok, _ = filepath.Match(pat, parts[i-1])
			}
			if ok {
				return true
			}
		}
	}
	return false
}

// cleanRel turns a path as typed (./data/x, data//x) into the form the
// allowlist is written in.
func cleanRel(p string) string {
	p = path.Clean(filepath.ToSlash(p))
	return strings.TrimPrefix(p, "./")
}

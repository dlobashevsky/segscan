package main

// segscan init, key, manifest: commands of a .sec/ repository that work
// without the keystore (DESIGN.md 6.1, 6.2, 6.8).

import (
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// ---------- init ----------

const defaultConfig = `# segscan configuration, see DESIGN.md 4.1
project     = %s
keystore    = ~/.secshell/%s
roots       = nodes/*
skip_uuids  = all
binary      = scan
hook_scan   = warn
forbid      = .htpasswd*, *.key, id_rsa*, id_ed25519*, id_ecdsa*
`

const preCommitHook = `#!/bin/sh
# segscan: blocking checks of the index, then the statistical scan of the
# added lines (warn, block or off: hook_scan in .sec/config).
command -v segscan >/dev/null 2>&1 || { echo "pre-commit: segscan is not in PATH" >&2; exit 1; }
segscan check -staged || exit 1
exec segscan hook
`

const prePushHook = `#!/bin/sh
# segscan: blocking checks of every pushed commit. $1 is the remote name, or
# its URL when there is none; only that remote's refs are taken as checked.
command -v segscan >/dev/null 2>&1 || { echo "pre-push: segscan is not in PATH" >&2; exit 1; }
remote=$1
while read -r lref loid rref roid; do
	case "$loid" in *[!0]*) ;; *) continue ;; esac   # a deleted ref
	range="$loid"
	git config --get "remote.$remote.url" >/dev/null 2>&1 && range="$loid --not --remotes=$remote"
	case "$roid" in *[!0]*) git cat-file -e "$roid^{commit}" 2>/dev/null && range="$roid..$loid" ;; esac
	segscan check -range "$range" || exit 1
done
`

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.Parse(args)
	top, err := gitOut("rev-parse", "--show-toplevel")
	if err != nil || top == "" {
		die(fmt.Errorf("not a git repository"))
	}
	project := filepath.Base(top)
	files := []struct {
		name string
		body string
		mode os.FileMode
	}{
		{"config", fmt.Sprintf(defaultConfig, project, project), 0o644},
		{"names", namesHeader, 0o644},
		{"manifest", manifestHeader, 0o644},
		{"allow", "# segscan allowlist: one fp per line, or path:glob\n", 0o644},
		{".gitignore", "# the optional link to the keystore\n/keys\n", 0o644},
		{"hooks/pre-commit", preCommitHook, 0o755},
		{"hooks/pre-push", prePushHook, 0o755},
	}
	if err := os.MkdirAll(secPath(top, "hooks"), 0o755); err != nil {
		die(err)
	}
	for _, f := range files {
		p := secPath(top, f.name)
		if _, err := os.Lstat(p); err == nil {
			continue
		}
		if err := os.WriteFile(p, []byte(f.body), f.mode); err != nil {
			die(err)
		}
		fmt.Fprintf(os.Stderr, "segscan: created %s/%s\n", secDir, f.name)
	}
	hooks := secDir + "/hooks"
	if cur, _ := gitOut("-C", top, "config", "--get", "core.hooksPath"); cur != "" && cur != hooks {
		die(fmt.Errorf("core.hooksPath is already %q: set it to %s by hand", cur, hooks))
	}
	if _, err := gitOut("-C", top, "config", "core.hooksPath", hooks); err != nil {
		die(fmt.Errorf("git config core.hooksPath: %v", err))
	}
	if gd := gitDir(); gd != "" {
		if _, err := os.Stat(filepath.Join(gd, "hooks", "pre-commit")); err == nil {
			fmt.Fprintln(os.Stderr, "segscan: note: .git/hooks/pre-commit no longer runs (core.hooksPath is .sec/hooks)")
		}
	}
	fmt.Fprintf(os.Stderr, "segscan: core.hooksPath = %s\n", hooks)
}

// ---------- key ----------

func loadNamesOrDie(top string) *nameList {
	data, err := os.ReadFile(secPath(top, "names"))
	if err != nil && !os.IsNotExist(err) {
		die(err)
	}
	l, probs := parseNames(data)
	if len(probs) > 0 {
		die(fmt.Errorf("%s/names:%d: %s", secDir, probs[0].Line, probs[0].Msg))
	}
	return l
}

func writeFile(p string, data []byte) {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		die(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		die(err)
	}
}

// keyUses counts the placeholders of every key in the working tree: name -> file -> count.
func keyUses(top string) map[string]map[string]int {
	s, err := worktreeSnapshot(top)
	if err != nil {
		die(err)
	}
	uses := map[string]map[string]int{}
	ck := &checker{top: top, cache: map[string]*fileInfo{}}
	for _, f := range s.Files {
		if f.Link || f.Gitlink || strings.HasPrefix(f.Path, secDir+"/") {
			continue
		}
		for _, p := range ck.info(s, f).phs {
			if uses[p.Name] == nil {
				uses[p.Name] = map[string]int{}
			}
			uses[p.Name][f.Path]++
		}
	}
	return uses
}

const keyUsage = `usage:
  segscan key add <name> [-scope GLOB,...] [-base58]
                                             add a key name and print its placeholder
  segscan key rm <name>                      remove a key that no placeholder uses
  segscan key list                           keys, scopes and where they are used
`

func cmdKey(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, keyUsage)
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		keyAdd(args[1:])
	case "rm":
		keyRm(args[1:])
	case "list":
		keyList(args[1:])
	case "set", "check":
		die(fmt.Errorf("key %s needs the keystore, which is not implemented yet", args[0]))
	default:
		fmt.Fprint(os.Stderr, keyUsage)
		os.Exit(2)
	}
}

// oneArg parses flags that may come before or after the single argument.
func oneArg(fs *flag.FlagSet, args []string) string {
	fs.Parse(args)
	if fs.NArg() == 0 {
		die(fmt.Errorf("%s: a key name is needed", fs.Name()))
	}
	name := fs.Arg(0)
	fs.Parse(fs.Args()[1:])
	if fs.NArg() > 0 {
		die(fmt.Errorf("%s: unexpected %q", fs.Name(), fs.Arg(0)))
	}
	return name
}

func keyAdd(args []string) {
	fs := flag.NewFlagSet("key add", flag.ExitOnError)
	scope := fs.String("scope", "", "comma-separated path globs where the key may be used")
	b58 := fs.Bool("base58", false, "the value is always base58 (our own generated keys)")
	name := oneArg(fs, args)
	if !validName(name) {
		die(fmt.Errorf("bad key name %q: use A-Z a-z 0-9 _ .", name))
	}
	top, _ := mustSec()
	l := loadNamesOrDie(top)
	if l.ByName[name] != nil {
		die(fmt.Errorf("key %s already exists: %s", name, placeholderText(name, l.ByName[name].UUID)))
	}
	k := &keyName{Name: name, UUID: newUUID(), Scope: splitList(*scope), Base58: *b58}
	for _, s := range k.Scope {
		if err := checkGlob(s); err != nil {
			die(err)
		}
	}
	l.Keys = append(l.Keys, k)
	writeFile(secPath(top, "names"), l.format())
	fmt.Println(placeholderText(k.Name, k.UUID))
}

func keyRm(args []string) {
	fs := flag.NewFlagSet("key rm", flag.ExitOnError)
	name := oneArg(fs, args)
	top, _ := mustSec()
	l := loadNamesOrDie(top)
	if l.ByName[name] == nil {
		die(fmt.Errorf("no key %s", name))
	}
	if files := keyUses(top)[name]; len(files) > 0 {
		var list []string
		for f := range files {
			list = append(list, f)
		}
		die(fmt.Errorf("key %s is still used in %d file(s), e.g. %s", name, len(list), list[0]))
	}
	keys := l.Keys[:0]
	for _, k := range l.Keys {
		if k.Name != name {
			keys = append(keys, k)
		}
	}
	l.Keys = keys
	writeFile(secPath(top, "names"), l.format())
}

func keyList(args []string) {
	fs := flag.NewFlagSet("key list", flag.ExitOnError)
	noHeader := fs.Bool("no-header", false, "omit the TSV header line")
	fs.Parse(args)
	top, _ := mustSec()
	l := loadNamesOrDie(top)
	uses := keyUses(top)
	if !*noHeader {
		fmt.Println("name\tuuid\tscope\tflags\tuses\tfiles")
	}
	l.format() // sorts
	for _, k := range l.Keys {
		n := 0
		for _, c := range uses[k.Name] {
			n += c
		}
		flags := ""
		if k.Base58 {
			flags = "base58"
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%d\t%d\n", k.Name, k.UUID, strings.Join(k.Scope, ","), flags, n, len(uses[k.Name]))
	}
}

// ---------- manifest ----------

const manifestUsage = `usage:
  segscan manifest fix    add entries for new files under the node roots, drop entries of deleted ones
`

func cmdManifest(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, manifestUsage)
		os.Exit(2)
	}
	switch args[0] {
	case "fix":
		manifestFix(args[1:])
	case "pull", "check", "apply":
		die(fmt.Errorf("manifest %s reads live attributes, which is not implemented yet", args[0]))
	default:
		fmt.Fprint(os.Stderr, manifestUsage)
		os.Exit(2)
	}
}

// fileMode derives a file's mode from its directory's: no execute bits, no
// setuid, setgid or sticky. 0755 -> 0644, 2770 -> 0660.
func fileMode(dirMode string) string {
	m, err := strconv.ParseUint(dirMode, 8, 32)
	if err != nil {
		return "0600"
	}
	return fmt.Sprintf("%04o", m&^0o7111)
}

func manifestFix(args []string) {
	fs := flag.NewFlagSet("manifest fix", flag.ExitOnError)
	fs.Parse(args)
	top, cfg := mustSec()
	data, err := os.ReadFile(secPath(top, "manifest"))
	if err != nil && !os.IsNotExist(err) {
		die(err)
	}
	entries, probs := parseManifest(data)
	if len(probs) > 0 {
		die(fmt.Errorf("%s/manifest:%d: %s", secDir, probs[0].Line, probs[0].Msg))
	}
	byPath := map[string]*mEntry{}
	for _, e := range entries {
		byPath[e.Path] = e
	}
	files, err := worktreeFiles(top)
	if err != nil {
		die(err)
	}
	present := map[string]bool{}
	var added, removed int
	for _, f := range files {
		if strings.HasPrefix(f.Path, secDir+"/") {
			continue
		}
		root, ok := cfg.nodeRoot(f.Path)
		if !ok {
			continue
		}
		if f.Gitlink {
			fmt.Fprintf(os.Stderr, "! %s\tnot added: a submodule\n", f.Path)
			continue
		}
		present[f.Path] = true
		for d := path.Dir(f.Path); ; d = path.Dir(d) {
			present[d] = true
			if d == root || d == "." {
				break
			}
		}
		if byPath[f.Path] != nil {
			continue
		}
		if pat, bad := matchAny(cfg.Forbid, f.Path); bad {
			fmt.Fprintf(os.Stderr, "! %s\tnot added: matches forbid = %s\n", f.Path, pat)
			continue
		}
		e := &mEntry{Path: f.Path, Type: "f", Mode: "0600", Owner: "root", Group: "root"}
		from := "default"
		if f.Link {
			e.Type, e.Mode = "l", "0777"
		}
		for d := path.Dir(f.Path); ; d = path.Dir(d) {
			if p := byPath[d]; p != nil && p.Type == "d" {
				e.Owner, e.Group, from = p.Owner, p.Group, "from "+d
				if !f.Link {
					e.Mode = fileMode(p.Mode)
				}
				break
			}
			if d == root || d == "." {
				break
			}
		}
		entries = append(entries, e)
		byPath[e.Path] = e
		added++
		fmt.Fprintf(os.Stderr, "+ %s\t%s %s %s:%s\t(%s, review)\n", e.Path, e.Type, e.Mode, e.Owner, e.Group, from)
	}
	keep := entries[:0]
	for _, e := range entries {
		gone := false
		switch e.Type {
		case "f", "l":
			gone = !present[e.Path]
		case "d":
			st, err := os.Stat(filepath.Join(top, e.Path))
			gone = !present[e.Path] && (err != nil || !st.IsDir())
		}
		if gone {
			removed++
			fmt.Fprintf(os.Stderr, "- %s\n", e.Path)
			continue
		}
		keep = append(keep, e)
	}
	if added > 0 || removed > 0 {
		writeFile(secPath(top, "manifest"), formatManifest(keep))
	}
	fmt.Fprintf(os.Stderr, "segscan: manifest: %d added, %d removed\n", added, removed)
}

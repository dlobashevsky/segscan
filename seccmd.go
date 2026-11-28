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
# hook_model  = block        # pre-commit: model check of a changed .sec/segscan.model (off, warn, block)
# scan_bpc    = 4.5          # statistical scan: report only findings of at least N bits per char
# scan_minlen = 12           # statistical scan: ignore shorter random-looking strings
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
# segscan: blocking checks of every pushed commit. Commits are taken as
# already checked only if the destination advertises them now (ls-remote):
# local remote-tracking refs can be stale or belong to another remote. If
# ls-remote fails, the whole ancestry is checked.
command -v segscan >/dev/null 2>&1 || { echo "pre-push: segscan is not in PATH" >&2; exit 1; }
known=$(git ls-remote "$1" 2>/dev/null | while read -r oid ref; do
	git cat-file -e "$oid^{commit}" 2>/dev/null && printf ' ^%s' "$oid"
done)
while read -r lref loid rref roid; do
	case "$loid" in *[!0]*) ;; *) continue ;; esac   # a deleted ref
	# A tag on a blob or tree pushes that object, and check only reads
	# commits: refuse rather than let it through unchecked.
	git cat-file -e "$loid^{commit}" 2>/dev/null || {
		echo "pre-push: $lref is not a commit; segscan cannot check it (git push --no-verify to push anyway)" >&2
		exit 1
	}
	segscan check -range "$loid$known" || exit 1
done
`

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	noKS := fs.Bool("no-keystore", false, "do not create the keystore (a machine that only plans changes)")
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
	for _, d := range []string{secDir, secDir + "/hooks"} {
		if err := os.Mkdir(filepath.Join(top, d), 0o755); err != nil && !os.IsExist(err) {
			die(err)
		}
		if err := repoDir(top, filepath.Join(top, d)); err != nil {
			die(err)
		}
	}
	for _, f := range files {
		p := secPath(top, f.name)
		if _, err := os.Lstat(p); err == nil {
			continue
		}
		// O_EXCL: a symlink that appeared since the Lstat is not followed.
		fh, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
		if err != nil {
			die(err)
		}
		if _, err := fh.WriteString(f.body); err != nil {
			die(err)
		}
		if err := fh.Close(); err != nil {
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
	if *noKS {
		return
	}
	cfg, err := loadSecConfig(top)
	if err != nil {
		die(err)
	}
	msg, err := initKeystore(top, cfg)
	if err != nil {
		die(err)
	}
	fmt.Fprintln(os.Stderr, "segscan: "+msg)
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

// writeFile replaces a .sec/ file of the repository at top.
func writeFile(top, p string, data []byte) {
	if err := repoDir(top, filepath.Dir(p)); err != nil {
		die(err)
	}
	if err := atomicWrite(p, data, 0o644); err != nil {
		die(err)
	}
}

// repoDir checks that every component of dir below top is a real directory.
// A checkout can hold symlinks anywhere, .sec itself included; following one
// would let the repository redirect a write to any file the user can write.
// A dir outside top is not checked: the user named it.
func repoDir(top, dir string) error {
	rel, err := filepath.Rel(top, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	p := top
	for _, c := range strings.Split(rel, string(filepath.Separator)) {
		p = filepath.Join(p, c)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s: not a directory (a symlink?); refusing to write through it", p)
		}
	}
	return nil
}

// atomicWrite writes data to p through a new temporary file in the same
// directory. The temporary name is random and created with O_EXCL, so no
// file or symlink placed there beforehand is ever opened; the final rename
// replaces p itself, never what p points to.
func atomicWrite(p string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// keyUses counts the placeholders of every key in the working tree: name -> file -> count.
func keyUses(top string) map[string]map[string]int {
	s, err := worktreeSnapshot(top)
	if err != nil {
		die(err)
	}
	uses := map[string]map[string]int{}
	ck := &checker{top: top, cache: map[string]*fileInfo{}, chains: map[string]bool{}}
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
  segscan key set <name> [-gen N]            set the value: from stdin, or N random base58 chars   (keystore)
  segscan key check [-weak]                  names <-> keystore: missing, unknown, mismatched   (keystore)
  segscan key retire [-secret] <name>        retire a value no name uses any more; still searched   (keystore)
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
	case "set":
		keySet(args[1:])
	case "check":
		keyCheck(args[1:])
	case "retire":
		keyRetire(args[1:])
	case "forget":
		die(fmt.Errorf("key forget is not implemented yet: it needs the state of check -all (DESIGN.md 4.3)"))
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
	writeFile(top, secPath(top, "names"), l.format())
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
	writeFile(top, secPath(top, "names"), l.format())
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
		// Only f and l entries need a file in the tree. d and s entries
		// describe the target: git keeps no empty directory, and a secret
		// file is never in the tree, so they are removed by hand only.
		if e.Type == "f" || e.Type == "l" {
			gone = !present[e.Path]
		}
		if gone {
			removed++
			fmt.Fprintf(os.Stderr, "- %s\n", e.Path)
			continue
		}
		keep = append(keep, e)
	}
	if added > 0 || removed > 0 {
		writeFile(top, secPath(top, "manifest"), formatManifest(keep))
	}
	fmt.Fprintf(os.Stderr, "segscan: manifest: %d added, %d removed\n", added, removed)
	if added+removed > 0 {
		fmt.Fprintf(os.Stderr, "segscan: review %s/manifest, then git add %s/manifest: the hook checks what is staged\n", secDir, secDir)
	}
}

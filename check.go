package main

// segscan check: the blocking checks of a .sec/ repository (DESIGN.md 6.5) on
// the working tree, the index, or every commit of a range.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ---------- snapshots: a set of files from the working tree, the index or a commit ----------

type snapFile struct {
	Path    string
	Link    bool
	Gitlink bool   // a submodule: its path is checked, its content is not read
	OID     string // blob id; "" for the working tree
}

type snapshot struct {
	Commit string // commit id, "" for the working tree and the index
	Files  []snapFile
	read   func(snapFile) ([]byte, error)
	byPath map[string]*snapFile
}

func (s *snapshot) index() {
	s.byPath = make(map[string]*snapFile, len(s.Files))
	for i := range s.Files {
		s.byPath[s.Files[i].Path] = &s.Files[i]
	}
}

// file returns the content of a path, or nil if the snapshot has no such regular file.
func (s *snapshot) file(p string) []byte {
	f := s.byPath[p]
	if f == nil || f.Link || f.Gitlink {
		return nil
	}
	data, err := s.read(*f)
	if err != nil {
		die(err)
	}
	return data
}

// gitZ runs git in dir and splits its -z output.
func gitZ(dir string, args ...string) ([]string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v", strings.Join(args, " "), err)
	}
	var recs []string
	for _, r := range bytes.Split(out, []byte{0}) {
		if len(r) > 0 {
			recs = append(recs, string(r))
		}
	}
	return recs, nil
}

// worktreeFiles lists tracked and untracked, not ignored files that exist on disk.
func worktreeFiles(top string) ([]snapFile, error) {
	recs, err := gitZ(top, "ls-files", "-co", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	sparse, err := skipWorktree(top)
	if err != nil {
		return nil, err
	}
	var out []snapFile
	seen := map[string]bool{}
	for _, p := range recs {
		p = strings.TrimSuffix(p, "/") // an untracked nested repository is listed as dir/
		if seen[p] {
			continue
		}
		seen[p] = true
		st, err := os.Lstat(filepath.Join(top, p))
		switch {
		case err != nil:
			// Hidden by a sparse checkout: still part of the tree, read from
			// the index, or manifest fix and key rm would take it as deleted.
			if f, ok := sparse[p]; ok {
				out = append(out, f)
			}
		case st.IsDir(): // git lists a directory only for a submodule or a nested repository
			out = append(out, snapFile{Path: p, Gitlink: true})
		case st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0:
			out = append(out, snapFile{Path: p, Link: st.Mode()&os.ModeSymlink != 0})
		}
	}
	return out, nil
}

// skipWorktree returns the index entries marked skip-worktree (sparse
// checkout), by path.
func skipWorktree(top string) (map[string]snapFile, error) {
	recs, err := gitZ(top, "ls-files", "-t", "-s", "-z")
	if err != nil {
		return nil, err
	}
	out := map[string]snapFile{}
	for _, r := range recs {
		// <tag> <mode> <oid> <stage>\t<path>
		meta, p, ok := strings.Cut(r, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 4 || f[0] != "S" {
			continue
		}
		out[p] = snapFile{Path: p, Link: f[1] == "120000", Gitlink: f[1] == "160000", OID: f[2]}
	}
	return out, nil
}

func worktreeSnapshot(top string) (*snapshot, error) {
	files, err := worktreeFiles(top)
	if err != nil {
		return nil, err
	}
	s := &snapshot{Files: files, read: func(f snapFile) ([]byte, error) {
		if f.OID != "" { // a sparse-checkout entry, not on disk
			return exec.Command("git", "-C", top, "cat-file", "blob", f.OID).Output()
		}
		return os.ReadFile(filepath.Join(top, f.Path))
	}}
	s.index()
	return s, nil
}

func indexSnapshot(top string, cf *catFile) (*snapshot, error) {
	recs, err := gitZ(top, "ls-files", "-s", "-z")
	if err != nil {
		return nil, err
	}
	s := &snapshot{read: cf.readFile}
	seen := map[string]bool{}
	for _, r := range recs {
		// <mode> <oid> <stage>\t<path>
		meta, p, ok := strings.Cut(r, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 || seen[p] {
			continue
		}
		seen[p] = true
		s.Files = append(s.Files, snapFile{Path: p, Link: f[0] == "120000", Gitlink: f[0] == "160000", OID: f[1]})
	}
	s.index()
	return s, nil
}

func commitSnapshot(top string, cf *catFile, commit string) (*snapshot, error) {
	recs, err := gitZ(top, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	s := &snapshot{Commit: commit, read: cf.readFile}
	for _, r := range recs {
		// <mode> <type> <oid>\t<path>
		meta, p, ok := strings.Cut(r, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 || f[1] != "blob" && f[1] != "commit" {
			continue
		}
		s.Files = append(s.Files, snapFile{Path: p, Link: f[0] == "120000", Gitlink: f[1] == "commit", OID: f[2]})
	}
	s.index()
	return s, nil
}

// catFile reads blobs through one long-running git cat-file --batch.
type catFile struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func newCatFile(top string) (*catFile, error) {
	cmd := exec.Command("git", "-C", top, "cat-file", "--batch")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &catFile{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<16)}, nil
}

func (c *catFile) readFile(f snapFile) ([]byte, error) {
	if _, err := fmt.Fprintf(c.in, "%s\n", f.OID); err != nil {
		return nil, err
	}
	hdr, err := c.out.ReadString('\n')
	if err != nil {
		return nil, err
	}
	h := strings.Fields(hdr)
	if len(h) != 3 {
		return nil, fmt.Errorf("git cat-file: %s: %s", f.Path, strings.TrimSpace(hdr))
	}
	n, err := strconv.Atoi(h[2])
	if err != nil {
		return nil, err
	}
	buf := make([]byte, n+1)
	if _, err := io.ReadFull(c.out, buf); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *catFile) close() {
	c.in.Close()
	c.cmd.Wait()
}

// ---------- findings ----------

// Check names, in the order of DESIGN.md 6.5.
const (
	ckConfig    = "config"
	ckGrammar   = "grammar"
	ckNames     = "names"
	ckManifest  = "manifest"
	ckForbidden = "forbidden"
	ckPrivate   = "private_key"
)

type checkFinding struct {
	Commit string `json:"commit"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Col    int    `json:"col"`
	Check  string `json:"check"`
	Msg    string `json:"message"`

	fp string // allowlist fingerprint of a private key line
}

// ---------- per-file analysis (cached by blob id) ----------

type phAt struct {
	placeholder
	Line int
}

type fileInfo struct {
	phs   []phAt
	finds []checkFinding // without Commit and File
}

func isBinary(data []byte) bool {
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// analyzeFile does not depend on the allowlist, so its result can be cached
// by blob id across snapshots with different allowlists.
func analyzeFile(data []byte) *fileInfo {
	fi := &fileInfo{}
	binary := isBinary(data)
	if binary {
		if i := bytes.Index(data, phPrefix); i >= 0 {
			fi.finds = append(fi.finds, checkFinding{Col: i + 1, Check: ckGrammar, Msg: "placeholder in a binary file"})
		}
	}
	var pem pemState
	no := 0
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		no++
		line = bytes.TrimRight(line, "\r")
		if _, private := pem.feed(line); private {
			f := Finding{Text: string(line)}
			fi.finds = append(fi.finds, checkFinding{Line: no, Col: 1, Check: ckPrivate, Msg: pemLabel(line), fp: f.FP()})
		}
		// A binary file still gets the private key check, line by line;
		// only placeholders are not looked for in it.
		if binary || !bytes.Contains(line, phPrefix) {
			continue
		}
		good, bad := parsePlaceholders(line)
		for _, b := range bad {
			fi.finds = append(fi.finds, checkFinding{Line: no, Col: b.Col + 1, Check: ckGrammar, Msg: "malformed placeholder: " + b.Why})
		}
		for _, p := range good {
			for _, t := range p.Transforms {
				if !knownTransforms[t] {
					fi.finds = append(fi.finds, checkFinding{Line: no, Col: p.Col + 1, Check: ckGrammar, Msg: "unknown transform " + t})
				}
			}
			fi.phs = append(fi.phs, phAt{p, no})
		}
	}
	return fi
}

// ---------- checks over one snapshot ----------

type checker struct {
	top   string
	cache map[string]*fileInfo
}

func (ck *checker) info(s *snapshot, f snapFile) *fileInfo {
	if f.OID != "" {
		if fi := ck.cache[f.OID]; fi != nil {
			return fi
		}
	}
	data, err := s.read(f)
	if err != nil {
		die(err)
	}
	fi := analyzeFile(data)
	if f.OID != "" {
		ck.cache[f.OID] = fi
	}
	return fi
}

func (ck *checker) run(s *snapshot) []checkFinding {
	var out []checkFinding
	add := func(file string, line, col int, check, format string, a ...any) {
		out = append(out, checkFinding{Commit: s.Commit, File: file, Line: line, Col: col, Check: check, Msg: fmt.Sprintf(format, a...)})
	}
	cfgPath, namesPath, manPath := secDir+"/config", secDir+"/names", secDir+"/manifest"
	hasSec := false
	for _, f := range s.Files {
		if strings.HasPrefix(f.Path, secDir+"/") {
			hasSec = true
			break
		}
	}
	// .sec itself as a symlink, submodule or file: the snapshot would look
	// like one from before adoption and lose names, manifest and forbid.
	if f := s.byPath[secDir]; f != nil {
		hasSec = true
		add(secDir, 0, 0, ckConfig, "must be a directory")
	}

	// A symlink or submodule in place of a .sec/ file would read as missing
	// and fall back to defaults, dropping the repository's own forbid list.
	for _, p := range []string{cfgPath, namesPath, manPath, secDir + "/allow"} {
		if f := s.byPath[p]; f != nil && (f.Link || f.Gitlink) {
			add(p, 0, 0, ckConfig, "must be a regular file")
			continue
		}
		// A directory in its place: git lists only what is below it.
		for _, f := range s.Files {
			if strings.HasPrefix(f.Path, p+"/") {
				add(p, 0, 0, ckConfig, "must be a regular file, not a directory")
				break
			}
		}
	}
	cfg, err := parseSecConfig(s.file(cfgPath), filepath.Base(ck.top))
	if err != nil {
		add(cfgPath, 0, 0, ckConfig, "%v", err)
		cfg, _ = parseSecConfig(nil, filepath.Base(ck.top))
	}
	names, probs := parseNames(s.file(namesPath))
	for _, p := range probs {
		add(namesPath, p.Line, 0, ckNames, "%s", p.Msg)
	}
	entries, probs := parseManifest(s.file(manPath))
	for _, p := range probs {
		add(manPath, p.Line, 0, ckManifest, "%s", p.Msg)
	}
	man := map[string]*mEntry{}
	for _, e := range entries {
		man[e.Path] = e
	}
	// The allowlist of this snapshot, not of the working tree: an unstaged
	// fingerprint must not hide a staged key.
	allow := &allowList{fp: map[string]bool{}}
	allow.add(s.file(secDir + "/allow"))

	// Paths that may never be in the repository.
	forbidPrefix := []string{secDir + "/keys"}
	ks := cfg.keystoreDir()
	// A path that climbs with ".." can leave the repository and come back
	// through a symlink of the working tree, and then neither view below
	// can tell where it lands in the snapshot. Such a path is refused; the
	// default lives under ~ and never needs one.
	if err := checkKeystorePath(ks); err != nil {
		add(cfgPath, 0, 0, ckConfig, "%v", err)
	}
	// Two views of where the keystore is, and both count:
	//  - lexical: a relative path names a place in the repository whatever
	//    the working tree has there now (a directory in the snapshot may be a
	//    symlink elsewhere in the working tree);
	//  - real: a path that reaches the repository through a symlink alias is
	//    still inside it.
	//  - lexical below an alias: once a prefix of an absolute path is the
	//    repository (literally or through a symlink), the rest names a place
	//    in it, whatever the working tree has there now.
	var rels []string
	if !filepath.IsAbs(ks) {
		rels = append(rels, filepath.Clean(ks))
		// Not filepath.Join: that would collapse ".." before symlinks
		// are resolved.
		ks = ck.top + string(filepath.Separator) + ks
	}
	if rel, ok := relBelowTop(canonical(ck.top), ks); ok {
		rels = append(rels, rel)
	}
	if rel, err := filepath.Rel(canonical(ck.top), canonical(ks)); err == nil {
		rels = append(rels, rel)
	}
	inRepo, below := false, ""
	for _, rel := range rels {
		switch {
		case rel == ".":
			inRepo = true
		case rel != ".." && !strings.HasPrefix(rel, "../"):
			forbidPrefix = append(forbidPrefix, filepath.ToSlash(rel))
			below = filepath.ToSlash(rel)
		}
	}
	// Even untracked, a keystore inside the checkout is exposed to every
	// tool that walks the tree (3.2): a config finding, not only the paths.
	switch {
	case inRepo:
		add(cfgPath, 0, 0, ckConfig, "the keystore cannot be the repository itself")
	case below != "":
		add(cfgPath, 0, 0, ckConfig, "the keystore must be outside the repository (it is at %s)", below)
	}

	for _, f := range s.Files {
		for _, pre := range forbidPrefix {
			if f.Path == pre || strings.HasPrefix(f.Path, pre+"/") {
				add(f.Path, 0, 0, ckForbidden, "the keystore must not be in the repository")
			}
		}
		if pat, ok := matchAny(cfg.Forbid, f.Path); ok {
			add(f.Path, 0, 0, ckForbidden, "matches forbid = %s", pat)
		}
		inSec := strings.HasPrefix(f.Path, secDir+"/")
		if hasSec && !inSec {
			if _, ok := cfg.nodeRoot(f.Path); ok && f.Gitlink {
				add(f.Path, 0, 0, ckManifest, "a submodule under a node root cannot be described by the manifest")
			} else if ok {
				e := man[f.Path]
				want := "f"
				if f.Link {
					want = "l"
				}
				switch {
				case e == nil:
					add(f.Path, 0, 0, ckManifest, "no manifest entry (segscan manifest fix)")
				case e.Type == "s":
					add(f.Path, 0, 0, ckManifest, "a secret file (type s) must not be in the repository")
				case e.Type != want:
					add(f.Path, 0, 0, ckManifest, "manifest type %s, but the file is type %s", e.Type, want)
				}
			}
		}
		if f.Link || f.Gitlink {
			continue
		}
		fi := ck.info(s, f)
		for _, x := range fi.finds {
			if x.Check == ckPrivate && allow.fp[x.fp] {
				continue
			}
			if inSec && x.Check != ckPrivate {
				continue // .sec/ files are checked for private keys only
			}
			x.Commit, x.File = s.Commit, f.Path
			out = append(out, x)
		}
		if inSec {
			continue
		}
		for _, p := range fi.phs {
			if !hasSec {
				break // before .sec/ existed: grammar, forbidden paths and private keys only
			}
			k := names.ByName[p.Name]
			switch {
			case k == nil:
				add(f.Path, p.Line, p.Col+1, ckNames, "unknown key %s (segscan key add)", p.Name)
			case k.UUID != p.UUID:
				add(f.Path, p.Line, p.Col+1, ckNames, "uuid of %s does not match %s", p.Name, namesPath)
			case len(k.Scope) > 0:
				if _, ok := matchAny(k.Scope, f.Path); !ok {
					add(f.Path, p.Line, p.Col+1, ckNames, "key %s used outside its scope", p.Name)
				}
			}
		}
	}
	if hasSec {
		for _, e := range entries {
			_, under := cfg.nodeRoot(e.Path)
			if !under {
				add(manPath, e.Line, 0, ckManifest, "%s is outside the node roots", e.Path)
				continue
			}
			if (e.Type == "f" || e.Type == "l") && s.byPath[e.Path] == nil {
				add(manPath, e.Line, 0, ckManifest, "%s: no such file", e.Path)
			}
			// An ancestor must be a directory or a declared link: a path
			// cannot be both a file and a directory on the target.
			for dir := path.Dir(e.Path); dir != "." && dir != "/"; dir = path.Dir(dir) {
				if a := man[dir]; a != nil && (a.Type == "f" || a.Type == "s") {
					add(manPath, e.Line, 0, ckManifest, "%s lies below %s, which is type %s", e.Path, dir, a.Type)
					break
				}
			}
		}
	}
	return out
}

// The two functions below walk a path one component at a time and resolve
// symlinks before applying "..": /tmp/alias/../repo with alias -> /actual/x
// is /actual/repo, not /tmp/repo. filepath.Clean must therefore never see
// the raw path first.

// canonical resolves symlinks in the absolute path p. Components that do
// not exist (yet) are kept as written.
func canonical(p string) string {
	cur := string(filepath.Separator)
	for _, c := range strings.Split(p, string(filepath.Separator)) {
		cur = step(cur, c)
	}
	return cur
}

// step moves from the resolved directory cur by one raw component.
func step(cur, c string) string {
	switch c {
	case "", ".":
		return cur
	case "..":
		return filepath.Dir(cur)
	}
	next := filepath.Join(cur, c)
	if r, err := filepath.EvalSymlinks(next); err == nil {
		return r
	}
	return next
}

// relBelowTop finds the shortest prefix of the absolute path p that is the
// repository top (top is canonical) and returns the rest of p as written,
// without resolving it.
func relBelowTop(top, p string) (string, bool) {
	parts := strings.Split(p, string(filepath.Separator))
	cur := string(filepath.Separator)
	for i := 0; i <= len(parts); i++ {
		if cur == top {
			rel := filepath.Clean(filepath.Join(append([]string{"."}, parts[i:]...)...))
			if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return rel, true
			}
		}
		if i < len(parts) {
			cur = step(cur, parts[i])
		}
	}
	return "", false
}

// ---------- the command ----------

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	staged := fs.Bool("staged", false, "check the index (pre-commit)")
	rng := fs.String("range", "", "check every commit given by these git rev-list arguments (pre-push), e.g. A..B")
	all := fs.Bool("all", false, "check every commit reachable from any ref")
	asJSON := fs.Bool("json", false, "JSON Lines output")
	noHeader := fs.Bool("no-header", false, "omit the TSV header line")
	fs.Parse(args)
	n := 0
	for _, b := range []bool{*staged, *rng != "", *all} {
		if b {
			n++
		}
	}
	if n > 1 || fs.NArg() > 0 {
		die(fmt.Errorf("check: use at most one of -staged, -range, -all, and no paths"))
	}
	// Not mustSec: every snapshot is checked with its own .sec/config, and a
	// broken one is a finding of that snapshot, not an error of the command.
	top := secRoot()
	if top == "" {
		die(fmt.Errorf("no %s/ in this repository: run segscan init", secDir))
	}
	ck := &checker{top: top, cache: map[string]*fileInfo{}}
	var finds []checkFinding
	switch {
	case *staged || *rng != "" || *all:
		cf, err := newCatFile(top)
		if err != nil {
			die(err)
		}
		defer cf.close()
		if *staged {
			s, err := indexSnapshot(top, cf)
			if err != nil {
				die(err)
			}
			finds = ck.run(s)
			break
		}
		revArgs := []string{"rev-list", "--reverse", "--all"}
		if *rng != "" {
			revArgs = append([]string{"rev-list", "--reverse"}, strings.Fields(*rng)...)
		}
		commits, err := gitOut(append([]string{"-C", top}, revArgs...)...)
		if err != nil {
			die(fmt.Errorf("git %s: %v", strings.Join(revArgs, " "), err))
		}
		seen := map[string]bool{}
		for _, c := range strings.Fields(commits) {
			s, err := commitSnapshot(top, cf, c)
			if err != nil {
				die(err)
			}
			for _, f := range ck.run(s) {
				key := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%s", f.Check, f.File, f.Line, f.Col, f.Msg)
				if !seen[key] { // the oldest commit that has it
					seen[key] = true
					finds = append(finds, f)
				}
			}
		}
	default:
		s, err := worktreeSnapshot(top)
		if err != nil {
			die(err)
		}
		finds = ck.run(s)
	}
	if *rng == "" && !*all {
		sort.SliceStable(finds, func(i, j int) bool {
			if finds[i].File != finds[j].File {
				return finds[i].File < finds[j].File
			}
			return finds[i].Line < finds[j].Line
		})
	}
	for i, f := range finds {
		if *asJSON {
			out, _ := json.Marshal(f)
			fmt.Println(string(out))
			continue
		}
		if i == 0 && !*noHeader {
			fmt.Println("commit\tfile\tline\tcol\tcheck\tmessage")
		}
		fmt.Printf("%s\t%s\t%d\t%d\t%s\t%s\n", f.Commit, escape(f.File), f.Line, f.Col, f.Check, escape(f.Msg))
	}
	fmt.Fprintln(os.Stderr, "segscan: known values not checked: keystore support is not implemented yet")
	if len(finds) > 0 {
		fmt.Fprintf(os.Stderr, "segscan: %d problem(s)\n", len(finds))
		os.Exit(1)
	}
}

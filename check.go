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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ---------- snapshots: a set of files from the working tree, the index or a commit ----------

type snapFile struct {
	Path string
	Link bool
	OID  string // blob id; "" for the working tree
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
	if f == nil || f.Link {
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
	var out []snapFile
	seen := map[string]bool{}
	for _, p := range recs {
		if seen[p] {
			continue
		}
		seen[p] = true
		st, err := os.Lstat(filepath.Join(top, p))
		if err != nil || !(st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0) {
			continue
		}
		out = append(out, snapFile{Path: p, Link: st.Mode()&os.ModeSymlink != 0})
	}
	return out, nil
}

func worktreeSnapshot(top string) (*snapshot, error) {
	files, err := worktreeFiles(top)
	if err != nil {
		return nil, err
	}
	s := &snapshot{Files: files, read: func(f snapFile) ([]byte, error) { return os.ReadFile(filepath.Join(top, f.Path)) }}
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
		if !ok || len(f) != 3 || seen[p] || f[0] == "160000" {
			continue
		}
		seen[p] = true
		s.Files = append(s.Files, snapFile{Path: p, Link: f[0] == "120000", OID: f[1]})
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
		if !ok || len(f) != 3 || f[1] != "blob" {
			continue
		}
		s.Files = append(s.Files, snapFile{Path: p, Link: f[0] == "120000", OID: f[2]})
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

func analyzeFile(data []byte, allow *allowList) *fileInfo {
	fi := &fileInfo{}
	if isBinary(data) {
		if i := bytes.Index(data, phPrefix); i >= 0 {
			fi.finds = append(fi.finds, checkFinding{Col: i + 1, Check: ckGrammar, Msg: "placeholder in a binary file"})
		}
		return fi
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
			if !allow.fp[f.FP()] {
				fi.finds = append(fi.finds, checkFinding{Line: no, Col: 1, Check: ckPrivate, Msg: pemLabel(line)})
			}
		}
		if !bytes.Contains(line, phPrefix) {
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
	allow *allowList
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
	fi := analyzeFile(data, ck.allow)
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

	// Paths that may never be in the repository.
	forbidPrefix := []string{secDir + "/keys"}
	ks := cfg.keystoreDir()
	if !filepath.IsAbs(ks) {
		ks = filepath.Join(ck.top, ks)
	}
	if rel, err := filepath.Rel(ck.top, ks); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") {
		forbidPrefix = append(forbidPrefix, filepath.ToSlash(rel))
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
			if _, ok := cfg.nodeRoot(f.Path); ok {
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
		if inSec || f.Link {
			continue
		}
		fi := ck.info(s, f)
		for _, x := range fi.finds {
			x.Commit, x.File = s.Commit, f.Path
			out = append(out, x)
		}
		for _, p := range fi.phs {
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
		}
	}
	return out
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
	top, _ := mustSec()
	ck := &checker{top: top, allow: loadAllow(secPath(top, "allow"), false), cache: map[string]*fileInfo{}}
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

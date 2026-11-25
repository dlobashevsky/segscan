// segscan is a statistical secret scanner: it looks for fragments that do not
// decompose into the ordinary words and letter patterns of the repository.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const usage = `segscan - statistical secret scanner

  segscan train [-m model] [-words list,...] [path...]
                                        train a model (no paths: git ls-files)
  segscan scan  [flags] [path...|-]     scan files (no paths: git ls-files)
  segscan diff  [flags]                 scan the added lines of a unified diff on stdin
                                        (git log -p --all -U0 | segscan diff)
  segscan hook  [flags]                 scan staged changes (for pre-commit)
  segscan install                       install a pre-commit hook in the current repository
  segscan calib [flags] file...         noise on files and recall on synthetic secrets
  segscan explain [flags] 'string'      show per-character cost and segmentation

Configuration repositories (a .sec/ directory, see DESIGN.md):
  segscan init                          create .sec/ and point core.hooksPath at .sec/hooks
  segscan key add <name> [-scope GLOB,...]
                                        add a key name, print its placeholder
  segscan key rm <name> | key list      remove an unused key / list keys and their uses
  segscan check [-staged|-range REVS|-all]
                                        blocking checks: placeholders, names, manifest,
                                        forbidden paths, private keys (default: working tree)
  segscan manifest fix                  add manifest entries for new files, drop deleted ones

Flags for scan/diff/hook/calib:
  -m file       model (default $SEGSCAN_MODEL, then .git/segscan.model)
  -tau N        randomness threshold, bits per char
  -excess N     minimum accumulated excess over a segment, bits
  -minlen N     minimum segment length
  -bpc N        report only findings with at least N average bits per char
  -kw N         threshold multiplier when password/token/key... precedes on the line (1 = off)
  -skip-uuids   do not score !SECKEY_..! placeholders and canonical UUIDs
  -allow file   allowlist (fp fingerprints and path:glob lines)
  -warn         (hook) print the findings but do not block the commit

Inside a .sec/ repository the model defaults to .sec/segscan.model, the
allowlist to .sec/allow, and -skip-uuids and the hook mode to .sec/config.
  -json         JSON Lines output (one object per finding) instead of TSV
  -preview N    how many chars of a finding to print (default 10)
  -show         print findings in full
  -no-header    omit the TSV header line

TSV columns: commit file line col bits_per_char length excess_bits count kind fp text
Exit code: 0 clean, 1 findings, 2 error.
`

type common struct {
	model, allow string
	show, noDef  bool
	json         bool
	noHeader     bool
	preview      int
	skipUUIDs    bool
	o            Opts

	sec *secConfig // set by finish inside a .sec/ repository
	set map[string]bool
}

func flags(name string) (*flag.FlagSet, *common) {
	c := &common{o: defaultOpts}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&c.model, "m", "", "model file")
	fs.StringVar(&c.allow, "allow", ".segscan-allow", "allowlist file")
	fs.BoolVar(&c.show, "show", false, "print findings in full")
	fs.BoolVar(&c.json, "json", false, "JSON Lines output instead of TSV")
	fs.BoolVar(&c.noHeader, "no-header", false, "omit the TSV header line")
	fs.IntVar(&c.preview, "preview", 10, "how many chars of a finding to print")
	fs.Float64Var(&c.o.MinBpc, "bpc", c.o.MinBpc, "report only findings with at least this many bits per char")
	fs.BoolVar(&c.noDef, "no-default-excludes", false, "do not skip lock files and *.min.js")
	fs.Float64Var(&c.o.Tau, "tau", c.o.Tau, "randomness threshold, bits per char")
	fs.Float64Var(&c.o.MinExcess, "excess", c.o.MinExcess, "minimum accumulated excess, bits")
	fs.IntVar(&c.o.MinLen, "minlen", c.o.MinLen, "minimum segment length")
	fs.Float64Var(&c.o.KwFactor, "kw", c.o.KwFactor, "threshold multiplier after password/token/key words (1 = off)")
	fs.BoolVar(&c.skipUUIDs, "skip-uuids", false, "do not score !SECKEY_..! placeholders and canonical UUIDs")
	return fs, c
}

// finish applies the defaults of a .sec/ repository to the flags that were
// not given. Call it after Parse.
func (c *common) finish(fs *flag.FlagSet) {
	c.set = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { c.set[f.Name] = true })
	if c.skipUUIDs {
		c.o.Skip = skipAll
	}
	top := secRoot()
	if top == "" {
		return
	}
	cfg, err := loadSecConfig(top)
	if err != nil {
		die(err)
	}
	c.sec = cfg
	if !c.set["allow"] {
		c.allow = secPath(top, "allow")
	}
	if !c.set["m"] && os.Getenv("SEGSCAN_MODEL") == "" {
		c.model = secPath(top, "segscan.model")
	}
	if !c.set["skip-uuids"] {
		c.o.Skip = cfg.SkipUUIDs
	}
}

func modelPath(v string) string {
	if v != "" {
		return v
	}
	if e := os.Getenv("SEGSCAN_MODEL"); e != "" {
		return e
	}
	if gd := gitDir(); gd != "" {
		return filepath.Join(gd, "segscan.model")
	}
	return "segscan.model"
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "segscan:", err)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "train":
		cmdTrain(args)
	case "scan":
		cmdScan(args)
	case "diff":
		cmdDiff(args, os.Stdin, false)
	case "hook":
		cmdHook(args)
	case "install":
		cmdInstall()
	case "calib":
		cmdCalib(args)
	case "explain":
		cmdExplain(args)
	case "init":
		cmdInit(args)
	case "key":
		cmdKey(args)
	case "check":
		cmdCheck(args)
	case "manifest":
		cmdManifest(args)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// ---------- files ----------

func readText(path string) ([]byte, bool) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 8<<20 {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return nil, false // binary
	}
	return data, true
}

func expand(paths []string) []string {
	var out []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "segscan:", err)
			continue
		}
		if !st.IsDir() {
			out = append(out, p)
			continue
		}
		filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if n := d.Name(); n == ".git" || n == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			out = append(out, path)
			return nil
		})
	}
	return out
}

func filesOrGit(paths []string) []string {
	if len(paths) > 0 {
		return expand(paths)
	}
	files, err := gitFiles()
	if err != nil {
		die(fmt.Errorf("no paths given and not a git repository"))
	}
	return files
}

// ---------- commands ----------

func train(files []string, allow *allowList, top, skip int, lists ...string) *Model {
	t := newTrainer()
	t.skip = skip
	for _, l := range lists {
		data, err := os.ReadFile(l)
		if err != nil {
			die(err)
		}
		t.addWords(data)
	}
	for _, f := range files {
		if allow.skipPath(f) {
			continue
		}
		if data, ok := readText(f); ok {
			t.addFile(data)
		}
	}
	return t.finish(top)
}

func cmdTrain(args []string) {
	fs, c := flags("train")
	top := fs.Int("top", 0, "keep only the N most frequent corpus words in the dictionary")
	words := fs.String("words", "", "comma-separated word lists (one word per line, a-z)")
	fs.Parse(args)
	c.finish(fs)
	var lists []string
	if *words != "" {
		lists = strings.Split(*words, ",")
	}
	m := train(filesOrGit(fs.Args()), loadAllow(c.allow, !c.noDef), *top, c.o.Skip, lists...)
	path := modelPath(c.model)
	if err := m.save(path); err != nil {
		die(err)
	}
	fmt.Fprintf(os.Stderr, "segscan: model %s: %d files, %d fragments, %d dictionary words\n",
		path, m.Files, m.Tokens, len(m.Words))
	if m.Tokens < 200000 {
		fmt.Fprintln(os.Stderr, "segscan: small corpus, expect many false positives: train on several repositories")
	}
}

// mustModel returns the working model: the repository model mixed with the built-in one.
func mustModel(c *common) *Model {
	m, err := loadModel(modelPath(c.model))
	if err != nil {
		if !os.IsNotExist(err) {
			die(err)
		}
		if baseModel == nil {
			die(fmt.Errorf("no model %s: run segscan train first", modelPath(c.model)))
		}
		fmt.Fprintf(os.Stderr, "segscan: no model %s, using the built-in one (segscan train makes it more precise)\n", modelPath(c.model))
		m = nil
	}
	return combine(m, baseModel)
}

// ---------- output ----------

const tsvHeader = "commit\tfile\tline\tcol\tbits_per_char\tlength\texcess_bits\tcount\tkind\tfp\ttext"

type printer struct {
	show    bool
	json    bool
	header  bool // a TSV header is still to be printed
	preview int
	uniq    bool
	n       int
	order   []string
	byFP    map[string]*Finding
}

func (c *common) printer(uniq bool) *printer {
	return &printer{show: c.show, json: c.json, header: !c.json && !c.noHeader, preview: c.preview, uniq: uniq}
}

func (p *printer) add(f Finding) {
	p.n++
	f.Count = 1
	if !p.uniq {
		p.print(&f)
		return
	}
	if p.byFP == nil {
		p.byFP = map[string]*Finding{}
	}
	fp := f.FP()
	if old := p.byFP[fp]; old != nil {
		old.Count++
		return
	}
	p.byFP[fp] = &f
	p.order = append(p.order, fp)
}

func (p *printer) flush() {
	for _, fp := range p.order {
		p.print(p.byFP[fp])
	}
}

// text returns the printed part of a finding and whether it was cut.
func (p *printer) text(f *Finding) (string, bool) {
	if f.Kind == kindPEM {
		return f.Label, false
	}
	if p.show || len(f.Text) <= p.preview {
		return f.Text, false
	}
	return f.Text[:p.preview], true
}

// escape makes a string safe for one TSV field: backslash escapes for tab,
// backslash and every byte outside printable ASCII.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

type jsonRow struct {
	Commit    string  `json:"commit"`
	File      string  `json:"file"`
	Line      int     `json:"line"`
	Col       int     `json:"col"`
	Bits      float64 `json:"bits_per_char"`
	Length    int     `json:"length"`
	Excess    float64 `json:"excess_bits"`
	Count     int     `json:"count"`
	Kind      string  `json:"kind"`
	FP        string  `json:"fp"`
	Text      string  `json:"text"`
	Truncated bool    `json:"truncated"`
}

func (p *printer) print(f *Finding) {
	text, cut := p.text(f)
	length := len(f.Text)
	if f.Kind == kindPEM {
		length = 0
	}
	if p.json {
		row := jsonRow{f.Commit, f.File, f.Line, f.Col, math.Round(f.Bits*100) / 100, length,
			math.Round(f.Excess*10) / 10, f.Count, f.Kind, f.FP(), strings.ToValidUTF8(text, "\uFFFD"), cut}
		out, _ := json.Marshal(row)
		fmt.Println(string(out))
		return
	}
	if p.header {
		p.header = false
		fmt.Println(tsvHeader)
	}
	text = escape(text)
	if cut {
		text += "..."
	}
	fmt.Printf("%s\t%s\t%d\t%d\t%.2f\t%d\t%.1f\t%d\t%s\t%s\t%s\n",
		f.Commit, escape(f.File), f.Line, f.Col, f.Bits, length, f.Excess, f.Count, f.Kind, f.FP(), text)
}

func cmdScan(args []string) {
	fs, c := flags("scan")
	fs.Parse(args)
	c.finish(fs)
	m := mustModel(c)
	allow := loadAllow(c.allow, !c.noDef)
	p := c.printer(false)
	s := &fileScan{sc: NewScanner(m, c.o), allow: allow, out: p.add}
	if fs.NArg() == 1 && fs.Arg(0) == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			die(err)
		}
		s.data("<stdin>", data)
	} else {
		for _, f := range filesOrGit(fs.Args()) {
			if allow.skipPath(f) {
				continue
			}
			if data, ok := readText(f); ok {
				s.data(f, data)
			}
		}
	}
	if p.n > 0 {
		os.Exit(1)
	}
}

func runDiff(c *common, m *Model, r io.Reader, uniq bool) int {
	allow := loadAllow(c.allow, !c.noDef)
	p := c.printer(uniq)
	s := &fileScan{sc: NewScanner(m, c.o), allow: allow, out: p.add}
	last := ""
	err := scanDiff(r, func(commit, file string, line int, text []byte) {
		if key := commit + "\x00" + file; key != last {
			last = key
			s.pem = pemState{}
		}
		if allow.skipPath(file) || bytes.IndexByte(text, 0) >= 0 {
			return
		}
		s.line(commit, file, line, text)
	})
	if err != nil {
		die(err)
	}
	p.flush()
	return p.n
}

func cmdDiff(args []string, r io.Reader, _ bool) {
	fs, c := flags("diff")
	all := fs.Bool("all", false, "print every occurrence instead of unique findings")
	fs.Parse(args)
	c.finish(fs)
	if runDiff(c, mustModel(c), r, !*all) > 0 {
		os.Exit(1)
	}
}

func cmdHook(args []string) {
	fs, c := flags("hook")
	warn := fs.Bool("warn", false, "print the findings but do not block the commit")
	fs.Parse(args)
	c.finish(fs)
	block := !*warn
	if !c.set["warn"] && c.sec != nil {
		switch c.sec.HookScan {
		case "off":
			return
		case "warn":
			block = false
		}
	}
	path := modelPath(c.model)
	m, err := loadModel(path)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "segscan: no model, training on git ls-files -> %s\n", path)
		files, gerr := gitFiles()
		if gerr != nil {
			die(gerr)
		}
		m = train(files, loadAllow(c.allow, !c.noDef), 0, c.o.Skip)
		if err := m.save(path); err != nil {
			die(err)
		}
	} else if err != nil {
		die(err)
	}
	m = combine(m, baseModel)
	cmd := exec.Command("git", "-c", "core.quotepath=off", "diff", "--cached", "-U0",
		"--no-color", "--no-ext-diff", "--diff-filter=ACMR")
	out, err := cmd.StdoutPipe()
	if err != nil {
		die(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		die(err)
	}
	n := runDiff(c, m, out, false)
	if err := cmd.Wait(); err != nil {
		die(err)
	}
	if n > 0 && !block {
		fmt.Fprintf(os.Stderr, "\nsegscan: %d suspicious fragment(s), not blocking.\n"+
			"False positive? Add its fp to the allowlist or put \"segscan:allow\" on the line.\n", n)
		return
	}
	if n > 0 {
		fmt.Fprintf(os.Stderr, "\nsegscan: %d suspicious fragment(s), commit blocked.\n"+
			"False positive? Add its fp to .segscan-allow or put \"segscan:allow\" on the line.\n", n)
		os.Exit(1)
	}
}

func cmdInstall() {
	gd := gitDir()
	if gd == "" {
		die(fmt.Errorf("not a git repository"))
	}
	exe, err := os.Executable()
	if err != nil {
		die(err)
	}
	hook := filepath.Join(gd, "hooks", "pre-commit")
	if _, err := os.Stat(hook); err == nil {
		die(fmt.Errorf("%s already exists: add this line to it: %s hook || exit 1", hook, exe))
	}
	os.MkdirAll(filepath.Dir(hook), 0o755)
	body := fmt.Sprintf("#!/bin/sh\nexec '%s' hook\n", exe)
	if err := os.WriteFile(hook, []byte(body), 0o755); err != nil {
		die(err)
	}
	fmt.Fprintln(os.Stderr, "segscan: installed", hook)
}

// ---------- calibration ----------

func cmdCalib(args []string) {
	fs, c := flags("calib")
	n := fs.Int("n", 300, "synthetic strings per cell")
	fs.Parse(args)
	c.finish(fs)
	m := mustModel(c)
	sc := NewScanner(m, c.o)

	// 1. Noise: findings on the given files (assumed to hold no secrets).
	lines, found := 0, 0
	s := &fileScan{sc: sc, allow: loadAllow("", false), out: func(Finding) { found++ }}
	for _, f := range expand(fs.Args()) {
		if data, ok := readText(f); ok {
			lines += bytes.Count(data, []byte{'\n'})
			s.data(f, data)
		}
	}
	if lines > 0 {
		fmt.Printf("noise: %d findings in %d lines (%.2f per 1000 lines)\n\n", found, lines, 1000*float64(found)/float64(lines))
	}

	// 2. Recall: random strings of various alphabets and lengths in typical config lines.
	const lower, upper, digits = "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789"
	alpha := []struct{ name, chars string }{
		{"hex", digits + "abcdef"},
		{"base32", upper + "234567"},
		{"a-z0-9", lower + digits},
		{"a-z", lower},
		{"base58", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"},
		{"base62", digits + upper + lower},
		{"base64", upper + lower + digits + "+/"},
		{"password", digits + upper + lower + "!@#$%^&*-_"},
	}
	lens := []int{8, 10, 12, 16, 20, 24, 32, 40}
	sets := []struct {
		name string
		tmpl []string
	}{
		{"keyword on the line", []string{"X-API-Key: %s", "  password: \"%s\"", "TOKEN=%s", "\"secret\":\"%s\",", "    api_key = '%s'  # prod"}},
		{"no keyword", []string{"    - %s", "  value: \"%s\"", "%s", "\"id\":\"%s\",", "url = https://example.org/v1/%s"}},
	}
	rng := rand.New(rand.NewSource(1))
	for _, set := range sets {
		tmpl := set.tmpl
		fmt.Printf("recall, %%, %s (tau=%.1f, excess=%.0f, minlen=%d, kw=%.2f)\n%-10s", set.name, c.o.Tau, c.o.MinExcess, c.o.MinLen, c.o.KwFactor, "")
		for _, l := range lens {
			fmt.Printf("%6d", l)
		}
		fmt.Println()
		for _, a := range alpha {
			fmt.Printf("%-10s", a.name)
			for _, l := range lens {
				hit := 0
				for i := 0; i < *n; i++ {
					sec := make([]byte, l)
					for k := range sec {
						sec[k] = a.chars[rng.Intn(len(a.chars))]
					}
					line := fmt.Sprintf(tmpl[i%len(tmpl)], sec)
					at := strings.Index(line, string(sec))
					ok := false
					sc.Line([]byte(line), func(col int, text []byte, _, _ float64) {
						lo, hi := max(col, at), min(col+len(text), at+l)
						if hi-lo >= (l+1)/2 {
							ok = true
						}
					})
					if ok {
						hit++
					}
				}
				fmt.Printf("%6.0f", 100*float64(hit)/float64(*n))
			}
			fmt.Println()
		}
		fmt.Println()
	}
}

// cmdExplain prints how a string was segmented and what each piece costs.
func cmdExplain(args []string) {
	fs, c := flags("explain")
	fs.Parse(args)
	c.finish(fs)
	sc := NewScanner(mustModel(c), c.o)
	for _, line := range fs.Args() {
		sc.explain = func(piece []byte, bits float32, word bool) {
			kind := "char"
			if word {
				kind = "word"
			}
			fmt.Printf("  %-24q %-5s %5.1f bits  %4.1f bits/char\n", piece, kind, bits, bits/float32(len(piece)))
		}
		fmt.Println(line)
		sc.Line([]byte(line), func(col int, text []byte, bits, excess float64) {
			fmt.Printf("  => finding: col %d, %q, %.1f bits/char, excess %.0f bits\n", col+1, text, bits, excess)
		})
	}
}

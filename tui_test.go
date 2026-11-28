package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]")

func plain(lines []string) string { return ansiRE.ReplaceAllString(strings.Join(lines, "\n"), "") }

func testRows() []*tuiRow {
	mk := func(file string, line int, text string, bits float64) *tuiRow {
		f := Finding{File: file, Line: line, Col: 10, Text: text, Bits: bits, Kind: kindEntropy}
		return &tuiRow{f: f, file: file, fp: f.FP()}
	}
	return []*tuiRow{
		mk("b.yaml", 2, "Zx81kq9PmW3vT7bRq2Lp", 5.1),
		mk("a.conf", 7, "nvme0n1p3", 4.7),
		mk("a.conf", 9, "nvme0n1p3", 4.7), // same fp as the row above
		mk("c.sh", 1, "Qm7vX2pLk9Rt4wZn", 6.0),
	}
}

func keys(s *tuiState, ks ...string) {
	for _, k := range ks {
		s.key(k)
	}
}

func TestTUISortAndMove(t *testing.T) {
	s := newTUIState(testRows())
	order := func() string {
		var out []string
		for _, it := range s.view {
			out = append(out, fmt.Sprintf("%s:%d", it.file, s.rows[it.row].f.Line))
		}
		return strings.Join(out, " ")
	}
	if got := order(); got != "a.conf:7 a.conf:9 b.yaml:2 c.sh:1" {
		t.Errorf("by file: %s", got)
	}
	keys(s, "s") // bpc first
	if got := order(); got != "c.sh:1 b.yaml:2 a.conf:7 a.conf:9" {
		t.Errorf("by bpc: %s", got)
	}
	s.rows[1].llm, s.rows[1].hasLLM = 0.9, true
	keys(s, "s") // llm first; without a score last
	if got := order(); !strings.HasPrefix(got, "a.conf:7 ") {
		t.Errorf("by llm: %s", got)
	}
	keys(s, "end", "down", "down")
	if s.cur != len(s.view)-1 {
		t.Errorf("cursor past the end: %d", s.cur)
	}
	keys(s, "home", "up")
	if s.cur != 0 {
		t.Errorf("cursor before the start: %d", s.cur)
	}
}

func TestTUIMarksAndPlan(t *testing.T) {
	s := newTUIState(testRows())
	s.hashes = map[string]string{"a.conf": "ha", "b.yaml": "hb", "c.sh": "hc"}
	// Row 0 is a.conf:7. A marks both a.conf rows (same fp).
	keys(s, "home", "A")
	for _, it := range s.view[:2] {
		if k, _ := s.mark(s.rows[it.row]); k != actAllowFP {
			t.Fatalf("A should cover every row with the fp")
		}
	}
	if !strings.Contains(s.statusLine(), "2 findings in 1 files") {
		t.Errorf("status: %s", s.statusLine())
	}
	// a on a row whose fp is marked A (everywhere) is refused.
	keys(s, "a")
	if !strings.Contains(s.msg, "marked A") {
		t.Errorf("a over A: %q", s.msg)
	}
	// b.yaml: a (this file only); c.sh: I.
	keys(s, "down", "down", "a", "down", "I")
	acts := s.planActions()
	var got []string
	for _, a := range acts {
		got = append(got, fmt.Sprintf("%c %s %d %s %s", a.Kind, a.File, a.Line, a.Hash, a.Glob))
	}
	// file actions, then rows in scan order
	want := "I c.sh 0 hc |A b.yaml 2 hb /b.yaml|A a.conf 7 ha "
	if strings.Join(got, "|") != want {
		t.Errorf("plan:\n%s\nwant\n%s", strings.Join(got, "|"), want)
	}
	// A file action overrides a row action under it, shown in lower case.
	keys(s, "up", "I")
	b := s.rows[0] // b.yaml
	if k, over := s.mark(b); k != actIgnore || !over {
		t.Errorf("file action over a: %c %v", k, over)
	}
	keys(s, "U") // takes the file action away: a comes back
	if k, _ := s.mark(b); k != actAllowFPHere {
		t.Errorf("after U: %c", k)
	}
	// A takes over the a marks of the fingerprint.
	keys(s, "A")
	if k, _ := s.mark(b); k != actAllowFP || len(s.fpHere) != 0 {
		t.Errorf("A after a: %c %v", k, s.fpHere)
	}
	// h hides marked rows: all are marked.
	keys(s, "h")
	if len(s.view) != 0 {
		t.Errorf("hide marked: %d rows left", len(s.view))
	}
	keys(s, "h", "X", "y")
	if s.nMarked() != 0 {
		t.Errorf("X y should clear every mark")
	}
}

// a marks one file only: the same fp in another file stays unmarked.
func TestTUIFPHere(t *testing.T) {
	rows := testRows()
	other := *rows[0]
	other.file, other.f.File = "d.yaml", "d.yaml"
	s := newTUIState(append(rows, &other))
	keys(s, "home", "down", "down", "a") // b.yaml:2
	if k, _ := s.mark(rows[0]); k != actAllowFPHere {
		t.Fatalf("b.yaml: %c", k)
	}
	if k, _ := s.mark(&other); k != 0 {
		t.Errorf("d.yaml has the same fp, but a is for b.yaml only: %c", k)
	}
	if !strings.Contains(s.statusLine(), "in b.yaml only") {
		t.Errorf("status: %s", s.statusLine())
	}
	if sum := strings.Join(s.summary(), "\n"); !strings.Contains(sum, "in b.yaml only") {
		t.Errorf("summary: %s", sum)
	}
	keys(s, "U")
	if s.nMarked() != 0 {
		t.Errorf("U: %d marked", s.nMarked())
	}
	// A name an allowlist line cannot hold.
	sp := *rows[0]
	sp.file, sp.f.File = "a b.yaml", "a b.yaml"
	s = newTUIState([]*tuiRow{&sp})
	keys(s, "a")
	if s.nMarked() != 0 || !strings.Contains(s.msg, "white space") {
		t.Errorf("a on a name with a space: %q", s.msg)
	}
}

func TestTUIRefusals(t *testing.T) {
	rows := testRows()
	pem := &tuiRow{f: Finding{File: "k.pem", Line: 1, Col: 1, Text: "-----BEGIN RSA PRIVATE KEY-----", Kind: kindPEM, Label: "-----BEGIN RSA PRIVATE KEY-----"}, file: "k.pem"}
	pem.fp = pem.f.FP()
	s := newTUIState(append(rows, pem))
	keys(s, "end") // k.pem is last by file
	keys(s, "A")
	if !strings.Contains(s.msg, "private key") {
		t.Errorf("A on a private key: %q", s.msg)
	}
	keys(s, "F")
	if !strings.Contains(s.msg, "private key") {
		t.Errorf("F on a private key: %q", s.msg)
	}
	// a is fine for a private key: check honours fp path: lines.
	keys(s, "a")
	if k, _ := s.mark(pem); k != actAllowFPHere {
		t.Errorf("a on a private key: %c %q", k, s.msg)
	}
	keys(s, "U", "home")
	// I on a file in HEAD asks first.
	s.ignore = func(string) bool { return true }
	keys(s, "I")
	if s.dialog == nil {
		t.Fatal("I on a committed file should ask")
	}
	keys(s, "n")
	if s.nMarked() != 0 {
		t.Errorf("n should not mark")
	}
	keys(s, "I", "y")
	if acts := s.planActions(); len(acts) != 1 || !acts[0].History {
		t.Errorf("confirmed I: %+v", acts)
	}
}

func TestTUIQuitDialog(t *testing.T) {
	s := newTUIState(testRows())
	keys(s, "q")
	if !s.quit {
		t.Fatal("q with nothing marked quits at once")
	}
	s = newTUIState(testRows())
	keys(s, "A", "q")
	if s.quit || s.dialog == nil || !strings.Contains(plain(s.render()), "apply all and quit") {
		t.Fatal("q with marks asks")
	}
	keys(s, "esc")
	if s.quit || s.dialog != nil {
		t.Fatal("esc stays")
	}
	keys(s, "q", "d")
	if !s.quit || s.applyOnQuit {
		t.Fatal("d discards and quits")
	}
	s = newTUIState(testRows())
	keys(s, "A", "ctrl-c", "a")
	if !s.quit || !s.applyOnQuit {
		t.Fatal("a applies and quits")
	}
}

func TestTUIFoldAndFilter(t *testing.T) {
	s := newTUIState(testRows())
	keys(s, "home", "z")
	if len(s.view) != 3 || s.view[0].row != -1 || s.view[0].n != 2 {
		t.Fatalf("fold: %+v", s.view)
	}
	keys(s, "F") // a file action on the folded row
	if s.fileMark["a.conf"] != actAllowFile {
		t.Errorf("F on a folded file")
	}
	keys(s, "z", "f")
	if len(s.view) != 2 || s.onlyFile != "a.conf" {
		t.Errorf("only this file: %+v", s.view)
	}
	keys(s, "f")
	if len(s.view) != 4 {
		t.Errorf("all files again: %d", len(s.view))
	}
}

func TestTUIRender(t *testing.T) {
	s := newTUIState(testRows())
	s.w, s.h = 80, 20
	s.source = func(f string) []string {
		return []string{"line one", "  password: Zx81kq9PmW3vT7bRq2Lp", "line three"}
	}
	s.rows[0].f.Col = 13    // b.yaml:2, after "  password: "
	keys(s, "down", "down") // b.yaml:2
	screen := s.render()
	if len(screen) != s.h {
		t.Fatalf("%d lines for a %d-line screen", len(screen), s.h)
	}
	for i, l := range screen {
		if n := len([]rune(ansiRE.ReplaceAllString(l, ""))); n > s.w {
			t.Errorf("line %d is %d columns wide: %q", i, n, l)
		}
	}
	text := plain(screen)
	for _, want := range []string{"4 findings, 0 marked", "b.yaml:2", "2    password: Zx81kq9PmW3vT7bRq2Lp", "fp "} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	// The finding is highlighted in the preview.
	if !strings.Contains(strings.Join(screen, "\n"), ansiReverse+ansiBold+"Zx81kq9PmW3vT7bRq2Lp") {
		t.Errorf("finding not highlighted")
	}
	// A long line keeps its start and the finding.
	s.source = func(string) []string {
		return []string{"x", "start" + strings.Repeat("a", 300) + "Zx81kq9PmW3vT7bRq2Lp" + strings.Repeat("b", 300), "y"}
	}
	s.rows[0].f.Col = 306
	text = plain(s.render())
	if !strings.Contains(text, "starta") || !strings.Contains(text, "Zx81kq9PmW3vT7bRq2Lp") {
		t.Errorf("long line preview:\n%s", text)
	}
}

func TestDecodeKeys(t *testing.T) {
	got := decodeKeys([]byte("j\x1b[A\x1b[6~\rq\x03\x1b\x7fé"))
	want := []string{"j", "up", "pgdn", "enter", "q", "ctrl-c", "esc", "backspace", "é"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %q", got)
	}
}

// A key cut between two reads is decoded when the rest comes; a lone ESC
// at the end of input is "esc".
func TestDecodeKeysAcrossReads(t *testing.T) {
	var got []string
	var pending []byte
	for _, chunk := range []string{"j\x1b", "[", "A\xc3", "\xa9", "\x1b", ""} {
		pending = append(pending, chunk...)
		k, rest := decodeKeysPartial(pending, chunk == "")
		got = append(got, k...)
		pending = append(pending[:0], rest...)
	}
	if want := "j,up,é,esc"; strings.Join(got, ",") != want {
		t.Errorf("got %q, want %s", got, want)
	}
}

// Control characters of a file name never reach the terminal.
func TestTUIFileNameEscaped(t *testing.T) {
	rows := testRows()
	rows[0].file, rows[0].f.File = "evil\x1b]0;pwned\x07\x1b[2J.yaml", "evil"
	s := newTUIState(rows)
	s.w, s.h = 100, 20
	for _, l := range s.render() {
		if strings.Contains(ansiRE.ReplaceAllString(l, ""), "\x1b") || strings.ContainsAny(ansiRE.ReplaceAllString(l, ""), "\x07") {
			t.Fatalf("a control character reached the screen: %q", l)
		}
	}
	s.fileMark[rows[0].file] = actIgnore
	if sum := strings.Join(s.summary(), ""); !strings.Contains(sum, "evil") {
		t.Fatalf("summary: %q", sum)
	}
	s.dialog = &tuiDialog{title: "t", lines: s.summary(), keys: "k", on: func(*tuiState, string) bool { return true }}
	for _, l := range s.render() {
		if strings.ContainsAny(ansiRE.ReplaceAllString(l, ""), "\x1b\x07") {
			t.Fatalf("a control character in the dialog: %q", l)
		}
	}
}

// F is refused on any row of a file that holds a private key, folded too.
func TestTUIFileWithPrivateKey(t *testing.T) {
	rows := testRows()
	pem := &tuiRow{f: Finding{File: "b.yaml", Line: 5, Col: 1, Text: "-----BEGIN PRIVATE KEY-----", Kind: kindPEM, Label: "-----BEGIN PRIVATE KEY-----"}, file: "b.yaml"}
	pem.fp = pem.f.FP()
	s := newTUIState(append(rows, pem))
	keys(s, "home", "down", "down") // b.yaml, the entropy row
	if _, r := s.current(); r == nil || r.f.Kind == kindPEM || r.file != "b.yaml" {
		t.Fatalf("not on the entropy row of b.yaml: %+v", r)
	}
	keys(s, "F")
	if s.fileMark["b.yaml"] != 0 || !strings.Contains(s.msg, "private key") {
		t.Errorf("F on a file with a private key: %q", s.msg)
	}
	keys(s, "z", "F") // folded
	if s.fileMark["b.yaml"] != 0 {
		t.Errorf("F on the folded row of a file with a private key")
	}
}

func TestSplitPaths(t *testing.T) {
	in := []string{"dir with spaces", `a"b`, `c\d`, "plain"}
	q := quotePaths(in)
	if got := splitPaths(q); strings.Join(got, "|") != strings.Join(in, "|") {
		t.Errorf("round trip %q -> %q -> %q", in, q, got)
	}
	if got := splitPaths(`"x y" z\ w  v`); strings.Join(got, "|") != "x y|z w|v" {
		t.Errorf("typed: %q", got)
	}
}

// A rescan keeps a mark only while the files it rests on are unchanged;
// an A mark also needs the fingerprint to be in no new file.
func TestTUICarryMarks(t *testing.T) {
	hashes := map[string]string{"a.conf": "ha", "b.yaml": "hb", "c.sh": "hc"}
	mark := func() *tuiState {
		s := newTUIState(testRows())
		s.hashes = hashes
		s.fpMark[s.rows[1].fp] = true                      // A: a.conf (both rows)
		s.fpHere[fpHereKey(s.rows[0].fp, "b.yaml")] = true // a: b.yaml
		s.fileMark["c.sh"] = actIgnore                     // I: c.sh
		return s
	}
	rescan := func(h map[string]string, rows []*tuiRow) (*tuiState, int) {
		s := newTUIState(rows)
		s.hashes = h
		return s, s.carryMarks(mark())
	}
	if s, n := rescan(hashes, testRows()); n != 0 || len(s.fpMark) != 1 || len(s.fpHere) != 1 || len(s.fileMark) != 1 {
		t.Errorf("nothing changed: dropped %d, %v %v %v", n, s.fpMark, s.fpHere, s.fileMark)
	}
	changed := map[string]string{"a.conf": "ha2", "b.yaml": "hb2", "c.sh": "hc2"}
	if s, n := rescan(changed, testRows()); n != 3 || s.nMarked() != 0 {
		t.Errorf("all files changed: dropped %d, %d marked", n, s.nMarked())
	}
	// The A fingerprint shows up in a file it was not in when marked.
	rows := testRows()
	extra := *rows[1]
	extra.file, extra.f.File = "d.conf", "d.conf"
	h := map[string]string{"a.conf": "ha", "b.yaml": "hb", "c.sh": "hc", "d.conf": "hd"}
	if s, n := rescan(h, append(rows, &extra)); n != 1 || len(s.fpMark) != 0 {
		t.Errorf("fp in a new file: dropped %d, %v", n, s.fpMark)
	}
}

// F is refused for a file whose private key the allowlist hides.
func TestTUIFileWithAllowedPrivateKey(t *testing.T) {
	s := newTUIState(testRows())
	s.pemFiles = map[string]bool{"b.yaml": true}
	keys(s, "home", "down", "down", "F") // b.yaml
	if s.fileMark["b.yaml"] != 0 || !strings.Contains(s.msg, "private key") {
		t.Errorf("F with a hidden private key: %q", s.msg)
	}
}

// A carries the hash of every file with the fingerprint; E on a folded
// file opens the name it was scanned under.
func TestTUIAHashesAndFoldedEdit(t *testing.T) {
	rows := testRows()
	extra := *rows[1]
	extra.file, extra.f.File = "sub/d.conf", "d.conf" // scanned from sub/
	s := newTUIState(append(rows, &extra))
	s.hashes = map[string]string{"a.conf": "ha", "b.yaml": "hb", "c.sh": "hc", "sub/d.conf": "hd"}
	keys(s, "home", "A") // a.conf
	acts := s.planActions()
	if len(acts) != 1 || acts[0].Hashes["sub/d.conf"] != "hd" {
		t.Errorf("A: %+v", acts)
	}
	keys(s, "end", "z", "E") // sub/d.conf is last, folded
	if s.editFile != "d.conf" {
		t.Errorf("E on a folded file: %q", s.editFile)
	}
}

// A also checks the files where the allowlist hides the fingerprint.
func TestTUIAHiddenOccurrences(t *testing.T) {
	s := newTUIState(testRows())
	fp := s.rows[1].fp // a.conf
	s.hashes = map[string]string{"a.conf": "ha", "b.yaml": "hb", "c.sh": "hc", "hidden.conf": "hh"}
	s.fpFiles = map[string]map[string]bool{fp: {"a.conf": true, "hidden.conf": true}}
	keys(s, "home", "A")
	if acts := s.planActions(); len(acts) != 1 || acts[0].Hashes["hidden.conf"] != "hh" {
		t.Errorf("A: %+v", acts)
	}
	// and a rescan where hidden.conf changed drops the mark
	n := newTUIState(testRows())
	n.hashes = map[string]string{"a.conf": "ha", "b.yaml": "hb", "c.sh": "hc", "hidden.conf": "hh2"}
	n.fpFiles = s.fpFiles
	if d := n.carryMarks(s); d != 1 || len(n.fpMark) != 0 {
		t.Errorf("hidden file changed: dropped %d, %v", d, n.fpMark)
	}
}

// An invalid UTF-8 byte is skipped, alone or at the end of input.
func TestDecodeKeysInvalidUTF8(t *testing.T) {
	for _, in := range []string{"\xff", "a\xfe", "\xc3", "\xffj"} {
		got := decodeKeys([]byte(in))
		for _, k := range got {
			if k == "�" {
				t.Errorf("%q: a replacement character as a key: %q", in, got)
			}
		}
	}
	if got := decodeKeys([]byte("\xffj")); strings.Join(got, ",") != "j" {
		t.Errorf("got %q", got)
	}
}

// The paths field survives segscan-tui: a name ending in a space too.
func TestTUIParamsRoundTrip(t *testing.T) {
	in := tuiParams{paths: quotePaths([]string{"name ", " lead", "a b"}), bpc: "4.5", minlen: "12", showAllowed: true, previewLines: 5}
	out := parseTUIParams([]byte(encodeTUIParams(in)))
	if out != in {
		t.Errorf("got %+v, want %+v", out, in)
	}
	if got := splitPaths(out.paths); strings.Join(got, "|") != "name | lead|a b" {
		t.Errorf("paths %q", got)
	}
}

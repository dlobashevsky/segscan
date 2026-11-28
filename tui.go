package main

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// segscan tui (docs/tui.md): the state of a session and how keys change
// it. Nothing here touches the terminal or the files: render returns the
// screen as lines, and the actions become a plan only on save.

type tuiRow struct {
	f       Finding
	file    string // repository path (what actions name)
	fp      string
	allowed bool // fp in the allowlist ("show allowed" mode)
	llm     float64
	hasLLM  bool
}

func (r *tuiRow) key() string { return fmt.Sprintf("%s:%d:%d", r.file, r.f.Line, r.f.Col) }

type viewItem struct {
	row  int    // index into rows, -1 for a folded file
	file string // the file of the row or of the folded group
	n    int    // folded: findings in it
}

type tuiDialog struct {
	title string
	lines []string
	keys  string                           // shown at the bottom
	on    func(s *tuiState, k string) bool // true: close the dialog
}

const (
	sortFile = iota // file, bpc, llm
	sortBpc         // bpc, llm, file
	sortLLM         // llm, bpc, file
)

var sortNames = []string{"file,bpc,llm", "bpc,llm,file", "llm,bpc,file"}

type tuiState struct {
	rows     []*tuiRow
	hashes   map[string]string               // repository path -> hash at the scan
	pemFiles map[string]bool                 // files with a private key, shown or allowed
	fpFiles  map[string]map[string]int       // fingerprint -> file -> findings, shown or allowed
	source   func(file string) []string      // lines of a file for the preview
	ignore   func(file string) (inHead bool) // git state for action I

	view       []viewItem
	cur, top   int
	sortMode   int
	hideMarked bool
	onlyFile   string
	folded     map[string]bool

	fileMark map[string]actKind // I or F, by file
	fileHist map[string]bool    // I confirmed for a file in HEAD
	fpMark   map[string]bool    // A, by fingerprint: everywhere
	fpHere   map[string]bool    // a, by fpHereKey: the fingerprint in that file

	previewLines int
	w, h         int
	msg          string
	dialog       *tuiDialog
	quit         bool // the session is over
	applyOnQuit  bool
	saveNow      bool // the caller applies the plan, then rescans
	editFile     string
	editLine     int
	rescan       bool
}

func newTUIState(rows []*tuiRow) *tuiState {
	s := &tuiState{rows: rows, folded: map[string]bool{}, fpHere: map[string]bool{},
		fileMark: map[string]actKind{}, fileHist: map[string]bool{}, fpMark: map[string]bool{},
		previewLines: 3, w: 100, h: 30, hashes: map[string]string{}}
	s.rebuild()
	return s
}

// actAllowFPHere is the TUI's mark for "a": an actAllowFP with the row's
// file as its glob.
const actAllowFPHere actKind = 'a'

func fpHereKey(fp, file string) string { return fp + "\x00" + file }

// mark returns the action that applies to a row: a file action wins over
// a fingerprint everywhere, which wins over the fingerprint in this file.
func (s *tuiState) mark(r *tuiRow) (actKind, bool) {
	here := s.fpHere[fpHereKey(r.fp, r.file)]
	if k, ok := s.fileMark[r.file]; ok {
		return k, here || s.fpMark[r.fp] // overridden: a row action under it
	}
	if s.fpMark[r.fp] {
		return actAllowFP, false
	}
	if here {
		return actAllowFPHere, false
	}
	return 0, false
}

func (s *tuiState) nMarked() int {
	n := 0
	for _, r := range s.rows {
		if k, _ := s.mark(r); k != 0 {
			n++
		}
	}
	return n
}

// rebuild recomputes the view after a change of sort, filter or marks,
// keeping the cursor on the same row where it can.
func (s *tuiState) rebuild() {
	var keep, keepFile string
	if s.cur < len(s.view) {
		it := s.view[s.cur]
		keepFile = "file:" + it.file
		if it.row >= 0 {
			keep = s.rows[it.row].key()
		} else {
			keep = keepFile
		}
	}
	idx := make([]int, 0, len(s.rows))
	for i, r := range s.rows {
		if s.onlyFile != "" && r.file != s.onlyFile {
			continue
		}
		if k, _ := s.mark(r); s.hideMarked && k != 0 {
			continue
		}
		idx = append(idx, i)
	}
	less := func(a, b *tuiRow) bool {
		llm := func(r *tuiRow) float64 {
			if r.hasLLM {
				return r.llm
			}
			return -1 // without a score: last
		}
		cmpFile := func() int { return strings.Compare(a.key(), b.key()) }
		switch s.sortMode {
		case sortBpc:
			if a.f.Bits != b.f.Bits {
				return a.f.Bits > b.f.Bits
			}
			if llm(a) != llm(b) {
				return llm(a) > llm(b)
			}
		case sortLLM:
			if llm(a) != llm(b) {
				return llm(a) > llm(b)
			}
			if a.f.Bits != b.f.Bits {
				return a.f.Bits > b.f.Bits
			}
		default:
			if a.file != b.file {
				return a.file < b.file
			}
			if a.f.Bits != b.f.Bits {
				return a.f.Bits > b.f.Bits
			}
		}
		return cmpFile() < 0
	}
	sort.SliceStable(idx, func(i, j int) bool { return less(s.rows[idx[i]], s.rows[idx[j]]) })
	s.view = s.view[:0]
	done := map[string]bool{}
	for _, i := range idx {
		f := s.rows[i].file
		if s.folded[f] {
			if !done[f] {
				done[f] = true
				n := 0
				for _, j := range idx {
					if s.rows[j].file == f {
						n++
					}
				}
				s.view = append(s.view, viewItem{row: -1, file: f, n: n})
			}
			continue
		}
		s.view = append(s.view, viewItem{row: i, file: f})
	}
	// The same row, or the folded row of its file.
	s.cur = 0
	found := false
	for i, it := range s.view {
		k := "file:" + it.file
		if it.row >= 0 {
			k = s.rows[it.row].key()
		}
		if k == keep {
			s.cur, found = i, true
			break
		}
	}
	for i, it := range s.view {
		if !found && it.row < 0 && "file:"+it.file == keepFile {
			s.cur = i
			break
		}
	}
	s.clamp()
}

func (s *tuiState) listHeight() int {
	h := (s.h - 3) / 2
	if h < 3 {
		h = 3
	}
	return h
}

func (s *tuiState) clamp() {
	if s.cur >= len(s.view) {
		s.cur = len(s.view) - 1
	}
	if s.cur < 0 {
		s.cur = 0
	}
	lh := s.listHeight()
	if s.cur < s.top {
		s.top = s.cur
	}
	if s.cur >= s.top+lh {
		s.top = s.cur - lh + 1
	}
	if s.top < 0 {
		s.top = 0
	}
}

func (s *tuiState) current() (viewItem, *tuiRow) {
	if s.cur >= len(s.view) {
		return viewItem{row: -1}, nil
	}
	it := s.view[s.cur]
	if it.row < 0 {
		return it, nil
	}
	return it, s.rows[it.row]
}

// hasPEM reports a private key anywhere in the file: a row, or one the
// scan found but the allowlist hides.
func (s *tuiState) hasPEM(file string) bool {
	if s.pemFiles[file] {
		return true
	}
	for _, r := range s.rows {
		if r.file == file && r.f.Kind == kindPEM {
			return true
		}
	}
	return false
}

// carryMarks takes the marks of the session before a rescan, except those
// that rest on a file changed since (or, for A, on a file that holds the
// fingerprint only now): those files are to be looked at again. It
// returns how many marks were dropped.
func (s *tuiState) carryMarks(old *tuiState) int {
	s.sortMode, s.hideMarked, s.onlyFile, s.folded = old.sortMode, old.hideMarked, old.onlyFile, old.folded
	dropped := 0
	same := func(f string) bool { return old.hashes[f] != "" && old.hashes[f] == s.hashes[f] }
	for f, k := range old.fileMark {
		if same(f) {
			s.fileMark[f], s.fileHist[f] = k, old.fileHist[f]
		} else {
			dropped++
		}
	}
	for k := range old.fpHere {
		if same(k[strings.IndexByte(k, 0)+1:]) {
			s.fpHere[k] = true
		} else {
			dropped++
		}
	}
	for fp := range old.fpMark {
		ok := true
		for _, st := range []*tuiState{old, s} {
			for _, f := range st.filesWithFP(fp) {
				if !same(f) {
					ok = false
				}
			}
		}
		if ok {
			s.fpMark[fp] = true
		} else {
			dropped++
		}
	}
	s.rebuild()
	return dropped
}

// filesWithFP lists the files holding a fingerprint: those of its rows
// and those where the allowlist hides it.
func (s *tuiState) filesWithFP(fp string) []string {
	seen := map[string]bool{}
	for f := range s.fpFiles[fp] {
		seen[f] = true
	}
	for _, r := range s.rows {
		if r.fp == fp {
			seen[r.file] = true
		}
	}
	return sortedKeys(seen)
}

// fpSpread counts the findings and files that share a fingerprint, those
// the allowlist hides included: A covers them all.
func (s *tuiState) fpSpread(fp string) (n, files int) {
	if m := s.fpFiles[fp]; len(m) > 0 {
		for _, c := range m {
			n += c
		}
		return n, len(m)
	}
	seen := map[string]bool{}
	for _, r := range s.rows {
		if r.fp == fp {
			n++
			seen[r.file] = true
		}
	}
	return n, len(seen)
}

// spreadText is "N findings in M files", and how many of them are not
// shown because the allowlist has them already.
func (s *tuiState) spreadText(fp string) string {
	n, files := s.fpSpread(fp)
	shown := 0
	for _, r := range s.rows {
		if r.fp == fp {
			shown++
		}
	}
	t := fmt.Sprintf("%d findings in %d files", n, files)
	if n > shown {
		t += fmt.Sprintf(", %d of them allowed already", n-shown)
	}
	return t
}

// key handles one key. Keys are names: "up", "down", "pgup", "pgdn",
// "home", "end", "enter", "esc", "ctrl-c" or the character typed.
func (s *tuiState) key(k string) {
	s.msg = ""
	if s.dialog != nil {
		if s.dialog.on(s, k) {
			s.dialog = nil
		}
		return
	}
	it, r := s.current()
	switch k {
	case "up", "k":
		s.cur--
	case "down", "j":
		s.cur++
	case "pgup":
		s.cur -= s.listHeight()
	case "pgdn", " ":
		s.cur += s.listHeight()
	case "home":
		s.cur = 0
	case "end":
		s.cur = len(s.view) - 1
	case "s":
		s.sortMode = (s.sortMode + 1) % len(sortNames)
		s.rebuild()
	case "h":
		s.hideMarked = !s.hideMarked
		s.rebuild()
	case "f":
		if s.onlyFile != "" {
			s.onlyFile = ""
		} else if it.file != "" {
			s.onlyFile = it.file
		}
		s.rebuild()
	case "z":
		if it.file != "" {
			s.folded[it.file] = !s.folded[it.file]
			s.rebuild()
		}
	case "I", "F":
		if it.file == "" {
			return
		}
		kind := actKind(k[0])
		if kind == actAllowFile && s.hasPEM(it.file) {
			s.msg = "F is not offered for a file with a private key: path: would hide it from the scan (a: the fp in this file)"
			return
		}
		if kind == actAllowFile {
			if _, err := allowPathLine(it.file); err != nil {
				s.msg = err.Error()
				return
			}
		}
		if kind == actIgnore && s.ignore != nil && s.ignore(it.file) && !s.fileHist[it.file] {
			f := it.file
			s.dialog = &tuiDialog{
				title: "Ignore a committed file?",
				lines: []string{f + " is in HEAD: its content is in the history already.",
					"Ignoring it stops tracking it from now on; it does not remove the value from the history."},
				keys: "y ignore anyway   n cancel",
				on: func(s *tuiState, k string) bool {
					switch k {
					case "y":
						s.fileHist[f] = true
						s.fileMark[f] = actIgnore
						s.rebuild()
						return true
					case "n", "esc":
						return true
					}
					return false
				},
			}
			return
		}
		s.fileMark[it.file] = kind
		s.rebuild()
	case "A":
		if r == nil {
			return
		}
		if r.f.Kind == kindPEM {
			s.msg = "A is not offered for a private key: its fp is the BEGIN line, the same for every key (a: in this file)"
			return
		}
		for k := range s.fpHere {
			if strings.HasPrefix(k, r.fp+"\x00") {
				delete(s.fpHere, k)
			}
		}
		s.fpMark[r.fp] = true
		s.rebuild()
	case "a":
		if r == nil {
			return
		}
		if s.fpMark[r.fp] {
			s.msg = "this fingerprint is marked A (everywhere); U first"
			return
		}
		if _, err := allowFPLine(r.fp, "/"+globEscape(r.file)); err != nil {
			s.msg = err.Error()
			return
		}
		s.fpHere[fpHereKey(r.fp, r.file)] = true
		s.rebuild()
	case "U":
		switch {
		case it.file != "" && s.fileMark[it.file] != 0:
			delete(s.fileMark, it.file)
			delete(s.fileHist, it.file)
		case r != nil && s.fpMark[r.fp]:
			delete(s.fpMark, r.fp)
		case r != nil:
			delete(s.fpHere, fpHereKey(r.fp, r.file))
		}
		s.rebuild()
	case "X":
		if s.nMarked() == 0 {
			return
		}
		s.dialog = &tuiDialog{title: "Clear all marks?", lines: []string{fmt.Sprintf("%d findings are marked.", s.nMarked())},
			keys: "y clear   n cancel", on: func(s *tuiState, k string) bool {
				switch k {
				case "y":
					s.clearMarks()
					return true
				case "n", "esc":
					return true
				}
				return false
			}}
	case "E":
		if r != nil {
			s.editFile, s.editLine = r.f.File, r.f.Line
		} else if it.file != "" {
			// a folded file: the name it was scanned under, as for a row
			// (it.file is from the repository top, the editor runs here)
			for _, o := range s.rows {
				if o.file == it.file {
					s.editFile, s.editLine = o.f.File, 1
					break
				}
			}
		}
	case "r":
		s.rescan = true
	case "w":
		if s.nMarked() == 0 && len(s.fileMark) == 0 {
			s.msg = "nothing marked"
			return
		}
		s.saveNow = true
	case "q", "ctrl-c":
		if len(s.planActions()) == 0 {
			s.quit = true
			return
		}
		s.dialog = &tuiDialog{title: "Quit", lines: s.summary(), keys: "a apply all and quit   d discard all and quit   esc stay",
			on: func(s *tuiState, k string) bool {
				switch k {
				case "a":
					s.quit, s.applyOnQuit = true, true
					return true
				case "d":
					s.quit = true
					return true
				case "esc", "n":
					return true
				}
				return false
			}}
	case "?":
		s.dialog = &tuiDialog{title: "Keys", lines: tuiHelp, keys: "any key", on: func(*tuiState, string) bool { return true }}
	}
	s.clamp()
}

var tuiHelp = []string{
	"up/down j/k pgup/pgdn home/end   move",
	"s  sort: file,bpc,llm / bpc,llm,file / llm,bpc,file",
	"h  hide marked rows      f  only this file (again: all)",
	"z  fold this file's findings into one row",
	"I  file -> .gitignore    F  file -> allowlist (path:)",
	"a  fingerprint -> allowlist, in this file only",
	"A  fingerprint -> allowlist, everywhere (every finding with that fp)",
	"U  unmark                X  clear all marks",
	"E  open in $EDITOR at the line (rescans)    r  rescan",
	"   segscan:allow anywhere on a line skips it: write it there yourself,",
	"   in a comment of the file's language (segscan never writes it)",
	"w  save: apply the marks after a summary",
	"q  quit (asks what to do with the marks)",
}

func (s *tuiState) clearMarks() {
	s.fpHere, s.fileMark, s.fileHist, s.fpMark = map[string]bool{}, map[string]actKind{}, map[string]bool{}, map[string]bool{}
	s.rebuild()
}

// globalAction is the action of an A mark: one fp line for every file
// with the fingerprint, shown or hidden by the allowlist. It is left out
// only when file actions (I, F) cover all those files. Its comment names
// a file and line not under a file action where there is one; every file
// with the fingerprint must still be as it was scanned.
func (s *tuiState) globalAction(fp string) (action, bool) {
	var rest []string
	for _, f := range s.filesWithFP(fp) {
		if s.fileMark[f] == 0 {
			rest = append(rest, f)
		}
	}
	if len(rest) == 0 {
		return action{}, false
	}
	a := action{Kind: actAllowFP, FP: fp, File: rest[0]}
	for _, r := range s.rows {
		if r.fp == fp && s.fileMark[r.file] == 0 {
			a.File, a.Line = r.file, r.f.Line
			break
		}
	}
	a.Hash = s.hashes[a.File]
	a.Hashes = map[string]string{}
	for _, f := range s.filesWithFP(fp) {
		if f != a.File {
			a.Hashes[f] = s.hashes[f]
		}
	}
	return a, true
}

// planActions turns the marks into actions; nothing is written here.
func (s *tuiState) planActions() []action {
	var out []action
	for _, f := range sortedKeys(s.fileMark) {
		out = append(out, action{Kind: s.fileMark[f], File: f, Hash: s.hashes[f], History: s.fileHist[f]})
	}
	done := map[string]bool{}
	for _, r := range s.rows {
		if s.fpMark[r.fp] && !done[r.fp] {
			done[r.fp] = true
			if a, ok := s.globalAction(r.fp); ok {
				out = append(out, a)
			}
		}
		if s.fileMark[r.file] != 0 {
			continue // the file action covers it
		}
		if k := fpHereKey(r.fp, r.file); s.fpHere[k] && !s.fpMark[r.fp] && !done[k] {
			done[k] = true
			out = append(out, action{Kind: actAllowFP, FP: r.fp, File: r.file, Line: r.f.Line,
				Glob: "/" + globEscape(r.file), Hash: s.hashes[r.file]})
		}
	}
	return out
}

// summary lists the marked actions for the quit dialog.
func (s *tuiState) summary() []string {
	var out []string
	for _, a := range s.planActions() {
		switch a.Kind {
		case actIgnore:
			out = append(out, "I  "+a.File+"  -> .gitignore")
		case actAllowFile:
			out = append(out, "F  "+a.File+"  -> allowlist")
		case actAllowFP:
			if a.Glob != "" {
				out = append(out, fmt.Sprintf("a  %s  -> allowlist, in %s only", a.FP, a.File))
				continue
			}
			out = append(out, fmt.Sprintf("A  %s  -> allowlist (%s)", a.FP, s.spreadText(a.FP)))
		}
	}
	return out
}

// ---------- rendering ----------

const (
	ansiReset   = "\x1b[0m"
	ansiReverse = "\x1b[7m"
	ansiDim     = "\x1b[2m"
	ansiBold    = "\x1b[1m"
)

var markColour = map[actKind]string{
	actIgnore:      "\x1b[31m", // red
	actAllowFile:   "\x1b[33m", // yellow
	actAllowFP:     "\x1b[36m", // cyan
	actAllowFPHere: "\x1b[36m",
}

// fit cuts or pads s to n columns (one rune, one column). Control
// characters become "·": everything shown goes through fit or show, and a
// file name can hold ESC.
func fit(s string, n int) string {
	if n <= 0 {
		return ""
	}
	s = show(s)
	if c := utf8.RuneCountInString(s); c <= n {
		return s + strings.Repeat(" ", n-c)
	}
	r := []rune(s)
	if n == 1 {
		return string(r[:1])
	}
	return string(r[:n-1]) + "…"
}

// show makes a finding's text printable on one line.
func show(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '\t':
			b.WriteString(" ")
		case c < 0x20 || (c >= 0x7f && c < 0xa0) || c == utf8.RuneError:
			b.WriteString("·")
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// render returns the screen, one string per line, with ANSI attributes.
func (s *tuiState) render() []string {
	var out []string
	w := s.w
	head := fmt.Sprintf(" segscan tui  %d findings, %d marked   sort %s", len(s.rows), s.nMarked(), sortNames[s.sortMode])
	if s.hideMarked {
		head += "   marked hidden"
	}
	if s.onlyFile != "" {
		head += "   file " + s.onlyFile
	}
	out = append(out, ansiBold+fit(head+"   ? keys", w)+ansiReset)

	lh := s.listHeight()
	for i := s.top; i < s.top+lh; i++ {
		if i >= len(s.view) {
			out = append(out, "")
			continue
		}
		it := s.view[i]
		var line, style string
		if it.row < 0 {
			k := s.fileMark[it.file]
			mk := " "
			if k != 0 {
				mk = string(k)
				style = markColour[k]
			}
			line = fmt.Sprintf("%s %-5s %-4s  %s  (%d findings, folded)", mk, "", "", it.file, it.n)
		} else {
			r := s.rows[it.row]
			k, over := s.mark(r)
			mk := " "
			switch {
			case k != 0:
				mk = string(k)
				style = markColour[k]
			case r.allowed:
				mk = "="
				style = ansiDim
			}
			if over {
				mk = strings.ToLower(mk)
			}
			llm := "  -  "
			if r.hasLLM {
				llm = fmt.Sprintf("%5.2f", r.llm)
			}
			loc := fmt.Sprintf("%s:%d", r.file, r.f.Line)
			text := show(r.f.Text)
			if r.f.Kind == kindPEM {
				text = r.f.Label
			}
			line = fmt.Sprintf("%s %s %4.2f  %s  %s", mk, llm, r.f.Bits, fit(loc, 40), text)
		}
		line = fit(line, w)
		if i == s.cur {
			style += ansiReverse
		}
		if style != "" {
			line = style + line + ansiReset
		}
		out = append(out, line)
	}

	out = append(out, ansiDim+strings.Repeat("─", w)+ansiReset)
	out = append(out, s.preview(s.h-len(out)-1)...)
	for len(out) < s.h-1 {
		out = append(out, "")
	}
	out = append(out[:s.h-1], fit(s.statusLine(), w))
	if s.dialog != nil {
		out = s.overlay(out)
	}
	return out
}

func (s *tuiState) statusLine() string {
	if s.msg != "" {
		return " " + s.msg
	}
	it, r := s.current()
	if it.file == "" {
		return " no findings   q quit"
	}
	var st string
	if r != nil {
		k, over := s.mark(r)
		switch k {
		case actIgnore:
			st = "planned: " + r.file + " -> .gitignore"
		case actAllowFile:
			st = "planned: " + r.file + " -> allowlist (path:)"
		case actAllowFP:
			st = fmt.Sprintf("planned: fp %s -> allowlist, everywhere (%s)", r.fp, s.spreadText(r.fp))
		case actAllowFPHere:
			st = fmt.Sprintf("planned: fp %s -> allowlist, in %s only", r.fp, r.file)
		default:
			st = fmt.Sprintf("fp %s", r.fp)
			if n, _ := s.fpSpread(r.fp); n > 1 {
				st += " (" + s.spreadText(r.fp) + ")"
			}
			if r.allowed {
				st += "   in the allowlist"
			}
		}
		if over {
			st += "   (a row action under the file action)"
		}
	} else if k := s.fileMark[it.file]; k != 0 {
		st = fmt.Sprintf("planned: %s (%c)", it.file, k)
	} else {
		st = it.file + ": folded"
	}
	return " " + st + "   I F a A U E  w save  q quit  ? keys"
}

// preview shows the lines around the current finding, the finding
// highlighted; a long line shows its start and the part around it.
func (s *tuiState) preview(n int) []string {
	_, r := s.current()
	if r == nil || s.source == nil || n <= 0 {
		return nil
	}
	lines := s.source(r.f.File)
	var out []string
	from, to := r.f.Line-s.previewLines, r.f.Line+s.previewLines
	if from < 1 {
		from = 1
	}
	if to > len(lines) {
		to = len(lines)
	}
	numW := len(fmt.Sprint(to))
	for no := from; no <= to && len(out) < n; no++ {
		text := lines[no-1]
		prefix := fmt.Sprintf("%*d  ", numW, no)
		room := s.w - len(prefix)
		if no != r.f.Line {
			out = append(out, ansiDim+prefix+ansiReset+fit(show(text), room))
			continue
		}
		start, end := r.f.Col-1, r.f.Col-1+len(r.f.Text)
		if r.f.Kind == kindPEM || start < 0 || end > len(text) {
			out = append(out, ansiBold+prefix+ansiReset+fit(show(text), room))
			continue
		}
		before, mid, after := text[:start], text[start:end], text[end:]
		// Keep the start of the line, then the part around the finding.
		if utf8.RuneCountInString(before)+utf8.RuneCountInString(mid) > room {
			head := []rune(before)
			keepHead := room / 4
			if len(head) > keepHead {
				tail := room / 4
				if tail > len(head)-keepHead {
					tail = len(head) - keepHead
				}
				before = string(head[:keepHead]) + "…" + string(head[len(head)-tail:])
			}
			if m := []rune(mid); len(m) > room/2 {
				mid = string(m[:room/4]) + "…" + string(m[len(m)-room/8:])
			}
		}
		vis := fit(show(before)+show(mid)+show(after), room)
		cut := utf8.RuneCountInString(show(before))
		m := utf8.RuneCountInString(show(mid))
		rs := []rune(vis)
		if cut > len(rs) {
			cut = len(rs)
		}
		if cut+m > len(rs) {
			m = len(rs) - cut
		}
		line := ansiBold + prefix + ansiReset + string(rs[:cut]) + ansiReverse + ansiBold + string(rs[cut:cut+m]) + ansiReset + string(rs[cut+m:])
		out = append(out, line)
	}
	return out
}

// overlay draws the dialog over the middle of the screen.
func (s *tuiState) overlay(screen []string) []string {
	d := s.dialog
	bw := s.w - 8
	if bw > 100 {
		bw = 100
	}
	if bw < 20 {
		bw = s.w
	}
	body := []string{ansiBold + fit(" "+d.title, bw) + ansiReset}
	room := s.h - 6
	for i, l := range d.lines {
		if i == room-1 && len(d.lines) > room {
			body = append(body, fit(fmt.Sprintf(" ... %d more", len(d.lines)-i), bw))
			break
		}
		body = append(body, fit(" "+l, bw))
	}
	body = append(body, fit("", bw), ansiReverse+fit(" "+d.keys, bw)+ansiReset)
	top := (s.h - len(body)) / 2
	if top < 0 {
		top = 0
	}
	left := strings.Repeat(" ", (s.w-bw)/2)
	out := append([]string{}, screen...)
	for i, l := range body {
		if top+i < len(out) {
			out[top+i] = left + l
		}
	}
	return out
}

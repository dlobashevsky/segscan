package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// segscan tui: the terminal side. The state and the keys are in tui.go.

// dieHook restores the terminal before die exits.
var dieHook func()

type tuiParams struct {
	paths        string // as typed: split by splitPaths, quoted by quotePaths
	bpc, minlen  string
	showAllowed  bool
	previewLines int
}

func cmdTUI(args []string) {
	fs, c := flags("tui")
	now := fs.Bool("now", false, "scan at once, without the launch screen")
	fs.Parse(args)
	c.finish(fs)
	if !isTerminal(0) || !isTerminal(1) {
		die(fmt.Errorf("tui: stdin and stdout must be a terminal"))
	}
	top := repoTop()
	if top == "" {
		die(fmt.Errorf("tui: not a git repository"))
	}
	allowPath := allowFilePath(c.allow)
	m := mustModel(c) // before the screen: it may print a note
	p := loadTUIParams()
	if fs.NArg() > 0 {
		p.paths = quotePaths(fs.Args())
	}
	if c.set["bpc"] || (p.bpc == "" && c.o.MinBpc > 0) {
		p.bpc = strconv.FormatFloat(c.o.MinBpc, 'f', -1, 64)
	}
	if c.set["minlen"] {
		p.minlen = strconv.Itoa(c.o.MinLen)
	}

	t, err := openTTY()
	if err != nil {
		die(err)
	}
	dieHook = t.close
	defer t.close()

	if !*now {
		var ok bool
		if p, ok = t.launch(p); !ok {
			return
		}
	}
	saveTUIParams(p)
	app := &tuiApp{c: c, m: m, top: top, allowPath: allowPath, p: p, t: t}
	app.run()
}

// ---------- the terminal ----------

type tty struct {
	old   *termState
	keys  chan string
	winch chan os.Signal
	done  bool
	// The reader stops while the editor has the terminal: suspend sends
	// on pause and waits for paused; resume sends on resumed.
	pause, paused, resumed chan struct{}
}

func openTTY() (*tty, error) {
	old, err := makeRaw(0)
	if err != nil {
		return nil, fmt.Errorf("tui: %v", err)
	}
	t := &tty{old: old, keys: make(chan string, 256), winch: make(chan os.Signal, 1),
		pause: make(chan struct{}), paused: make(chan struct{}), resumed: make(chan struct{})}
	if sig := winchSignal(); sig != nil {
		signal.Notify(t.winch, sig)
	}
	os.Stdout.WriteString("\x1b[?1049h\x1b[?25l")
	go t.read()
	return t, nil
}

func (t *tty) close() {
	if t.done {
		return
	}
	t.done = true
	os.Stdout.WriteString("\x1b[0m\x1b[?25h\x1b[?1049l")
	restoreTerm(0, t.old)
}

// suspend gives the terminal back (for the editor): the reader stops
// first, so no key typed in the editor reaches the TUI. resume takes the
// terminal again and restarts the reader.
func (t *tty) suspend() {
	t.pause <- struct{}{}
	<-t.paused
	os.Stdout.WriteString("\x1b[0m\x1b[?25h\x1b[?1049l")
	restoreTerm(0, t.old)
}

func (t *tty) resume() {
	makeRaw(0)
	os.Stdout.WriteString("\x1b[?1049h\x1b[?25l")
	t.resumed <- struct{}{}
}

// read turns the bytes of stdin into key names. A read returns after
// 0.1 s without input (VTIME), so the loop sees a pause request soon, and
// a key cut between two reads (ESC [ A, a UTF-8 character) is kept until
// the rest comes; what is still pending after a quiet read is final.
func (t *tty) read() {
	buf := make([]byte, 64)
	var pending []byte
	for {
		select {
		case <-t.pause:
			pending = nil
			t.paused <- struct{}{}
			<-t.resumed
			continue
		default:
		}
		n, err := os.Stdin.Read(buf)
		if n == 0 && err != nil && err != io.EOF {
			close(t.keys)
			return
		}
		pending = append(pending, buf[:n]...)
		keys, rest := decodeKeysPartial(pending, n == 0)
		pending = append(pending[:0], rest...)
		for _, k := range keys {
			select {
			case t.keys <- k:
			default: // 256 keys behind: drop
			}
		}
	}
}

var escKeys = map[string]string{
	"\x1b[A": "up", "\x1b[B": "down", "\x1b[C": "right", "\x1b[D": "left",
	"\x1bOA": "up", "\x1bOB": "down", "\x1bOC": "right", "\x1bOD": "left",
	"\x1b[5~": "pgup", "\x1b[6~": "pgdn",
	"\x1b[H": "home", "\x1b[1~": "home", "\x1bOH": "home", "\x1b[7~": "home",
	"\x1b[F": "end", "\x1b[4~": "end", "\x1bOF": "end", "\x1b[8~": "end",
	"\x1b[3~": "delete",
}

// decodeKeys splits the bytes of the terminal into keys, all of them: a
// lone ESC is "esc".
func decodeKeys(b []byte) []string {
	k, _ := decodeKeysPartial(b, true)
	return k
}

// decodeKeysPartial is decodeKeys for input that may go on: unless final,
// an ESC that may start a sequence not complete yet, or the first bytes of
// a UTF-8 character, are left in rest.
func decodeKeysPartial(b []byte, final bool) (out []string, rest []byte) {
	for len(b) > 0 {
		if !final && escPrefix(b) {
			return out, b
		}
		if !final && b[0] >= 0x80 && !utf8.FullRune(b) {
			return out, b
		}
		if b[0] == 0x1b {
			matched := false
			for seq, name := range escKeys {
				if bytes.HasPrefix(b, []byte(seq)) {
					out = append(out, name)
					b = b[len(seq):]
					matched = true
					break
				}
			}
			if matched {
				continue
			}
			if len(b) > 1 && (b[1] == '[' || b[1] == 'O') {
				// an unknown sequence: skip to its final byte
				k := 2
				for k < len(b) && (b[k] < 0x40 || b[k] > 0x7e) {
					k++
				}
				b = b[min(k+1, len(b)):]
				continue
			}
			out = append(out, "esc")
			b = b[1:]
			continue
		}
		switch b[0] {
		case '\r', '\n':
			out = append(out, "enter")
		case 0x7f, 0x08:
			out = append(out, "backspace")
		case 0x03:
			out = append(out, "ctrl-c")
		case '\t':
			out = append(out, "tab")
		default:
			if b[0] < 0x20 {
				break
			}
			r, size := []rune(string(b)), 0
			if len(r) > 0 {
				size = len(string(r[0]))
				out = append(out, string(r[0]))
			}
			b = b[max(size, 1):]
			continue
		}
		b = b[1:]
	}
	return out, nil
}

// escPrefix reports b starting with an escape sequence not complete yet:
// ESC alone, ESC [ or ESC O, or a CSI without its final byte.
func escPrefix(b []byte) bool {
	if b[0] != 0x1b {
		return false
	}
	if len(b) == 1 {
		return true
	}
	if b[1] != '[' && b[1] != 'O' {
		return false
	}
	for k := 2; k < len(b); k++ {
		if b[k] >= 0x40 && b[k] <= 0x7e {
			return false
		}
	}
	return true
}

func (t *tty) draw(lines []string) {
	var b strings.Builder
	b.WriteString("\x1b[H")
	for i, l := range lines {
		b.WriteString(l)
		b.WriteString("\x1b[0m\x1b[K")
		if i < len(lines)-1 {
			b.WriteString("\r\n")
		}
	}
	os.Stdout.WriteString(b.String())
}

func (t *tty) size() (int, int) {
	w, h, err := termSize(1)
	if err != nil || w < 20 || h < 8 {
		return 80, 24
	}
	return w, h
}

// next waits for a key; a resize gives "resize".
func (t *tty) next() (string, bool) {
	select {
	case k, ok := <-t.keys:
		return k, ok
	case <-t.winch:
		return "resize", true
	}
}

// ---------- the launch screen ----------

func (t *tty) launch(p tuiParams) (tuiParams, bool) {
	type field struct {
		name string
		val  *string
		flag *bool
		help string
	}
	pl := strconv.Itoa(p.previewLines)
	fields := []field{
		{"paths", &p.paths, nil, `files and directories; "a b" or a\ b for a name with a space; empty: what git would commit`},
		{"bpc", &p.bpc, nil, "report only findings of at least N bits per char; empty: none"},
		{"minlen", &p.minlen, nil, "minimum length of a finding; empty: the default"},
		{"show allowed", nil, &p.showAllowed, "also list findings whose fp is in the allowlist, dimmed"},
		{"preview lines", &pl, nil, "lines shown above and below the finding"},
	}
	cur, editing := 0, false
	for {
		w, h := t.size()
		var lines []string
		lines = append(lines, ansiBold+fit(" segscan tui: what to scan", w)+ansiReset, "")
		for i, f := range fields {
			v := ""
			if f.flag != nil {
				v = "no"
				if *f.flag {
					v = "yes"
				}
			} else {
				v = *f.val
			}
			if editing && i == cur {
				v += "█"
			}
			l := fit(fmt.Sprintf("  %-14s %s", f.name, v), w)
			if i == cur {
				l = ansiReverse + l + ansiReset
			}
			lines = append(lines, l)
		}
		scan := "  [ scan ]"
		if cur == len(fields) {
			scan = ansiReverse + fit(scan, w) + ansiReset
		}
		lines = append(lines, "", scan, "")
		if cur < len(fields) {
			lines = append(lines, ansiDim+fit("  "+fields[cur].help, w)+ansiReset)
		}
		for len(lines) < h-1 {
			lines = append(lines, "")
		}
		lines = append(lines, fit(" up/down choose   enter edit, toggle or scan   esc quit", w))
		t.draw(lines[:h])

		k, ok := t.next()
		if !ok {
			return p, false
		}
		if editing {
			f := fields[cur]
			switch k {
			case "enter", "esc":
				editing = false
			case "backspace":
				if r := []rune(*f.val); len(r) > 0 {
					*f.val = string(r[:len(r)-1])
				}
			default:
				if len([]rune(k)) == 1 {
					*f.val += k
				}
			}
			continue
		}
		switch k {
		case "up", "k":
			if cur > 0 {
				cur--
			}
		case "down", "j", "tab":
			if cur < len(fields) {
				cur++
			}
		case "enter", " ":
			if cur == len(fields) {
				p.previewLines, _ = strconv.Atoi(pl)
				if p.previewLines <= 0 {
					p.previewLines = 3
				}
				return p, true
			}
			if fields[cur].flag != nil {
				*fields[cur].flag = !*fields[cur].flag
			} else if k == "enter" {
				editing = true
			}
		case "esc", "q", "ctrl-c":
			return p, false
		}
	}
}

// ---------- the session ----------

type tuiApp struct {
	c         *common
	m         *Model
	top       string
	allowPath string
	p         tuiParams
	t         *tty
	s         *tuiState
	lines     map[string][]string
}

func (a *tuiApp) run() {
	a.scan()
	for {
		a.s.w, a.s.h = a.t.size()
		a.s.clamp()
		a.t.draw(a.s.render())
		k, ok := a.t.next()
		if !ok {
			return
		}
		if k != "resize" {
			a.s.key(k)
		}
		switch {
		case a.s.quit:
			acts := a.s.planActions()
			a.t.close()
			if a.s.applyOnQuit && len(acts) > 0 {
				p := &plan{top: a.top, allowPath: a.allowPath, actions: acts}
				r, err := p.apply(false)
				printApply(r, err)
				for _, l := range a.check() { // as after w
					fmt.Println(show(l))
				}
			}
			return
		case a.s.saveNow:
			a.s.saveNow = false
			a.save()
		case a.s.editFile != "":
			a.edit(a.s.editFile, a.s.editLine)
			a.s.editFile = ""
		case a.s.rescan:
			a.s.rescan = false
			a.scan()
		}
	}
}

// scan (re)builds the list. Marks on a file that has not changed are kept;
// those on a changed file are dropped and said so.
func (a *tuiApp) scan() {
	o := a.c.o
	if v, err := strconv.ParseFloat(strings.TrimSpace(a.p.bpc), 64); err == nil && v >= 0 {
		o.MinBpc = v
	} else if strings.TrimSpace(a.p.bpc) == "" {
		o.MinBpc = 0
	}
	if v, err := strconv.Atoi(strings.TrimSpace(a.p.minlen)); err == nil && v > 0 {
		o.MinLen = v
	}
	allow := loadAllow(a.c.allow, !a.c.noDef)
	var rows []*tuiRow
	hashes := map[string]string{}
	pem := map[string]bool{}
	outside := 0
	fpFiles := map[string]map[string]bool{}
	// The scan sees every fingerprint (path: lines still skip files); the
	// rows are the ones not allowed, or all in "show allowed" mode. A
	// needs every file with the fingerprint, shown or not.
	noFP := &allowList{fp: map[string]bool{}, paths: allow.paths, words: allow.words}
	sc := &fileScan{sc: NewScanner(a.m, o), allow: noFP}
	for _, f := range scanFiles(splitPaths(a.p.paths), false) {
		rp := repoPath(f)
		// The actions name repository paths: a file outside the checkout
		// cannot take one.
		if filepath.IsAbs(rp) || rp == ".." || strings.HasPrefix(rp, "../") {
			outside++
			continue
		}
		if allow.skipPath(rp) {
			continue
		}
		data, ok := readText(f)
		if !ok {
			continue
		}
		hashes[rp] = fileHash(data)
		// A private key, allowed or not: F (path:) would hide it.
		if bytes.Contains(data, []byte("-----BEGIN ")) && bytes.Contains(data, []byte("PRIVATE KEY")) {
			pem[rp] = true
		}
		sc.out = func(x Finding) {
			fp := x.FP()
			if fpFiles[fp] == nil {
				fpFiles[fp] = map[string]bool{}
			}
			fpFiles[fp][rp] = true
			allowed := allow.allowFP(fp, rp)
			if allowed && !a.p.showAllowed {
				return
			}
			rows = append(rows, &tuiRow{f: x, file: rp, fp: fp, allowed: allowed})
		}
		sc.rel = rp
		sc.data(f, data)
	}
	old := a.s
	a.s = newTUIState(rows)
	a.s.hashes = hashes
	a.s.pemFiles = pem
	a.s.fpFiles = fpFiles
	a.s.previewLines = a.p.previewLines
	a.lines = map[string][]string{}
	a.s.source = a.source
	a.s.ignore = func(f string) bool { _, inHead, _ := (&plan{top: a.top}).gitState(f); return inHead }
	var msgs []string
	if old != nil {
		if dropped := a.s.carryMarks(old); dropped > 0 {
			msgs = append(msgs, fmt.Sprintf("%d mark(s) dropped: their files changed", dropped))
		}
	}
	if outside > 0 {
		msgs = append(msgs, fmt.Sprintf("%d file(s) outside the repository left out", outside))
	}
	a.s.msg = strings.Join(msgs, "; ")
}

func (a *tuiApp) source(f string) []string {
	if l, ok := a.lines[f]; ok {
		return l
	}
	data, _ := os.ReadFile(f)
	l := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	a.lines[f] = l
	return l
}

// save shows what the plan will do, applies it on y, checks the tree and
// rescans.
func (a *tuiApp) save() {
	p := &plan{top: a.top, allowPath: a.allowPath, actions: a.s.planActions()}
	r, err := p.apply(true)
	lines := applyLines(r)
	if err != nil {
		lines = append(lines, "error: "+err.Error())
	}
	apply := false
	a.s.dialog = &tuiDialog{title: "Save: apply these changes?", lines: lines, keys: "y apply   n back",
		on: func(s *tuiState, k string) bool {
			switch k {
			case "y":
				apply = true
				return true
			case "n", "esc":
				return true
			}
			return false
		}}
	for a.s.dialog != nil {
		a.s.w, a.s.h = a.t.size()
		a.t.draw(a.s.render())
		k, ok := a.t.next()
		if !ok {
			return
		}
		if k != "resize" {
			a.s.key(k)
		}
	}
	if !apply {
		return
	}
	r, err = p.apply(false)
	lines = applyLines(r)
	if err != nil {
		lines = append(lines, "error: "+err.Error())
	}
	lines = append(lines, "")
	lines = append(lines, a.check()...)
	a.s.clearMarks()
	a.scan()
	a.s.dialog = &tuiDialog{title: "Saved", lines: lines, keys: "any key", on: func(*tuiState, string) bool { return true }}
}

// check runs the working-tree checks of segscan check, as cmdCheck does
// without flags, in a .sec/ repository.
func (a *tuiApp) check() []string {
	top := secRoot()
	if top == "" {
		return []string{"(no .sec/: segscan check not run)"}
	}
	finds, why, err := checkWorktree(top) // what segscan check prints
	if err != nil {
		return []string{"segscan check: " + err.Error()}
	}
	note := ""
	if why != "" {
		note = " (known values not checked: " + why + ")"
	}
	if len(finds) == 0 {
		return []string{"segscan check: clean" + note}
	}
	out := []string{fmt.Sprintf("segscan check: %d problem(s)%s", len(finds), note)}
	for _, f := range finds {
		out = append(out, fmt.Sprintf("  %s:%d  %s  %s", f.File, f.Line, f.Check, f.Msg))
	}
	return out
}

func (a *tuiApp) edit(file string, line int) {
	ed := os.Getenv("VISUAL")
	if ed == "" {
		ed = os.Getenv("EDITOR")
	}
	if ed == "" {
		ed = "vi"
	}
	a.t.suspend()
	argv := strings.Fields(ed)
	cmd := exec.Command(argv[0], append(argv[1:], fmt.Sprintf("+%d", line), file)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	a.t.resume()
	a.scan()
	if err != nil {
		a.s.msg = "editor: " + err.Error()
	}
}

func applyLines(r applyResult) []string {
	var out []string
	out = append(out, r.Done...)
	for _, w := range r.Warn {
		out = append(out, "warning: "+w)
	}
	for _, s := range r.Skipped {
		out = append(out, "not done: "+s)
	}
	if len(out) == 0 {
		out = append(out, "nothing to do")
	}
	return out
}

func printApply(r applyResult, err error) {
	for _, l := range applyLines(r) {
		fmt.Println(show(l)) // file names may hold control characters
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "segscan:", err)
	}
}

// ---------- settings: segscan-tui in the git directory ----------

func tuiParamsPath() string {
	p, err := gitOut("rev-parse", "--git-path", "segscan-tui")
	if err != nil {
		return ""
	}
	return p
}

func loadTUIParams() tuiParams {
	p := tuiParams{previewLines: 3}
	data, err := os.ReadFile(tuiParamsPath())
	if err != nil {
		return p
	}
	for _, l := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "paths":
			p.paths = v
		case "bpc":
			p.bpc = v
		case "minlen":
			p.minlen = v
		case "show_allowed":
			p.showAllowed = v == "yes"
		case "preview_lines":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				p.previewLines = n
			}
		}
	}
	return p
}

func saveTUIParams(p tuiParams) {
	path := tuiParamsPath()
	if path == "" {
		return
	}
	yes := "no"
	if p.showAllowed {
		yes = "yes"
	}
	data := fmt.Sprintf("# segscan tui settings\npaths = %s\nbpc = %s\nminlen = %s\nshow_allowed = %s\npreview_lines = %d\n",
		p.paths, p.bpc, p.minlen, yes, p.previewLines)
	atomicWrite(path, []byte(data), 0o644)
}

// splitPaths splits the paths field at white space; "..." and a backslash
// keep a space (or a quote) in a name.
func splitPaths(s string) []string {
	var out []string
	var cur strings.Builder
	in, quoted := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			in = true
		case c == '"':
			quoted, in = !quoted, true
		case (c == ' ' || c == '\t') && !quoted:
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

// quotePaths is the inverse of splitPaths.
func quotePaths(ps []string) string {
	q := make([]string, len(ps))
	for i, p := range ps {
		var b strings.Builder
		for _, c := range []byte(p) {
			if c == ' ' || c == '\t' || c == '"' || c == '\\' {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
		}
		q[i] = b.String()
	}
	return strings.Join(q, " ")
}

package main

import (
	"bytes"
	_ "embed"
	"encoding/gob"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
)

// Model of "ordinary text": character trigrams over the letters of a word
// plus a dictionary of frequent letter fragments (the snngram idea: a word is
// its best segmentation into known parts).

const (
	ctxStart     = 26 // pseudo-symbol "start of word" in a trigram context
	maxWordLen   = 24
	modelVersion = 1

	costDigit    = 3.32 // log2(10)
	costSoft     = 1.0  // _ - . /
	costPunct    = 2.5  // other punctuation
	costOther    = 1.0  // non-ASCII
	costCap      = 8.0  // cap on the cost of a single letter
	penSwitch    = 2.0  // letter<->digit switch
	penCamel     = 1.0  // lower->UPPER switch (camelCase)
	penCase      = 1.5  // UPPER->lower not at a word start
	dictMaxBpc   = 4.5  // a word enters the dictionary only if it is "pronounceable"
	dictMinCnt   = 3
	dictMinFil   = 2
	dictGuardLen = 6
)

const (
	cLetter = iota
	cDigit
	cSoft
	cPunct
	cStruct
	cOther
	cBreak
)

var class [256]uint8

func init() {
	for i := range class {
		class[i] = cOther
	}
	for i := 0; i < 32; i++ {
		class[i] = cBreak
	}
	class[127] = cBreak
	for b := 'a'; b <= 'z'; b++ {
		class[b] = cLetter
		class[b-32] = cLetter
	}
	for b := '0'; b <= '9'; b++ {
		class[b] = cDigit
	}
	for _, b := range []byte("_-./") {
		class[b] = cSoft
	}
	for _, b := range []byte("+!@#$%^&*~?|\\") {
		class[b] = cPunct
	}
	for _, b := range []byte(":=,;()[]{}<>") {
		class[b] = cStruct
	}
	for _, b := range []byte(" \"'`") {
		class[b] = cBreak
	}
}

func isUpper(b byte) bool { return b >= 'A' && b <= 'Z' }

// ann annotates one byte: class, trigram context and boundary penalty.
type ann struct {
	cls    uint8
	c      uint8 // letter index 0..25
	p1, p2 uint8 // context (ctxStart = start of word)
	ws     bool  // the letter starts a word
	pen    float32
}

// annotate annotates a string. Training and scanning share this function so
// that their contexts match.
func annotate(s []byte, out []ann) []ann {
	out = out[:0]
	for i, b := range s {
		a := ann{cls: class[b], p1: ctxStart, p2: ctxStart}
		switch a.cls {
		case cLetter:
			a.c = (b | 0x20) - 'a'
			a.ws = true
			if i > 0 {
				p := &out[i-1]
				switch {
				case p.cls == cDigit:
					a.pen = penSwitch
				case p.cls == cLetter:
					pu, u := isUpper(s[i-1]), isUpper(b)
					if !pu && u {
						a.pen = penCamel // a new camelCase word
					} else {
						a.ws = false
						a.p2, a.p1 = p.p1, p.c
						if pu && !u && !p.ws {
							a.pen = penCase
						}
					}
				}
			}
		case cDigit:
			if i > 0 && out[i-1].cls == cLetter {
				a.pen = penSwitch
			}
		}
		out = append(out, a)
	}
	return out
}

type Model struct {
	Version int
	Tri     [27][27][26]uint32
	Words   map[string]float32 // lower-cased fragment -> cost in bits
	Tokens  uint64
	Files   int

	tri     [27][27][26]float32 // derived: letter cost in bits
	maxWord int
}

// derive computes letter costs: Witten-Bell interpolation trigram->bigram->unigram.
func (m *Model) derive() {
	var uni [26]float64
	var n1 float64
	var bi [27][26]float64
	var nbi, tbi [27]float64
	var ntri, ttri [27][27]float64
	for p2 := 0; p2 < 27; p2++ {
		for p1 := 0; p1 < 27; p1++ {
			for c := 0; c < 26; c++ {
				v := float64(m.Tri[p2][p1][c])
				if v == 0 {
					continue
				}
				uni[c] += v
				n1 += v
				bi[p1][c] += v
				nbi[p1] += v
				ntri[p2][p1] += v
				ttri[p2][p1]++
			}
		}
	}
	for p1 := 0; p1 < 27; p1++ {
		for c := 0; c < 26; c++ {
			if bi[p1][c] > 0 {
				tbi[p1]++
			}
		}
	}
	for p2 := 0; p2 < 27; p2++ {
		for p1 := 0; p1 < 27; p1++ {
			for c := 0; c < 26; c++ {
				p := (uni[c] + 1) / (n1 + 26)
				if nbi[p1] > 0 {
					p = (bi[p1][c] + tbi[p1]*p) / (nbi[p1] + tbi[p1])
				}
				if ntri[p2][p1] > 0 {
					p = (float64(m.Tri[p2][p1][c]) + ttri[p2][p1]*p) / (ntri[p2][p1] + ttri[p2][p1])
				}
				bits := -math.Log2(p)
				if bits > costCap {
					bits = costCap
				}
				m.tri[p2][p1][c] = float32(bits)
			}
		}
	}
	m.maxWord = 0
	for w := range m.Words {
		if len(w) > m.maxWord {
			m.maxWord = len(w)
		}
	}
}

// wordBits is the cost of a fragment under the character model (no dictionary).
func (m *Model) wordBits(w string) float64 {
	p1, p2 := uint8(ctxStart), uint8(ctxStart)
	var sum float64
	for i := 0; i < len(w); i++ {
		c := w[i] - 'a'
		sum += float64(m.tri[p2][p1][c])
		p2, p1 = p1, c
	}
	return sum
}

// Built-in base model (Go sources plus English and French word lists).
// A repository model is mixed with it 50/50; without training it works alone.
//
//go:embed base.model
var baseBlob []byte

var baseModel = func() *Model {
	if len(baseBlob) == 0 {
		return nil
	}
	m := &Model{}
	if err := gob.NewDecoder(bytes.NewReader(baseBlob)).Decode(m); err != nil || m.Version != modelVersion {
		return nil
	}
	m.derive()
	return m
}()

// combine mixes the probabilities of two models equally. Either may be nil.
func combine(a, b *Model) *Model {
	if a == nil || a.Tokens == 0 {
		a, b = b, nil
	}
	if a == nil {
		return nil
	}
	if b == nil || b.Tokens == 0 {
		return a
	}
	mix := func(x, y float64) float32 {
		return float32(-math.Log2(0.5*math.Exp2(-x) + 0.5*math.Exp2(-y)))
	}
	m := &Model{Version: modelVersion, Tokens: a.Tokens, Files: a.Files, Words: make(map[string]float32, len(a.Words)+len(b.Words))}
	for p2 := 0; p2 < 27; p2++ {
		for p1 := 0; p1 < 27; p1++ {
			for c := 0; c < 26; c++ {
				m.tri[p2][p1][c] = mix(float64(a.tri[p2][p1][c]), float64(b.tri[p2][p1][c]))
			}
		}
	}
	for w, x := range a.Words {
		if y, ok := b.Words[w]; ok {
			m.Words[w] = mix(float64(x), float64(y))
		} else {
			m.Words[w] = x + 1
		}
	}
	for w, y := range b.Words {
		if _, ok := a.Words[w]; !ok {
			m.Words[w] = y + 1
		}
	}
	for w := range m.Words {
		if len(w) > m.maxWord {
			m.maxWord = len(w)
		}
	}
	return m
}

func loadModel(path string) (*Model, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeModel(f, path)
}

func decodeModel(r io.Reader, path string) (*Model, error) {
	m := &Model{}
	if err := gob.NewDecoder(r).Decode(m); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if m.Version != modelVersion {
		return nil, fmt.Errorf("%s: model version %d, need %d: retrain it (segscan train)", path, m.Version, modelVersion)
	}
	m.derive()
	return m, nil
}

func (m *Model) save(path string) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(m); err != nil {
		return err
	}
	return atomicWrite(path, buf.Bytes(), 0o644)
}

// ---------- training ----------

type fragStat struct {
	n, files uint32
	last     int32
	list     bool // word from an external list (-words)
}

const listWordBits = 18 // cost of a word known only from a list

type trainer struct {
	skip   int // spans to leave out, as Opts.Skip
	guard  *trainGuardScan
	blank  []byte
	frag   map[string]*fragStat
	tokens uint64
	files  int
	a      []ann
	low    []byte
}

const maxFragLen = 40 // longer letter runs are left out of the statistics

func newTrainer() *trainer { return &trainer{frag: map[string]*fragStat{}} }

func (t *trainer) addFile(data []byte) {
	t.files++
	var pem pemState
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		if skip, _ := pem.feed(line); skip {
			continue
		}
		t.addLine(line)
	}
}

// addWords adds a ready-made word list (one word per line, a-z). With
// -guard a word the built-in model reports is left out too.
func (t *trainer) addWords(data []byte) {
	for _, w := range bytes.Fields(bytes.ToLower(data)) {
		ok := len(w) >= 2 && len(w) <= maxWordLen
		for _, b := range w {
			ok = ok && b >= 'a' && b <= 'z'
		}
		if !ok {
			continue
		}
		if t.guard != nil {
			if t.guard.line(w); len(t.guard.spans) > 0 {
				t.guard.listDropped++
				continue
			}
		}
		st := t.frag[string(w)]
		if st == nil {
			st = &fragStat{last: -1}
			t.frag[string(w)] = st
		}
		st.list = true
	}
}

// trainGuardScan is train -guard: the built-in model scans every line
// first, and a letter fragment inside one of its findings is not counted,
// unless the allowlist has the finding's fp. A key copied into several
// files would otherwise become a dictionary word and stop being reported.
// Other occurrences of the same fragment count as usual.
type trainGuardScan struct {
	sc    *Scanner
	allow *allowList
	spans [][2]int // the findings on the current line

	findings, allowed, dropped int
	listDropped                int // -words entries left out
}

func (g *trainGuardScan) line(s []byte) {
	g.spans = g.spans[:0]
	if bytes.Contains(s, allowMarker) {
		return
	}
	g.sc.Line(s, func(col int, text []byte, _, _ float64) {
		g.findings++
		if g.allow != nil && g.allow.fp[(&Finding{Text: string(text)}).FP()] {
			g.allowed++
			return
		}
		g.spans = append(g.spans, [2]int{col, col + len(text)})
	})
}

// covers reports whether [from, to) overlaps a finding of the line.
func (g *trainGuardScan) covers(from, to int) bool {
	for _, sp := range g.spans {
		if from < sp[1] && sp[0] < to {
			return true
		}
	}
	return false
}

// addLine collects and counts the letter fragments (words) of a line.
func (t *trainer) addLine(s []byte) {
	if t.guard != nil {
		t.guard.line(s)
	}
	s = blankSpans(s, &t.blank, t.skip)
	t.a = annotate(s, t.a)
	fs := -1
	flush := func(end int) {
		if fs < 0 {
			return
		}
		t.tokens++
		if t.guard != nil && t.guard.covers(fs, end) {
			t.guard.dropped++
			fs = -1
			return
		}
		if n := end - fs; n <= maxFragLen {
			t.low = t.low[:0]
			for _, b := range s[fs:end] {
				t.low = append(t.low, b|0x20)
			}
			st := t.frag[string(t.low)]
			if st == nil {
				st = &fragStat{last: -1}
				t.frag[string(t.low)] = st
			}
			st.n++
			if st.last != int32(t.files) {
				st.last = int32(t.files)
				st.files++
			}
		}
		fs = -1
	}
	for i := range t.a {
		a := &t.a[i]
		if a.cls != cLetter {
			flush(i)
			continue
		}
		if a.ws {
			flush(i)
			fs = i
		}
	}
	flush(len(s))
}

// finish builds the model. top > 0 keeps only the most frequent corpus words.
func (t *trainer) finish(top int) *Model {
	m := &Model{Version: modelVersion, Words: map[string]float32{}, Tokens: t.tokens, Files: t.files}
	// The character model is trained on the vocabulary, not on the token
	// stream: each word counts with weight ~log(frequency). Otherwise a few
	// very frequent identifiers drown the statistics of ordinary words.
	for w, st := range t.frag {
		if len(w) > 3 && st.n < 2 && !st.list {
			continue // a long fragment seen once may be a piece of a secret
		}
		wt := uint32(math.Ceil(math.Log2(float64(st.n) + 1)))
		p1, p2 := uint8(ctxStart), uint8(ctxStart)
		for i := 0; i < len(w); i++ {
			c := w[i] - 'a'
			m.Tri[p2][p1][c] += wt
			p2, p1 = p1, c
		}
	}
	m.derive()
	eff := combine(m, baseModel)
	type wc struct {
		w string
		n uint32
	}
	var keep []wc
	for w, st := range t.frag {
		if st.list && (st.n < dictMinCnt || st.files < dictMinFil) {
			if len(w) >= 4 { // short words are useless at this cost
				m.Words[w] = listWordBits
			}
			continue
		}
		if st.list {
			keep = append(keep, wc{w, st.n})
			continue
		}
		if len(w) < 2 || len(w) > maxWordLen || st.n < dictMinCnt || st.files < dictMinFil {
			continue
		}
		// Keep secrets out of the dictionary: a long fragment must be a
		// plausible word under the character model. Short ones are safe anyway:
		// a rare short word is expensive per character.
		if len(w) >= dictGuardLen && eff.wordBits(w)/float64(len(w)) > dictMaxBpc {
			continue
		}
		keep = append(keep, wc{w, st.n})
	}
	if top > 0 && len(keep) > top {
		sort.Slice(keep, func(i, j int) bool { return keep[i].n > keep[j].n })
		keep = keep[:top]
	}
	for _, k := range keep {
		bits := 1.0
		if t.tokens > uint64(k.n) {
			bits = math.Log2(float64(t.tokens) / float64(k.n))
		}
		m.Words[k.w] = float32(bits)
	}
	m.derive()
	return m
}

// ---------- PEM blocks ----------

type pemState struct{ in bool }

// feed reports whether to skip the line and whether it starts a private key.
func (p *pemState) feed(line []byte) (skip, private bool) {
	if p.in {
		// A private key marker counts even inside a block that was never
		// closed, or an unterminated certificate would hide the key after it.
		if i := bytes.Index(line, []byte("-----BEGIN ")); i >= 0 {
			private = bytes.Contains(line[i:], []byte("PRIVATE KEY"))
			p.in = !bytes.Contains(line[i:], []byte("-----END "))
			return true, private
		}
		if bytes.Contains(line, []byte("-----END ")) {
			p.in = false
		}
		return true, false
	}
	if i := bytes.Index(line, []byte("-----BEGIN ")); i >= 0 {
		private = bytes.Contains(line[i:], []byte("PRIVATE KEY"))
		if !bytes.Contains(line[i:], []byte("-----END ")) {
			p.in = true
		}
		return true, private
	}
	return false, false
}

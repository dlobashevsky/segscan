package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

type Opts struct {
	Tau       float64 // bits per char above which a char counts as "random"
	MinExcess float64 // minimum sum of excesses over a segment, bits
	MinLen    int
	MinDist   int     // minimum number of distinct chars in a segment
	KwFactor  float64 // MinExcess multiplier when a word like password/token/key precedes on the line
	MinBpc    float64 // report only segments with at least this average cost per char
}

var defaultOpts = Opts{Tau: 3.0, MinExcess: 14, MinLen: 6, MinDist: 5, KwFactor: 0.5}

// Words after which a secret is expected on the line. They find nothing by
// themselves; they only lower the threshold for what already looks random.
var keywords = [][]byte{
	[]byte("pass"), []byte("pwd"), []byte("secret"), []byte("token"), []byte("key"), []byte("auth"),
	[]byte("cred"), []byte("bearer"), []byte("salt"), []byte("signature"), []byte("private"),
}

type Finding struct {
	Commit string
	File   string
	Line   int
	Col    int
	Text   string
	Bits   float64 // average cost per char
	Excess float64
	Kind   string // kindEntropy or kindPEM
	Label  string // what to print instead of Text (private key marker)
	Count  int
}

const (
	kindEntropy = "entropy"
	kindPEM     = "private_key"
)

func (f *Finding) FP() string {
	h := sha256.Sum256([]byte(f.Text))
	return hex.EncodeToString(h[:6])
}

type Scanner struct {
	m *Model
	o Opts

	a    []ann
	cost []float32 // char cost without the dictionary
	best []float32
	from []int32
	attr []float32 // char cost after segmentation
	low  []byte
	up   []int32
	run  []int32
	lc   []byte
	kwAt int // position right after the first keyword on the line, or -1

	explain func(piece []byte, bits float32, word bool) // debug output of the segmentation
}

func NewScanner(m *Model, o Opts) *Scanner { return &Scanner{m: m, o: o} }

// Line finds suspicious segments in a line. emit gets the offset and the segment.
func (s *Scanner) Line(line []byte, emit func(col int, text []byte, bits, excess float64)) {
	s.kwAt = -1
	if s.o.KwFactor < 1 && len(line) >= s.o.MinLen {
		s.lc = append(s.lc[:0], line...)
		for k, b := range s.lc {
			if isUpper(b) {
				s.lc[k] = b | 0x20
			}
		}
		for _, kw := range keywords {
			if at := bytes.Index(s.lc, kw); at >= 0 && (s.kwAt < 0 || at+len(kw) < s.kwAt) {
				s.kwAt = at + len(kw)
			}
		}
	}
	i := 0
	for i < len(line) {
		for i < len(line) && class[line[i]] == cBreak {
			i++
		}
		j := i
		for j < len(line) && class[line[j]] != cBreak {
			j++
		}
		if j-i >= s.o.MinLen {
			s.chunk(line[i:j], i, emit)
		}
		i = j
	}
}

func (s *Scanner) chunk(c []byte, off int, emit func(int, []byte, float64, float64)) {
	n := len(c)
	s.a = annotate(c, s.a)
	s.cost = grow(s.cost, n)
	s.attr = grow(s.attr, n)
	s.best = grow(s.best, n+1)
	s.from = growI(s.from, n+1)
	s.up = growI(s.up, n+1)
	s.run = growI(s.run, n+1)
	if cap(s.low) < n {
		s.low = make([]byte, n*2)
	}
	s.low = s.low[:n]

	s.up[0], s.run[0] = 0, 0
	for i := range s.a {
		a := &s.a[i]
		var v float32
		s.low[i] = c[i]
		s.up[i+1] = s.up[i]
		s.run[i+1] = 0
		switch a.cls {
		case cLetter:
			v = s.m.tri[a.p2][a.p1][a.c] + a.pen
			s.low[i] = c[i] | 0x20
			if isUpper(c[i]) {
				s.up[i+1]++
			}
			s.run[i+1] = s.run[i] + 1
		case cDigit:
			v = costDigit + a.pen
		case cSoft:
			v = costSoft
		case cPunct:
			v = costPunct
		case cOther:
			v = costOther
		}
		s.cost[i] = v
	}

	// Numeric literals 0x... up to 64 bits (with U/L suffixes) are not secrets.
	for i := 0; i+2 < n; i++ {
		if c[i] != '0' || c[i+1]|0x20 != 'x' || (i > 0 && s.a[i-1].cls <= cDigit) {
			continue
		}
		j := i + 2
		for j < n && isHex(c[j]) {
			j++
		}
		h := j - i - 2
		for j < n && (c[j]|0x20 == 'u' || c[j]|0x20 == 'l') {
			j++
		}
		if h >= 1 && h <= 16 && (j == n || s.a[j].cls > cDigit) {
			for k := i; k < j; k++ {
				s.cost[k] = 0
			}
			i = j - 1
		}
	}

	// DP: best[i] is the minimum cost of the prefix of length i. Options:
	// a single char, or a dictionary word ending at i.
	s.best[0] = 0
	words := s.m.Words
	for i := 1; i <= n; i++ {
		b := s.best[i-1] + s.cost[i-1]
		f := int32(i - 1)
		maxL := int(s.run[i])
		if maxL > s.m.maxWord {
			maxL = s.m.maxWord
		}
		for l := 2; l <= maxL; l++ {
			j := i - l
			// a word must be in one case pattern: lower, UPPER or Capitalized
			u := int(s.up[i] - s.up[j])
			if u != 0 && u != l && !(u == 1 && isUpper(c[j])) {
				continue
			}
			w, ok := words[string(s.low[j:i])]
			if !ok {
				continue
			}
			if v := s.best[j] + w + s.a[j].pen; v < b {
				b, f = v, int32(j)
			}
		}
		s.best[i], s.from[i] = b, f
	}
	var pieces [][2]int
	for i := n; i > 0; {
		j := int(s.from[i])
		v := (s.best[i] - s.best[j]) / float32(i-j)
		for k := j; k < i; k++ {
			s.attr[k] = v
		}
		if s.explain != nil {
			pieces = append(pieces, [2]int{j, i})
		}
		i = j
	}
	for k := len(pieces) - 1; k >= 0; k-- {
		j, i := pieces[k][0], pieces[k][1]
		s.explain(c[j:i], s.best[i]-s.best[j], i-j > 1)
	}
	s.segs(c, 0, n, off, emit)
}

// segs: the segment with the maximum sum of (cost - tau), then recurse left and right.
func (s *Scanner) segs(c []byte, lo, hi, off int, emit func(int, []byte, float64, float64)) {
	for hi-lo >= s.o.MinLen {
		tau := float32(s.o.Tau)
		var cur, bestSum float32
		cs, bs, be := lo, lo, lo
		for k := lo; k < hi; k++ {
			v := s.attr[k] - tau
			if cur <= 0 {
				cur, cs = v, k
			} else {
				cur += v
			}
			if cur > bestSum {
				bestSum, bs, be = cur, cs, k+1
			}
		}
		need := s.o.MinExcess
		if s.kwAt >= 0 {
			need *= s.o.KwFactor
		}
		if float64(bestSum) < need {
			return
		}
		s.segs(c, lo, bs, off, emit)
		if off+bs < s.kwAt || s.kwAt < 0 {
			need = s.o.MinExcess
		}
		if float64(bestSum) >= need && be-bs >= s.o.MinLen && distinct(c[bs:be]) >= s.o.MinDist {
			var sum float32
			for k := bs; k < be; k++ {
				sum += s.attr[k]
			}
			if avg := float64(sum) / float64(be-bs); avg >= s.o.MinBpc {
				emit(off+bs, c[bs:be], avg, float64(bestSum))
			}
		}
		lo = be
	}
}

func isHex(b byte) bool {
	return b >= '0' && b <= '9' || b|0x20 >= 'a' && b|0x20 <= 'f'
}

func distinct(b []byte) int {
	var seen [256]bool
	n := 0
	for _, x := range b {
		if !seen[x] {
			seen[x] = true
			n++
		}
	}
	return n
}

func grow(s []float32, n int) []float32 {
	if cap(s) < n {
		return make([]float32, n, n*2)
	}
	return s[:n]
}

func growI(s []int32, n int) []int32 {
	if cap(s) < n {
		return make([]int32, n, n*2)
	}
	return s[:n]
}

// ---------- scanning a file line by line ----------

type fileScan struct {
	sc    *Scanner
	allow *allowList
	pem   pemState
	out   func(Finding)
}

var allowMarker = []byte("segscan:allow")

func (fs *fileScan) line(commit, file string, no int, line []byte) {
	line = bytes.TrimRight(line, "\r")
	skip, private := fs.pem.feed(line)
	if private {
		f := Finding{Commit: commit, File: file, Line: no, Col: 1, Text: string(line), Kind: kindPEM, Label: pemLabel(line)}
		if !fs.allow.fp[f.FP()] {
			fs.out(f)
		}
	}
	if skip || bytes.Contains(line, allowMarker) {
		return
	}
	fs.sc.Line(line, func(col int, text []byte, bits, excess float64) {
		f := Finding{Commit: commit, File: file, Line: no, Col: col + 1, Text: string(text), Bits: bits, Excess: excess, Kind: kindEntropy}
		if !fs.allow.fp[f.FP()] {
			fs.out(f)
		}
	})
}

// pemLabel extracts the "-----BEGIN ... PRIVATE KEY-----" marker from a line.
func pemLabel(line []byte) string {
	i := bytes.Index(line, []byte("-----BEGIN "))
	if i < 0 {
		return "PRIVATE KEY"
	}
	rest := line[i+11:]
	if j := bytes.Index(rest, []byte("-----")); j >= 0 {
		return string(line[i : i+11+j+5])
	}
	return string(line[i:])
}

func (fs *fileScan) data(file string, data []byte) {
	fs.pem = pemState{}
	no := 0
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		no++
		fs.line("", file, no, line)
	}
}

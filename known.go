package main

// Check 6, known values (DESIGN.md 6.5, 8): every strong form of every
// current and retired key value and of every secret-file pattern, searched
// in the raw bytes of every file, in UTF-16 too, and inside gzip and ZIP.

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

const ckKnown = "known_value"

type kvSource struct {
	What string // "key ch_pass", "retired value of ch_pass", "secret file htpasswd", ...
}

type kvHit struct {
	src   int
	chain string
	part  string // for secret files: "content", "a line", "a value"
	enc   string // "", "UTF-16LE", "UTF-16BE"
}

type kvMatcher struct {
	srcs  []kvSource
	pats  [][]byte
	hits  [][]kvHit // per pattern
	first map[uint64][]int
	byPat map[string]int
}

func newMatcher() *kvMatcher {
	return &kvMatcher{first: map[uint64][]int{}, byPat: map[string]int{}}
}

func (m *kvMatcher) source(what string) int {
	m.srcs = append(m.srcs, kvSource{what})
	return len(m.srcs) - 1
}

func (m *kvMatcher) addPattern(p []byte, h kvHit) {
	if len(p) < 8 {
		return // strong forms only, and they are at least 8 bytes
	}
	i, ok := m.byPat[string(p)]
	if !ok {
		i = len(m.pats)
		m.byPat[string(p)] = i
		m.pats = append(m.pats, p)
		m.hits = append(m.hits, nil)
		k := binary.LittleEndian.Uint64(p)
		m.first[k] = append(m.first[k], i)
	}
	for _, x := range m.hits[i] {
		if x.src == h.src {
			return // one source is reported once per place
		}
	}
	m.hits[i] = append(m.hits[i], h)
}

// addValue adds the strong forms of v, and their UTF-16 encodings.
func (m *kvMatcher) addValue(src int, v []byte, part string, chains [][]string) {
	for _, f := range formsOf(v, chains) {
		if f.Weak {
			continue
		}
		m.addPattern(f.Data, kvHit{src: src, chain: f.Chain, part: part})
		if ascii(f.Data) {
			m.addPattern(utf16(f.Data, false), kvHit{src: src, chain: f.Chain, part: part, enc: "UTF-16LE"})
			m.addPattern(utf16(f.Data, true), kvHit{src: src, chain: f.Chain, part: part, enc: "UTF-16BE"})
		}
	}
}

func ascii(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

func utf16(b []byte, be bool) []byte {
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		if be {
			out = append(out, 0, c)
		} else {
			out = append(out, c, 0)
		}
	}
	return out
}

// secretPatterns: the whole content, each line trimmed of spaces, and the
// value of each name=value line as written and without one pair of quotes.
// Empty patterns are dropped before any transform.
func secretPatterns(data []byte) (whole []byte, lines, values [][]byte) {
	seen := map[string]bool{}
	add := func(to *[][]byte, p []byte) {
		if len(p) > 0 && !seen[string(p)] {
			seen[string(p)] = true
			*to = append(*to, p)
		}
	}
	if len(bytes.TrimSpace(data)) > 0 {
		whole = data
	}
	for _, l := range bytes.Split(data, []byte("\n")) {
		l = bytes.Trim(l, " \t")
		add(&lines, l)
		if i := bytes.IndexByte(l, '='); i > 0 {
			v := l[i+1:]
			add(&values, v)
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				add(&values, v[1:len(v)-1])
			}
		}
	}
	return
}

// buildMatcher collects the patterns of check 6 from the keystore.
func buildMatcher(ks *keystore, extra map[string]bool) *kvMatcher {
	chains := searchChains(extra)
	m := newMatcher()
	for _, name := range sortedKeys(ks.keys) {
		k := ks.keys[name]
		m.addValue(m.source("value of key "+k.Name), []byte(k.Value), "", chains)
	}
	for _, r := range ks.retired {
		m.addValue(m.source("retired value of key "+r.Name), []byte(r.Value), "", chains)
	}
	for _, f := range ks.files {
		what := "secret file " + f.Name
		if f.Version != "" {
			what = "retired secret file " + f.Version
		}
		src := m.source(what)
		whole, lines, values := secretPatterns(f.Data)
		if whole != nil {
			m.addValue(src, whole, "content", chains)
		}
		for _, l := range lines {
			m.addValue(src, l, "a line", chains)
		}
		for _, v := range values {
			m.addValue(src, v, "a value", chains)
		}
	}
	return m
}

func sortedKeys[V any](mp map[string]V) []string {
	var out []string
	for k := range mp {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type kvFound struct {
	off  int
	hit  kvHit
	from string // the archive member it was found in, "" for the file itself
}

// search returns every place where a pattern starts in data.
func (m *kvMatcher) search(data []byte, from string, out []kvFound) []kvFound {
	if len(m.pats) == 0 {
		return out
	}
	for i := 0; i+8 <= len(data); i++ {
		ids, ok := m.first[binary.LittleEndian.Uint64(data[i:])]
		if !ok {
			continue
		}
		for _, id := range ids {
			if bytes.HasPrefix(data[i:], m.pats[id]) {
				for _, h := range m.hits[id] {
					out = append(out, kvFound{off: i, hit: h, from: from})
				}
			}
		}
	}
	return out
}

// isTextFile: valid UTF-8 without NUL anywhere (8). Anything else is binary
// for check 6.
func isTextFile(data []byte) bool {
	return bytes.IndexByte(data, 0) < 0 && utf8.Valid(data)
}

const unpackLimit = 64 << 20

// scanBinary searches data and what its gzip members or ZIP archive hold.
// It returns why the file is not fully scanned, or "".
func (m *kvMatcher) scanBinary(data []byte, from string, depth int, out *[]kvFound) string {
	*out = m.search(data, from, *out)
	if depth > 2 {
		return "nested archives more than two levels deep"
	}
	member := func(name string, content []byte) string {
		if isTextFile(content) {
			*out = m.search(content, name, *out)
			return ""
		}
		return m.scanBinary(content, name, depth+1, out)
	}
	if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
		total := 0
		for _, f := range zr.File {
			if strings.HasSuffix(f.Name, "/") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return "cannot unpack " + f.Name + ": " + err.Error()
			}
			b, err := io.ReadAll(io.LimitReader(rc, int64(unpackLimit-total+1)))
			rc.Close()
			if err != nil {
				return "cannot unpack " + f.Name + ": " + err.Error()
			}
			if total += len(b); total > unpackLimit {
				return "unpacks to more than 64 MiB"
			}
			if why := member(joinMember(from, f.Name), b); why != "" {
				return why
			}
		}
		return ""
	}
	// gzip members, wherever the first one starts: a text prefix (a
	// self-extracting script) followed by gzip to the end of the file.
	at := bytes.Index(data, []byte{0x1f, 0x8b, 0x08})
	if at < 0 || !isTextFile(data[:at]) {
		return "binary format segscan does not unpack"
	}
	zr, err := gzip.NewReader(bytes.NewReader(data[at:]))
	if err != nil {
		return "cannot unpack gzip: " + err.Error()
	}
	b, err := io.ReadAll(io.LimitReader(zr, unpackLimit+1))
	if err != nil {
		return "cannot unpack gzip: " + err.Error()
	}
	if len(b) > unpackLimit {
		return "unpacks to more than 64 MiB"
	}
	return member(joinMember(from, fmt.Sprintf("gzip@%d", at)), b)
}

func joinMember(from, name string) string {
	if from == "" {
		return name
	}
	return from + "/" + name
}

// knownFindings runs check 6 on one file. For a binary file it also says
// why it could not be read completely; whether that is allowed depends on
// the snapshot's .sec/allow.
func (m *kvMatcher) knownFindings(p string, data []byte) (out []checkFinding, notFully string) {
	var found []kvFound
	text := isTextFile(data)
	if text {
		found = m.search(data, "", nil)
	} else if why := m.scanBinary(data, "", 1, &found); why != "" && !isModelFile(p, data) {
		notFully = why
	}
	seen := map[string]bool{}
	for _, f := range found {
		line, col := 0, f.off+1
		if text {
			line = bytes.Count(data[:f.off], []byte("\n")) + 1
			col = f.off - bytes.LastIndexByte(data[:f.off], '\n')
		}
		msg := m.srcs[f.hit.src].What
		if f.hit.part != "" {
			msg = f.hit.part + " of " + msg
		}
		if f.hit.chain != "" {
			msg += " (form " + f.hit.chain + ")"
		}
		if f.hit.enc != "" {
			msg += " in " + f.hit.enc
		}
		if f.from != "" {
			msg += " inside " + f.from
			line, col = 0, 0
		}
		k := fmt.Sprintf("%d\x00%d\x00%s", line, col, msg)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, checkFinding{Line: line, Col: col, Check: ckKnown, Msg: msg})
	}
	return out, notFully
}

// isModelFile: a statistical model (.sec/segscan.model) is gob, which stores its
// strings as they are, so the raw search above covers it.
func isModelFile(p string, data []byte) bool {
	_, err := decodeModel(bytes.NewReader(data), p)
	return err == nil
}

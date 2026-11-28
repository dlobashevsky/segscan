package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// ctxOpts says how much of the source line goes into the prompt.
type ctxOpts struct {
	K       int // each side gets K × finding length...
	MinSide int // ...but at least this many bytes...
	MaxSide int // ...and at most this many
	MaxLine int // a line up to this many bytes goes in whole
	MaxFind int // a longer finding is shown as head…tail
}

// excerpt is what the model sees of one finding.
type excerpt struct {
	Before, Cand, After string
	CutLeft, CutRight   bool
	NoSource            bool // the source line was not found; Cand is segscan's text only
}

// window cuts the context around line[start:end].
func window(line []byte, start, end int, o ctxOpts) excerpt {
	var e excerpt
	lo, hi := 0, len(line)
	if len(line) > o.MaxLine {
		pad := o.K * (end - start)
		pad = max(pad, o.MinSide)
		pad = min(pad, o.MaxSide)
		if start-pad > 0 {
			lo = runeStart(line, start-pad)
		}
		if end+pad < len(line) {
			hi = runeStart(line, end+pad)
		}
	}
	e.CutLeft, e.CutRight = lo > 0, hi < len(line)
	e.Before = escape(line[lo:start])
	e.Cand = shorten(line[start:end], o.MaxFind)
	e.After = escape(line[end:hi])
	return e
}

// shorten keeps a long finding's head and tail: a 100 KB base64 image is
// recognisable from its first and last few dozen chars.
func shorten(s []byte, maxLen int) string {
	if len(s) <= maxLen || maxLen < 12 {
		return escape(s)
	}
	h := runeStart(s, maxLen*2/3)
	t := runeStart(s, len(s)-maxLen/3)
	return fmt.Sprintf("%s…[%d bytes omitted]…%s", escape(s[:h]), t-h, escape(s[t:]))
}

// runeStart moves i back to the start of the UTF-8 sequence it falls into.
func runeStart(b []byte, i int) int {
	for k := 0; k < utf8.UTFMax && i > 0 && i < len(b) && !utf8.RuneStart(b[i]); k++ {
		i--
	}
	return i
}

// escape keeps printable text (any script) and writes control bytes and
// invalid UTF-8 as \t, \xNN, the way segscan prints them.
func escape(b []byte) string {
	var sb strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		switch {
		case r == '\t':
			sb.WriteString(`\t`)
		case r == utf8.RuneError && n == 1, r < 0x20, r == 0x7f:
			fmt.Fprintf(&sb, `\x%02x`, b[0])
		default:
			sb.Write(b[:n])
		}
		b = b[n:]
	}
	return sb.String()
}

// sources reads source lines: from the working tree, or from a commit when
// the finding came from `segscan diff`.
type sources struct {
	dir   string
	files map[string][][]byte
}

func newSources(dir string) *sources {
	return &sources{dir: dir, files: map[string][][]byte{}}
}

func (s *sources) line(commit, file string, no int) ([]byte, error) {
	key := commit + "\x00" + file
	lines, ok := s.files[key]
	if !ok {
		data, err := s.read(commit, file)
		if err != nil {
			s.files[key] = nil
			return nil, err
		}
		lines = bytes.Split(data, []byte("\n"))
		s.files[key] = lines
	}
	if lines == nil {
		return nil, fmt.Errorf("%s: not readable", file)
	}
	if no < 1 || no > len(lines) {
		return nil, fmt.Errorf("%s: no line %d", file, no)
	}
	return bytes.TrimRight(lines[no-1], "\r"), nil
}

func (s *sources) read(commit, file string) ([]byte, error) {
	if file == "<stdin>" {
		return nil, fmt.Errorf("finding from stdin")
	}
	if commit == "" {
		return os.ReadFile(filepath.Join(s.dir, file))
	}
	out, err := exec.Command("git", "-C", s.dir, "show", commit+":"+file).Output()
	if err != nil {
		return nil, fmt.Errorf("git show %s:%s: %v", commit, file, err)
	}
	return out, nil
}

// locate finds the finding in its source line and cuts the excerpt. If the
// line does not hold the text (the file changed since the scan), it falls
// back to segscan's own text, without context.
func locate(src *sources, f *finding, o ctxOpts) (excerpt, error) {
	line, err := src.line(f.Commit, f.File, f.Line)
	if err == nil {
		start := f.Col - 1
		end := start + f.Length
		if start >= 0 && end <= len(line) && f.matches(line[start:end]) {
			return window(line, start, end, o), nil
		}
		if !f.Truncated && f.Text != "" {
			if i := bytes.Index(line, []byte(f.Text)); i >= 0 {
				return window(line, i, i+len(f.Text), o), nil
			}
		}
		err = fmt.Errorf("%s:%d: the line does not hold the finding (file changed?)", f.File, f.Line)
	}
	if f.Truncated || f.Text == "" {
		return excerpt{}, fmt.Errorf("%v; run segscan with -show to review without the source", err)
	}
	return excerpt{Cand: shorten([]byte(f.Text), o.MaxFind), NoSource: true}, nil
}

// matches compares a source segment with segscan's text (which is cut to
// -preview chars unless -show, and has invalid UTF-8 replaced).
func (f *finding) matches(seg []byte) bool {
	s := strings.ToValidUTF8(string(seg), "�")
	if f.Truncated {
		// The preview is cut at a byte, which may split the last rune.
		return strings.HasPrefix(s, strings.TrimRight(f.Text, "�"))
	}
	return s == f.Text
}

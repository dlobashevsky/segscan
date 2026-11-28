package main

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// The M action puts "segscan:allow" into a comment at the end of a line.
// It must never change data: a marker inside a string, a YAML block scalar
// or a heredoc becomes part of the value. So it is offered only for file
// types whose comment syntax is known, and only where a simple scan of the
// file shows the end of the line to be outside any string. In doubt, no.

type commentStyle struct {
	start, end string // "#", "" or "<!--", "-->"
	quotes     string // quote characters of the language
	// multi-line constructs: if one opens before the line and may still be
	// open, the marker is refused
	blockOpen []string
	// rawOpen: the same for constructs that need a pattern (a raw string
	// prefix must start a token: r"..." yes, "user" no)
	rawOpen   []*regexp.Regexp
	spanLines bool // quoted strings may continue on the next line (shell, SQL)
	escSingle bool // a backslash may escape inside single quotes too (SQL E'...')
	yaml      bool // YAML: quotes only open a scalar; block and multi-line scalars
	xml       bool
}

var (
	styleNginx = commentStyle{start: "#", quotes: `"'`, spanLines: true}
	// bash/zsh $'...' escapes \' and may span lines: read single quotes both ways
	styleShell = commentStyle{start: "#", quotes: `"'`, blockOpen: []string{"<<"}, spanLines: true, escSingle: true}
	stylePy    = commentStyle{start: "#", quotes: `"'`, blockOpen: []string{`"""`, `'''`}}
	styleTOML  = commentStyle{start: "#", quotes: `"'`, blockOpen: []string{`"""`, `'''`}}
	styleYAML  = commentStyle{start: "#", quotes: `"'`, yaml: true}
	// C-like languages, each with its multi-line strings: Go and JS raw
	// and template strings, C++ R"(...)", Rust r#"..."#, the """ text
	// blocks of Java, Kotlin, Scala, Swift and C# 11, C# @"...".
	styleGo = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*", "`"}}
	styleJS = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*", "`"}}
	styleC  = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*"}, rawOpen: []*regexp.Regexp{regexp.MustCompile(`(^|[^A-Za-z0-9_])(u8|[uUL])?R"`)}}
	// Rust: ordinary strings may span lines too
	styleRust = commentStyle{start: "//", quotes: "\"", blockOpen: []string{"/*"}, spanLines: true, rawOpen: []*regexp.Regexp{regexp.MustCompile(`(^|[^A-Za-z0-9_])[bc]?r#*"`)}}
	styleJVM  = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*", `"""`, `#"`}}
	styleCS   = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*", `"""`}, rawOpen: []*regexp.Regexp{regexp.MustCompile(`@\$*"|\$+@"`)}}
	// PostgreSQL dollar quotes: $$...$$ and $tag$...$tag$
	styleSQL = commentStyle{start: "--", quotes: "'\"`", blockOpen: []string{"/*"}, spanLines: true, escSingle: true,
		rawOpen: []*regexp.Regexp{regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)?\$`)}}
	styleLua = commentStyle{start: "--", quotes: `'"`, blockOpen: []string{"[[", "[="}}
	styleXML = commentStyle{start: "<!--", end: "-->", xml: true}
)

// styleFor returns the comment style of a repository path, false for a type
// the marker is not offered for (JSON, INI, .env, Dockerfile, unknown...).
func styleFor(p string) (commentStyle, bool) {
	base := path.Base(p)
	switch strings.ToLower(path.Ext(base)) {
	case ".sh", ".bash", ".zsh":
		return styleShell, true
	case ".py":
		return stylePy, true
	case ".yaml", ".yml":
		return styleYAML, true
	case ".toml":
		return styleTOML, true
	case ".go":
		return styleGo, true
	case ".js", ".mjs", ".ts":
		return styleJS, true
	case ".c", ".h", ".cc", ".cpp", ".hpp":
		return styleC, true
	case ".rs":
		return styleRust, true
	case ".java", ".kt", ".scala", ".swift":
		return styleJVM, true
	case ".cs":
		return styleCS, true
	case ".sql":
		return styleSQL, true
	case ".lua":
		return styleLua, true
	case ".xml", ".html", ".htm":
		return styleXML, true
	case ".conf":
		// nginx allows a comment after any directive; other .conf formats
		// are anybody's guess.
		if base == "nginx.conf" || strings.Contains("/"+path.Dir(p)+"/", "/nginx/") {
			return styleNginx, true
		}
	}
	return commentStyle{}, false
}

// directiveRE: comments that tools read (linters, editors, encodings, build
// constraints). A marker appended to one would become part of it.
var directiveRE = regexp.MustCompile(`(?i)(shellcheck|yamllint|noqa|pylint|flake8|mypy|type:\s*ignore|eslint|prettier|nolint|go:|\+build|rubocop|isort|fmt:|vim?:|-\*-|coding[:=]|ex:|kate:)`)

// markLine returns the file with the marker added to line no (1-based), or
// why it cannot be done.
func markLine(repoPath string, data []byte, no int) ([]byte, error) {
	st, ok := styleFor(repoPath)
	if !ok {
		return nil, fmt.Errorf("%s: no safe comment syntax known for this file type", repoPath)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if no < 1 || no > len(lines) || (no == len(lines) && len(lines[no-1]) == 0) {
		return nil, fmt.Errorf("%s: no line %d", repoPath, no)
	}
	raw := lines[no-1]
	body := bytes.TrimRight(raw, "\r\n")
	eol := raw[len(body):]
	if bytes.Contains(body, allowMarker) {
		return data, nil // already marked
	}
	if no == 1 && bytes.HasPrefix(body, []byte("#!")) {
		return nil, fmt.Errorf("%s:1: a #! line: added text would become an argument of the interpreter", repoPath)
	}
	if why := unsafeLine(st, lines, no-1); why != "" {
		return nil, fmt.Errorf("%s:%d: %s", repoPath, no, why)
	}
	if st.end == "" && hasLineComment(st, body) && directiveRE.Match(body) {
		return nil, fmt.Errorf("%s:%d: the comment on the line is read by a tool; text added to it could change what it says", repoPath, no)
	}
	var add string
	if st.end == "" && hasLineComment(st, body) {
		add = " segscan:allow" // already inside a comment at the end
	} else if st.end != "" {
		add = " " + st.start + " segscan:allow " + st.end
	} else {
		add = " " + st.start + " segscan:allow"
	}
	var out bytes.Buffer
	for i, l := range lines {
		if i == no-1 {
			out.Write(body)
			out.WriteString(add)
			out.Write(eol)
			continue
		}
		out.Write(l)
	}
	return out.Bytes(), nil
}

// unsafeLine says why the end of line i may not be outside strings, or "".
func unsafeLine(st commentStyle, lines [][]byte, i int) string {
	body := bytes.TrimRight(lines[i], "\r\n")
	if len(bytes.TrimSpace(body)) == 0 {
		return "an empty line"
	}
	if bytes.HasSuffix(bytes.TrimRight(body, " \t"), []byte(`\`)) {
		return "the line continues on the next one"
	}
	if i > 0 && bytes.HasSuffix(bytes.TrimRight(bytes.TrimRight(lines[i-1], "\r\n"), " \t"), []byte(`\`)) {
		return "the line continues the previous one"
	}
	// Multi-line constructs anywhere before or on the line: refuse rather
	// than track whether they are closed.
	for _, open := range st.blockOpen {
		for k := 0; k <= i; k++ {
			if bytes.Contains(lines[k], []byte(open)) {
				return fmt.Sprintf("a multi-line construct (%s) at or before the line", open)
			}
		}
	}
	for _, re := range st.rawOpen {
		for k := 0; k <= i; k++ {
			if re.Match(lines[k]) {
				return "a raw or multi-line string at or before the line"
			}
		}
	}
	switch {
	case st.yaml:
		return yamlUnsafe(lines, i)
	case st.xml:
		return xmlUnsafe(lines, i)
	}
	// Where strings may span lines, every line from the top must close its
	// own quotes, whether a backslash escapes (E'...' in PostgreSQL, shell
	// double quotes) or not: a string left open anywhere above, or a line
	// that reads two ways, and the marker is refused. Elsewhere a string
	// ends with its line, and only the line itself counts.
	from := i
	if st.spanLines {
		from = 0
	}
	for k := from; k <= i; k++ {
		l := bytes.TrimRight(lines[k], "\r\n")
		if scanQuotes(st, l, true) != 0 || scanQuotes(st, l, false) != 0 {
			if k == i {
				return "the end of the line may be inside a string"
			}
			return fmt.Sprintf("a string may run on from line %d", k+1)
		}
	}
	return ""
}

// scanQuotes runs the quote state over one line and returns the quote
// still open at its end (0: none). With esc a backslash escapes the next
// character inside double quotes, and inside single quotes too where the
// language has such strings (SQL E'...'); without, it is an ordinary one.
// A line comment outside quotes ends the line.
func scanQuotes(st commentStyle, body []byte, esc bool) byte {
	var q byte
	for k := 0; k < len(body); k++ {
		c := body[k]
		switch {
		case q != 0:
			if c == '\\' && esc && (q != '\'' || st.escSingle) {
				k++
			} else if c == q {
				q = 0
			}
		case strings.IndexByte(st.quotes, c) >= 0:
			q = c
		case st.commentAt(body, k):
			return 0
		}
	}
	return q
}

// commentAt reports a line comment starting at body[k]. "#" starts one
// only at a word start (shell, YAML: a#b is a word); "//" and "--" anywhere.
func (st commentStyle) commentAt(body []byte, k int) bool {
	if !bytes.HasPrefix(body[k:], []byte(st.start)) {
		return false
	}
	return st.start != "#" || k == 0 || body[k-1] == ' ' || body[k-1] == '\t'
}

// hasLineComment reports whether the line already ends in a line comment.
func hasLineComment(st commentStyle, body []byte) bool {
	var q byte
	for k := 0; k < len(body); k++ {
		c := body[k]
		switch {
		case q != 0:
			if c == '\\' && q != '\'' {
				k++
			} else if c == q {
				q = 0
			}
		case strings.IndexByte(st.quotes, c) >= 0:
			q = c
		case st.commentAt(body, k):
			return true
		}
	}
	return false
}

func indentOf(l []byte) int { return len(l) - len(bytes.TrimLeft(l, " ")) }

// yamlUnsafe: a marker after a YAML value is a comment only on a line of
// the form "key: value", "key:", "- value" whose value, if quoted, closes
// on the line, outside block scalars and multi-line plain scalars.
func yamlUnsafe(lines [][]byte, i int) string {
	if why := yamlBlockScalar(lines, i); why != "" {
		return why
	}
	body := bytes.TrimRight(lines[i], "\r\n")
	t := bytes.TrimSpace(body)
	if t[0] == '#' {
		return "" // a comment line
	}
	val := t
	for bytes.HasPrefix(val, []byte("- ")) {
		val = bytes.TrimSpace(val[2:])
	}
	if k := yamlKeyEnd(val); k >= 0 {
		val = bytes.TrimSpace(val[k:])
	} else if len(val) == len(t) {
		return "the line is not a YAML key or list item (a multi-line scalar?)"
	}
	if len(val) > 0 && (val[0] == '"' || val[0] == '\'') {
		if !yamlQuotedCloses(val) {
			return "the line ends inside a quoted YAML scalar"
		}
	}
	// A value followed by a more indented line is a multi-line plain
	// scalar, where a comment is not allowed.
	if len(val) > 0 && val[0] != '#' {
		for k := i + 1; k < len(lines); k++ {
			l := bytes.TrimRight(lines[k], "\r\n")
			if n := bytes.TrimSpace(l); len(n) == 0 || n[0] == '#' {
				continue
			}
			if indentOf(l) > indentOf(body) {
				return "the value continues on the next line"
			}
			break
		}
	}
	return ""
}

// yamlKeyEnd returns the offset after "key:" at the start of t, or -1.
func yamlKeyEnd(t []byte) int {
	if len(t) == 0 || t[0] == '"' || t[0] == '\'' {
		return -1 // a quoted key: rare, refuse
	}
	for k := 0; k < len(t); k++ {
		if t[k] == ':' && (k+1 == len(t) || t[k+1] == ' ') {
			return k + 1
		}
		if t[k] == ' ' && k+1 < len(t) && t[k+1] == '#' {
			return -1
		}
	}
	return -1
}

// yamlQuotedCloses reports whether a quoted scalar at the start of v closes
// on the line (” escapes a single quote, \ escapes in double quotes).
func yamlQuotedCloses(v []byte) bool {
	q := v[0]
	for k := 1; k < len(v); k++ {
		switch {
		case q == '"' && v[k] == '\\':
			k++
		case v[k] == q && q == '\'' && k+1 < len(v) && v[k+1] == '\'':
			k++
		case v[k] == q:
			return true
		}
	}
	return false
}

// yamlBlockScalar reports a line inside a block scalar (key: | or key: >),
// found through the nearest less indented line above.
func yamlBlockScalar(lines [][]byte, i int) string {
	body := bytes.TrimRight(lines[i], "\r\n")
	ind := indentOf(body)
	if v := bytes.TrimSpace(body); bytes.HasSuffix(v, []byte("|")) || bytes.HasSuffix(v, []byte(">")) ||
		bytes.HasSuffix(v, []byte("|-")) || bytes.HasSuffix(v, []byte(">-")) || bytes.HasSuffix(v, []byte("|+")) || bytes.HasSuffix(v, []byte(">+")) {
		return "the line starts a YAML block scalar"
	}
	for k := i - 1; k >= 0; k-- {
		l := bytes.TrimRight(lines[k], "\r\n")
		t := bytes.TrimSpace(l)
		if len(t) == 0 || t[0] == '#' {
			continue
		}
		if indentOf(l) < ind {
			// strip a trailing comment before looking for the indicator
			if c := bytes.Index(t, []byte(" #")); c >= 0 {
				t = bytes.TrimSpace(t[:c])
			}
			last := t
			if f := bytes.Fields(t); len(f) > 0 {
				last = f[len(f)-1]
			}
			if len(last) > 0 && (last[0] == '|' || last[0] == '>') {
				return "the line is inside a YAML block scalar"
			}
			ind = indentOf(l)
			if ind == 0 {
				break
			}
		}
	}
	return ""
}

// xmlUnsafe: the line must end with a closed tag, outside CDATA, script
// and style, so that a comment after it is between nodes.
func xmlUnsafe(lines [][]byte, i int) string {
	var before []byte
	for k := 0; k < i; k++ {
		before = append(before, lines[k]...)
	}
	low := bytes.ToLower(append(append([]byte{}, before...), lines[i]...))
	if bytes.Count(low, []byte("<![cdata[")) > bytes.Count(low, []byte("]]>")) {
		return "the line is inside CDATA"
	}
	if bytes.Count(low, []byte("<!--")) > bytes.Count(low, []byte("-->")) {
		return "the line is inside a comment"
	}
	for _, tag := range []string{"script", "style"} {
		if bytes.LastIndex(low, []byte("<"+tag)) > bytes.LastIndex(low, []byte("</"+tag)) {
			return "the line is inside <" + tag + ">"
		}
	}
	body := bytes.TrimRight(lines[i], "\r\n \t")
	if !bytes.HasSuffix(body, []byte(">")) {
		return "the line does not end with a tag"
	}
	// Inside an open tag spanning lines: the last '<' before the line has
	// no '>' after it.
	if lt := bytes.LastIndexByte(before, '<'); lt >= 0 && bytes.IndexByte(before[lt:], '>') < 0 {
		return "the line is inside a tag"
	}
	// Quotes on the line must balance (an attribute value may hold '>').
	if bytes.Count(body, []byte(`"`))%2 != 0 || bytes.Count(body, []byte(`'`))%2 != 0 {
		return "the end of the line may be inside an attribute value"
	}
	return ""
}

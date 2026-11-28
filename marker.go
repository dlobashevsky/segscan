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
	escSingle bool // a backslash may escape inside single quotes too (shell $'...')
	yaml      bool // YAML: quotes only open a scalar; block and multi-line scalars
	// refuse: a file holding any of these is refused whole. Java
	// translates \uXXXX before it reads a token (\u0022 is a quote,
	// \u000a a newline); C translates trigraphs (??/ is a backslash, so
	// "??/" at the end of a line continues it).
	refuse []string
}

var (
	styleNginx = commentStyle{start: "#", quotes: `"'`}
	// bash/zsh $'...' escapes \' and may span lines: read single quotes both ways
	styleShell = commentStyle{start: "#", quotes: `"'`, blockOpen: []string{"<<"}, escSingle: true}
	stylePy    = commentStyle{start: "#", quotes: `"'`, blockOpen: []string{`"""`, `'''`}}
	styleTOML  = commentStyle{start: "#", quotes: `"'`, blockOpen: []string{`"""`, `'''`}}
	styleYAML  = commentStyle{start: "#", quotes: `"'`, yaml: true}
	// C-like languages, each with its multi-line strings: Go raw strings, C++ R"(...)", Rust r#"..."#, the """ text
	// blocks of Java, Kotlin, Scala, Swift and C# 11, C# @"...".
	styleGo = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*", "`"}}
	styleC  = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*"}, rawOpen: []*regexp.Regexp{regexp.MustCompile(`(^|[^A-Za-z0-9_])(u8|[uUL])?R"`)}, refuse: []string{"??"}}
	// Rust: ordinary strings may span lines too
	styleRust = commentStyle{start: "//", quotes: "\"", blockOpen: []string{"/*"}, rawOpen: []*regexp.Regexp{regexp.MustCompile(`(^|[^A-Za-z0-9_])[bc]?r#*"`)}}
	styleJVM  = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*", `"""`, `#"`}}
	styleJava = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*", `"""`, `#"`}, refuse: []string{`\u`}}
	styleCS   = commentStyle{start: "//", quotes: "\"'", blockOpen: []string{"/*", `"""`}, rawOpen: []*regexp.Regexp{regexp.MustCompile(`@\$*"|\$+@"`)}}
	styleLua  = commentStyle{start: "--", quotes: `'"`, blockOpen: []string{"[[", "[="}}
)

// styleFor returns the comment style of a repository path, false for a type
// the marker is not offered for (JSON, INI, .env, Dockerfile, unknown...).
// SQL (bracketed and backtick identifiers, dollar, E and q strings, by dialect)
// and XML/HTML (markup mixed with text) are not offered either: too many
// ways for the end of a line to be inside a value. Ruby, Perl and JS/TS
// (JSX child text is not code) likewise, Scala (XML literals) and Swift
// (multi-line regex literals).
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
	case ".c", ".h", ".cc", ".cpp", ".hpp":
		return styleC, true
	case ".rs":
		return styleRust, true
	case ".java":
		return styleJava, true
	case ".kt":
		return styleJVM, true
	case ".cs":
		return styleCS, true
	case ".lua":
		return styleLua, true
	case ".conf":
		// nginx allows a comment after any directive; other .conf formats
		// are anybody's guess.
		if base == "nginx.conf" || strings.Contains("/"+path.Dir(p)+"/", "/nginx/") {
			return styleNginx, true
		}
	}
	return commentStyle{}, false
}

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
	for _, x := range st.refuse {
		if bytes.Contains(data, []byte(x)) {
			return nil, fmt.Errorf("%s: the file holds %q, which the compiler translates before it reads strings and comments (use the fingerprint)", repoPath, x)
		}
	}
	if why := unsafeLine(st, lines, no-1); why != "" {
		return nil, fmt.Errorf("%s:%d: %s", repoPath, no, why)
	}
	// Never append to a comment already on the line: compilers, linters,
	// editors and interpreters read many of them (//line, //go:, noqa,
	// shellcheck, modelines...), and added text changes what they say.
	// Where the comment character stands on the line does not matter: in
	// "x=1# noqa" or ";// eslint" it starts a comment some tool reads, in a
	// string it is harmless, and telling the two apart is what goes wrong.
	if bytes.Contains(body, []byte(st.start)) {
		return nil, fmt.Errorf("%s:%d: the line already holds %q (a comment?); text added could change what it says (use the fingerprint)", repoPath, no, st.start)
	}
	var add string
	if st.end != "" {
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
	}
	// Every line from the top must close its own quotes, whether a
	// backslash escapes ($'...' in bash and zsh, Lua's \z, C's \ at the
	// end) or not: a string left open anywhere above, or a line that reads
	// two ways, and the marker is refused. Almost every language has some
	// way for a string to run over lines, so this holds for all of them.
	for k := 0; k <= i; k++ {
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
// language has such strings (shell $'...'); without, it is an ordinary one.
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

func indentOf(l []byte) int { return len(l) - len(bytes.TrimLeft(l, " ")) }

// yamlUnsafe: a marker after a YAML value is a comment only on a line of
// the form "key: value", "key:", "- value" whose value, if quoted, closes
// on the line, outside block scalars and multi-line plain scalars.
func yamlUnsafe(lines [][]byte, i int) string {
	if why := yamlBlockScalar(lines, i); why != "" {
		return why
	}
	// A quoted scalar or a flow collection ([...], {...}) left open on any
	// line so far may still be open here, whatever this line looks like.
	for k := 0; k <= i; k++ {
		if why := yamlOpensLine(bytes.TrimRight(lines[k], "\r\n")); why != "" {
			if k == i {
				return why
			}
			return fmt.Sprintf("line %d: %s", k+1, why)
		}
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

// yamlOpensLine reports a line whose value starts a quoted scalar that does
// not close on it, or opens more [ { than it closes.
func yamlOpensLine(l []byte) string {
	t := bytes.TrimSpace(l)
	if len(t) == 0 || t[0] == '#' {
		return ""
	}
	val := t
	for bytes.HasPrefix(val, []byte("- ")) {
		val = bytes.TrimSpace(val[2:])
	}
	if k := yamlKeyEnd(val); k >= 0 {
		val = bytes.TrimSpace(val[k:])
	}
	// Node properties before the scalar: !tag, !!str, &anchor.
	for len(val) > 0 && (val[0] == '!' || val[0] == '&') {
		sp := bytes.IndexAny(val, " \t")
		if sp < 0 {
			val = nil
			break
		}
		val = bytes.TrimSpace(val[sp:])
	}
	// Explicit keys ("? ...") can hold anything over several lines.
	if t[0] == '?' && (len(t) == 1 || t[1] == ' ' || t[1] == '\t') {
		return "an explicit YAML key (? ...)"
	}
	if why := yamlScanLine(t); why != "" {
		return why
	}
	if len(val) > 0 && (val[0] == '"' || val[0] == '\'') && !yamlQuotedCloses(val) {
		return "a quoted YAML scalar runs over lines"
	}
	if len(val) > 0 && (val[0] == '[' || val[0] == '{') {
		if c := yamlCut(val); bytes.Count(c, []byte("[")) != bytes.Count(c, []byte("]")) || bytes.Count(c, []byte("{")) != bytes.Count(c, []byte("}")) {
			return "a YAML flow collection runs over lines"
		}
	}
	return ""
}

// yamlScanLine follows quotes and flow brackets along a whole line: a quote
// opens wherever it stands (a plain "don't" too: in doubt, no), a
// backslash escapes inside double quotes, a doubled quote inside single
// ones, and " #" outside them starts a comment. A quote or a bracket still
// open at the end of the line may run on over the next ones.
func yamlScanLine(t []byte) string {
	var q byte
	depth := 0
	for k := 0; k < len(t); k++ {
		c := t[k]
		switch {
		case q == '"' && c == '\\':
			k++
		case q == '\'' && c == '\'' && k+1 < len(t) && t[k+1] == '\'':
			k++
		case q != 0 && c == q:
			q = 0
		case q != 0:
		case c == '#' && (k == 0 || t[k-1] == ' ' || t[k-1] == '\t'):
			k = len(t)
		case c == '"' || c == '\'':
			q = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		}
	}
	switch {
	case q != 0:
		return "an unbalanced quote: a string may run over lines"
	case depth != 0:
		return "a YAML flow collection runs over lines"
	}
	return ""
}

// yamlCut drops a trailing comment from a value.
func yamlCut(v []byte) []byte {
	if c := bytes.Index(v, []byte(" #")); c >= 0 {
		return v[:c]
	}
	return v
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
// on the line (a doubled single quote stands for one inside single
// quotes; a backslash escapes inside double quotes).
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

package main

// Transforms (DESIGN.md 5.2) and the forms of a value that import and
// check 6 search for (6.3 step 1).

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// transformOrder fixes the order in which singles and pairs are generated.
var transformOrder = []string{"sha256", "dsha1", "b64", "b64nl", "b64url", "urlenc", "dq", "nginxq", "sq", "xml"}

const maxForm = 64 << 10 // a form derived from a placeholder chain (5.1)

// escaping transforms leave base58 unchanged (4.2).
var escaping = map[string]bool{"urlenc": true, "dq": true, "nginxq": true, "sq": true, "xml": true}

func applyTransform(t string, v []byte) ([]byte, error) {
	switch t {
	case "sha256":
		s := sha256.Sum256(v)
		return []byte(hex.EncodeToString(s[:])), nil
	case "dsha1":
		s := sha1.Sum(v)
		s = sha1.Sum(s[:])
		return []byte(hex.EncodeToString(s[:])), nil
	case "b64":
		return []byte(base64.StdEncoding.EncodeToString(v)), nil
	case "b64nl":
		return []byte(base64.StdEncoding.EncodeToString(append(append([]byte{}, v...), '\n'))), nil
	case "b64url":
		return []byte(base64.RawURLEncoding.EncodeToString(v)), nil
	case "urlenc":
		var b bytes.Buffer
		for _, c := range v {
			if isAlnum(c) || c == '-' || c == '.' || c == '_' || c == '~' {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
		return b.Bytes(), nil
	case "dq":
		if !utf8.Valid(v) {
			return nil, fmt.Errorf("dq: not valid UTF-8")
		}
		var b bytes.Buffer
		for _, c := range v {
			switch {
			case c == '\\':
				b.WriteString(`\\`)
			case c == '"':
				b.WriteString(`\"`)
			case c == '\t':
				b.WriteString(`\t`)
			case c == '\r':
				b.WriteString(`\r`)
			case c == '\n':
				b.WriteString(`\n`)
			case c < 0x20 || c == 0x7f:
				fmt.Fprintf(&b, `\u%04x`, c)
			default:
				b.WriteByte(c)
			}
		}
		return b.Bytes(), nil
	case "nginxq":
		var b bytes.Buffer
		for _, c := range v {
			switch {
			case c == '\\':
				b.WriteString(`\\`)
			case c == '"':
				b.WriteString(`\"`)
			case c == '\t':
				b.WriteString(`\t`)
			case c == '\r':
				b.WriteString(`\r`)
			case c == '\n':
				b.WriteString(`\n`)
			case c == '$':
				return nil, fmt.Errorf("nginxq: $ cannot be escaped in nginx")
			case c < 0x20 || c == 0x7f:
				return nil, fmt.Errorf("nginxq: control byte 0x%02x", c)
			default:
				b.WriteByte(c)
			}
		}
		return b.Bytes(), nil
	case "sq":
		if bytes.IndexByte(v, 0) >= 0 {
			return nil, fmt.Errorf("sq: NUL byte")
		}
		return bytes.ReplaceAll(v, []byte("'"), []byte(`'\''`)), nil
	case "xml":
		if !utf8.Valid(v) {
			return nil, fmt.Errorf("xml: not valid UTF-8")
		}
		var b bytes.Buffer
		for _, r := range string(v) {
			switch {
			case r == '&':
				b.WriteString("&amp;")
			case r == '<':
				b.WriteString("&lt;")
			case r == '>':
				b.WriteString("&gt;")
			case r == '"':
				b.WriteString("&quot;")
			case r == '\'':
				b.WriteString("&apos;")
			case r == '\t':
				b.WriteString("&#9;")
			case r == '\n':
				b.WriteString("&#10;")
			case r == '\r':
				b.WriteString("&#13;")
			case r < 0x20 || r == 0xfffe || r == 0xffff:
				return nil, fmt.Errorf("xml: character U+%04X is not allowed in XML 1.0", r)
			default:
				b.WriteRune(r)
			}
		}
		return b.Bytes(), nil
	}
	return nil, fmt.Errorf("unknown transform %s", t)
}

// applyChain applies the transforms left to right; every intermediate form
// is at most maxForm when limit is set (forms from placeholder chains).
func applyChain(chain []string, v []byte, limit bool) ([]byte, error) {
	for _, t := range chain {
		var err error
		if v, err = applyTransform(t, v); err != nil {
			return nil, err
		}
		if limit && len(v) > maxForm {
			return nil, fmt.Errorf("%s: form longer than 64 KiB", t)
		}
	}
	return v, nil
}

// searchChains: no transform, every single, every ordered pair, and the
// longer chains in extra (those used in the repository).
func searchChains(extra map[string]bool) [][]string {
	out := [][]string{nil}
	for _, a := range transformOrder {
		out = append(out, []string{a})
	}
	for _, a := range transformOrder {
		for _, b := range transformOrder {
			out = append(out, []string{a, b})
		}
	}
	var long []string
	for c := range extra {
		if strings.Count(c, ":") >= 2 {
			long = append(long, c)
		}
	}
	sort.Strings(long)
	for _, c := range long {
		out = append(out, strings.Split(c, ":"))
	}
	return out
}

type form struct {
	Chain string // "" for the bare value, else "b64", "sha256:urlenc", ...
	Data  []byte
	Weak  bool
}

// formsOf returns the distinct forms of v, each with the first chain that
// gives it. A chain that cannot represent v gives no form (6.3 step 1).
func formsOf(v []byte, chains [][]string) []form {
	var out []form
	seen := map[string]bool{}
	for _, c := range chains {
		d, err := applyChain(c, v, false)
		if err != nil || len(d) == 0 || seen[string(d)] {
			continue
		}
		seen[string(d)] = true
		out = append(out, form{Chain: strings.Join(c, ":"), Data: d, Weak: weakForm(d)})
	}
	return out
}

// weakForm: shorter than 8 bytes, or cheap under the cost model: fewer than
// 4 distinct bytes, or text that the statistical scanner with the built-in
// model and default thresholds finds nothing random in (a word, a version,
// a path). The built-in model, not the repository's, so the decision only
// changes with a segscan release.
func weakForm(d []byte) bool {
	if len(d) < 8 || distinct(d) < 4 {
		return true
	}
	if baseModel == nil {
		return false
	}
	found := false
	sc := NewScanner(baseModel, defaultOpts)
	for _, line := range bytes.Split(d, []byte("\n")) {
		sc.Line(line, func(int, []byte, float64, float64) { found = true })
		if found {
			return false
		}
	}
	return true
}

// chainsUsed collects the transform chains of placeholders in text.
func chainsUsed(data []byte, into map[string]bool) {
	if !bytes.Contains(data, phPrefix) {
		return
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		good, _ := parsePlaceholders(line)
		for _, p := range good {
			if len(p.Transforms) > 0 {
				into[strings.Join(p.Transforms, ":")] = true
			}
		}
	}
}

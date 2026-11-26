package main

// .sec/names and .sec/manifest: parsing, validation, formatting.

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// ---------- names ----------

type keyName struct {
	Name, UUID string
	Scope      []string
	Base58     bool // the value is always base58 (flag base58)
	Line       int
}

type nameList struct {
	Keys   []*keyName
	ByName map[string]*keyName
}

const namesHeader = "# segscan key names: name<TAB>uuid[<TAB>scope,...[<TAB>flags]]. No values here.\n"

// validName: [A-Za-z0-9_][A-Za-z0-9_.]*. No leading '.', so a name used as
// a file name (secret=<name>) is one path component and never "." or "..".
func validName(s string) bool {
	if s == "" || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isNameByte(s[i]) {
			return false
		}
	}
	return true
}

// parseNames returns the list and the problems found, each with its line.
func parseNames(data []byte) (*nameList, []lineProblem) {
	l := &nameList{ByName: map[string]*keyName{}}
	var probs []lineProblem
	uuids := map[string]bool{}
	for no, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		bad := func(format string, a ...any) { probs = append(probs, lineProblem{no + 1, fmt.Sprintf(format, a...)}) }
		if len(f) < 2 || len(f) > 4 {
			bad("expected name<TAB>uuid[<TAB>scope[<TAB>flags]]")
			continue
		}
		k := &keyName{Name: f[0], UUID: f[1], Line: no + 1}
		if len(f) >= 3 {
			k.Scope = splitList(f[2])
		}
		flagsOK := true
		if len(f) == 4 {
			for _, fl := range splitList(f[3]) {
				if fl != "base58" {
					bad("%s: unknown flag %q", k.Name, fl)
					flagsOK = false
					continue
				}
				k.Base58 = true
			}
		}
		if !flagsOK {
			continue
		}
		switch {
		case !validName(k.Name):
			bad("bad name %q", k.Name)
			continue
		case !isUUID([]byte(k.UUID), false):
			bad("bad uuid for %s", k.Name)
			continue
		case l.ByName[k.Name] != nil:
			bad("duplicate name %s", k.Name)
			continue
		case uuids[k.UUID]:
			bad("duplicate uuid for %s", k.Name)
			continue
		}
		for _, s := range k.Scope {
			if err := checkGlob(s); err != nil {
				bad("%s: %v", k.Name, err)
			}
		}
		uuids[k.UUID] = true
		l.ByName[k.Name] = k
		l.Keys = append(l.Keys, k)
	}
	return l, probs
}

func (l *nameList) format() []byte {
	sort.Slice(l.Keys, func(i, j int) bool { return l.Keys[i].Name < l.Keys[j].Name })
	var b strings.Builder
	b.WriteString(namesHeader)
	for _, k := range l.Keys {
		b.WriteString(k.Name + "\t" + k.UUID)
		if len(k.Scope) > 0 || k.Base58 {
			b.WriteString("\t" + strings.Join(k.Scope, ","))
		}
		if k.Base58 {
			b.WriteString("\tbase58")
		}
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

type lineProblem struct {
	Line int
	Msg  string
}

// ---------- manifest ----------

type mEntry struct {
	Path, Type, Mode, Owner, Group string
	Attrs                          []string
	Line                           int
}

const manifestHeader = "# segscan manifest: path<TAB>type<TAB>mode<TAB>owner<TAB>group[<TAB>k=v...]\n" +
	"# type: f file, d directory, l symlink, s secret file from the keystore\n"

var modeRE = regexp.MustCompile(`^[0-7]{3,4}$`)

func parseManifest(data []byte) ([]*mEntry, []lineProblem) {
	var out []*mEntry
	var probs []lineProblem
	seen := map[string]bool{}
	for no, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		bad := func(format string, a ...any) { probs = append(probs, lineProblem{no + 1, fmt.Sprintf(format, a...)}) }
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			bad("expected path<TAB>type<TAB>mode<TAB>owner<TAB>group")
			continue
		}
		e := &mEntry{Path: f[0], Type: f[1], Mode: f[2], Owner: f[3], Group: f[4], Attrs: f[5:], Line: no + 1}
		ok := true
		check := func(cond bool, format string, a ...any) {
			if !cond {
				bad(format, a...)
				ok = false
			}
		}
		check(e.Path != "" && path.Clean(e.Path) == e.Path && !strings.HasPrefix(e.Path, "/") &&
			e.Path != ".." && !strings.HasPrefix(e.Path, "../"), "bad path %q", e.Path)
		check(strings.Contains("fdls", e.Type) && len(e.Type) == 1, "%s: bad type %q", e.Path, e.Type)
		check(modeRE.MatchString(e.Mode), "%s: bad mode %q", e.Path, e.Mode)
		check(e.Owner != "" && !strings.ContainsAny(e.Owner, " :"), "%s: bad owner %q", e.Path, e.Owner)
		check(e.Group != "" && !strings.ContainsAny(e.Group, " :"), "%s: bad group %q", e.Path, e.Group)
		secret := ""
		for _, a := range e.Attrs {
			k, v, has := strings.Cut(a, "=")
			check(has && k != "", "%s: bad attribute %q", e.Path, a)
			switch k {
			case "secret":
				check(e.Type == "s", "%s: secret= is only for type s", e.Path)
				secret = v
			}
		}
		if e.Type == "s" {
			check(validName(secret), "%s: type s needs secret=<name>", e.Path)
		}
		check(!seen[e.Path], "duplicate path %s", e.Path)
		if ok {
			seen[e.Path] = true
			out = append(out, e)
		}
	}
	return out, probs
}

func formatManifest(es []*mEntry) []byte {
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
	var b strings.Builder
	b.WriteString(manifestHeader)
	for _, e := range es {
		b.WriteString(strings.Join(append([]string{e.Path, e.Type, e.Mode, e.Owner, e.Group}, e.Attrs...), "\t"))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

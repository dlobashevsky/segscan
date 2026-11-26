package main

// Support for configuration repositories with a .sec/ directory (DESIGN.md):
// repository discovery, .sec/config, path globs and uuids.

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"
)

const secDir = ".sec"

// What -skip-uuids hides from the statistical scanner (DESIGN.md 5.3).
const (
	skipOff          = iota
	skipPlaceholders // well-formed !SECKEY_..! spans
	skipAll          // placeholders and bare canonical UUIDs
)

type secConfig struct {
	Project   string
	Keystore  string // as written, may start with ~/
	Roots     []string
	SkipUUIDs int
	Binary    string // scan | skip
	HookScan  string // warn | block | off
	Forbid    []string
}

// secRoot returns the top directory of the current git repository if it has
// a .sec/ directory, otherwise "".
func secRoot() string {
	top, err := gitOut("rev-parse", "--show-toplevel")
	if err != nil || top == "" {
		return ""
	}
	if st, err := os.Stat(filepath.Join(top, secDir)); err == nil && st.IsDir() {
		return top
	}
	return ""
}

func secPath(top string, name ...string) string {
	return filepath.Join(append([]string{top, secDir}, name...)...)
}

// mustSec returns the repository top and its configuration, or exits.
func mustSec() (string, *secConfig) {
	top := secRoot()
	if top == "" {
		die(fmt.Errorf("no %s/ in this repository: run segscan init", secDir))
	}
	cfg, err := loadSecConfig(top)
	if err != nil {
		die(err)
	}
	return top, cfg
}

func loadSecConfig(top string) (*secConfig, error) {
	data, err := os.ReadFile(secPath(top, "config"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	cfg, err := parseSecConfig(data, filepath.Base(top))
	if err != nil {
		return nil, fmt.Errorf("%s/config: %v", secDir, err)
	}
	return cfg, nil
}

// parseSecConfig reads "key = value" lines. # starts a comment at the start
// of a line or after whitespace. Unknown keys are errors, so that a typo does
// not silently fall back to a default.
func parseSecConfig(data []byte, project string) (*secConfig, error) {
	cfg := &secConfig{Project: project, Roots: []string{"nodes/*"}, SkipUUIDs: skipAll, Binary: "scan", HookScan: "warn"}
	for no, l := range strings.Split(string(data), "\n") {
		if msg := textLineProblem(l); msg != "" {
			return nil, fmt.Errorf("line %d: %s", no+1, msg)
		}
		for i := 0; i < len(l); i++ {
			if l[i] == '#' && (i == 0 || l[i-1] == ' ' || l[i-1] == '\t') {
				l = l[:i]
				break
			}
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", no+1)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		bad := func() error { return fmt.Errorf("line %d: bad value for %s: %q", no+1, k, v) }
		switch k {
		case "project":
			if v == "" || strings.ContainsAny(v, "/\\") {
				return nil, bad()
			}
			cfg.Project = v
		case "keystore":
			cfg.Keystore = v
		case "roots":
			cfg.Roots = splitList(v)
		case "skip_uuids":
			switch v {
			case "all":
				cfg.SkipUUIDs = skipAll
			case "placeholders":
				cfg.SkipUUIDs = skipPlaceholders
			case "off":
				cfg.SkipUUIDs = skipOff
			default:
				return nil, bad()
			}
		case "binary":
			if v != "scan" && v != "skip" {
				return nil, bad()
			}
			cfg.Binary = v
		case "hook_scan":
			if v != "warn" && v != "block" && v != "off" {
				return nil, bad()
			}
			cfg.HookScan = v
		case "forbid":
			cfg.Forbid = splitList(v)
		default:
			return nil, fmt.Errorf("line %d: unknown key %q", no+1, k)
		}
	}
	for _, p := range append(append([]string{}, cfg.Roots...), cfg.Forbid...) {
		if err := checkGlob(p); err != nil {
			return nil, err
		}
	}
	if cfg.Keystore == "" {
		cfg.Keystore = "~/.secshell/" + cfg.Project
	}
	return cfg, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// keystoreDir is the keystore path with ~ expanded; $SEGSCAN_KEYSTORE wins.
// checkKeystorePath refuses "." and ".." components in the keystore path.
func checkKeystorePath(p string) error {
	for _, c := range strings.Split(p, string(filepath.Separator)) {
		if c == "." || c == ".." {
			return fmt.Errorf("keystore %q: no . or .. components allowed", p)
		}
	}
	return nil
}

// invokerHome is ~ of the user segscan works for: under sudo the caller's
// home from the password database, not root's or an inherited $HOME.
func invokerHome() string {
	if os.Geteuid() == 0 {
		if id := os.Getenv("SUDO_UID"); id != "" {
			if u, err := user.LookupId(id); err == nil {
				return u.HomeDir
			}
		}
	}
	home, _ := os.UserHomeDir()
	return home
}

func (c *secConfig) keystoreDir() string {
	p := c.Keystore
	if e := os.Getenv("SEGSCAN_KEYSTORE"); e != "" {
		p = e
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home := invokerHome(); home != "" {
			p = home + string(filepath.Separator) + rest // no Clean: see canonical
		}
	}
	return p
}

// nodeRoot returns the shortest directory prefix of a repository path that
// matches one of the root globs: nodes/n1/etc/x -> nodes/n1.
func (c *secConfig) nodeRoot(p string) (string, bool) {
	for i := 0; i < len(p); i++ {
		if p[i] != '/' {
			continue
		}
		dir := p[:i]
		for _, r := range c.Roots {
			if matchSegs(strings.Split(strings.Trim(r, "/"), "/"), strings.Split(dir, "/")) {
				return dir, true
			}
		}
	}
	return "", false
}

// isNodeRoot reports whether p itself is a node root path (nodes/n1).
func (c *secConfig) isNodeRoot(p string) bool {
	for _, r := range c.Roots {
		if matchSegs(strings.Split(strings.Trim(r, "/"), "/"), strings.Split(p, "/")) {
			return true
		}
	}
	return false
}

// ---------- globs ----------

// matchPath reports whether a repository path matches a glob. A pattern
// without "/" matches the last element of the path, as in .gitignore; one
// with "/" matches the whole path, and a "**" element stands for any number
// of elements, none included.
func matchPath(pat, p string) bool {
	pat = strings.Trim(pat, "/")
	if !strings.Contains(pat, "/") {
		ok, _ := path.Match(pat, path.Base(p))
		return ok
	}
	return matchSegs(strings.Split(pat, "/"), strings.Split(p, "/"))
}

func matchAny(pats []string, p string) (string, bool) {
	for _, pat := range pats {
		if matchPath(pat, p) {
			return pat, true
		}
	}
	return "", false
}

func matchSegs(ps, xs []string) bool {
	for len(ps) > 0 {
		if ps[0] == "**" {
			for i := 0; i <= len(xs); i++ {
				if matchSegs(ps[1:], xs[i:]) {
					return true
				}
			}
			return false
		}
		if len(xs) == 0 {
			return false
		}
		if ok, _ := path.Match(ps[0], xs[0]); !ok {
			return false
		}
		ps, xs = ps[1:], xs[1:]
	}
	return len(xs) == 0
}

func checkGlob(pat string) error {
	for _, seg := range strings.Split(strings.Trim(pat, "/"), "/") {
		if _, err := path.Match(seg, ""); err != nil {
			return fmt.Errorf("bad glob %q", pat)
		}
	}
	return nil
}

// ---------- uuids ----------

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		die(err)
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// isUUID checks the canonical 8-4-4-4-12 form; anyCase also accepts A-F.
func isUUID(b []byte, anyCase bool) bool {
	if len(b) != 36 {
		return false
	}
	for i, c := range b {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || anyCase && c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// ---------- placeholders ----------

var phPrefix = []byte("!SECKEY_")

// maxTransforms bounds a chain: :b64 repeated grows the result exponentially.
const maxTransforms = 4

// knownTransforms are the transforms of DESIGN.md 5.2.
var knownTransforms = map[string]bool{
	"sha256": true, "dsha1": true, "b64": true, "b64nl": true, "b64url": true,
	"urlenc": true, "dq": true, "nginxq": true, "sq": true, "xml": true,
}

type placeholder struct {
	Col, End   int // byte offsets of the opening '!' and just after the closing one
	Name, UUID string
	Transforms []string
}

type badPlaceholder struct {
	Col int
	Why string
}

func isNameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '.'
}

// parsePlaceholders finds every "!SECKEY_" in a line and parses it:
//
//	!SECKEY_<name>_<uuid>[:<transform>]...!
//
// The name has no '-' and the uuid always does, so the uuid is the last 36
// bytes of the run of name and uuid characters.
func parsePlaceholders(line []byte) (good []placeholder, bad []badPlaceholder) {
	off := 0
	for {
		i := bytes.Index(line[off:], phPrefix)
		if i < 0 {
			return
		}
		i += off
		if p, why := parsePlaceholder(line, i); why == "" {
			good = append(good, p)
			off = p.End
		} else {
			bad = append(bad, badPlaceholder{Col: i, Why: why})
			off = i + len(phPrefix)
		}
	}
}

func parsePlaceholder(line []byte, i int) (placeholder, string) {
	j := i + len(phPrefix)
	k := j
	for k < len(line) && (isNameByte(line[k]) || line[k] == '-') {
		k++
	}
	run := line[j:k]
	if len(run) < 36 || !isUUID(run[len(run)-36:], true) {
		return placeholder{}, "no uuid after the name"
	}
	u := run[len(run)-36:]
	if !isUUID(u, false) {
		return placeholder{}, "the uuid must be lower-case"
	}
	if len(run) < 38 || run[len(run)-37] != '_' {
		return placeholder{}, "no name, or no '_' between the name and the uuid"
	}
	name := run[:len(run)-37]
	if bytes.IndexByte(name, '-') >= 0 {
		return placeholder{}, "'-' in the name"
	}
	if name[0] == '.' {
		return placeholder{}, "the name starts with '.'"
	}
	p := placeholder{Col: i, Name: string(name), UUID: string(u)}
	for k < len(line) && line[k] == ':' {
		t := k + 1
		for t < len(line) && (line[t] >= 'a' && line[t] <= 'z' || line[t] >= '0' && line[t] <= '9') {
			t++
		}
		if t == k+1 {
			return placeholder{}, "empty transform after ':'"
		}
		p.Transforms = append(p.Transforms, string(line[k+1:t]))
		if len(p.Transforms) > maxTransforms {
			return placeholder{}, fmt.Sprintf("more than %d transforms", maxTransforms)
		}
		k = t
	}
	if k >= len(line) || line[k] != '!' {
		return placeholder{}, "no closing '!'"
	}
	p.End = k + 1
	return p, ""
}

func isAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// blankSpans returns the line with placeholders, and for skipAll also bare
// canonical UUIDs, replaced by spaces, so the scanner does not score them and
// does not take "SECKEY" for the keyword "key". Offsets are kept. buf is
// reused between calls.
func blankSpans(line []byte, buf *[]byte, mode int) []byte {
	if mode == skipOff {
		return line
	}
	hasPH := bytes.Contains(line, phPrefix)
	if !hasPH && (mode != skipAll || bytes.Count(line, []byte{'-'}) < 4) {
		return line
	}
	b := append((*buf)[:0], line...)
	*buf = b
	if hasPH {
		good, _ := parsePlaceholders(line)
		for _, p := range good {
			for k := p.Col; k < p.End; k++ {
				b[k] = ' '
			}
		}
	}
	if mode == skipAll {
		for i := 0; i+36 <= len(b); i++ {
			if (i == 0 || !isAlnum(b[i-1])) && (i+36 == len(b) || !isAlnum(b[i+36])) && isUUID(b[i:i+36], true) {
				for k := i; k < i+36; k++ {
					b[k] = ' '
				}
				i += 35
			}
		}
	}
	return b
}

// placeholderText is how a placeholder is written.
func placeholderText(name, uuid string, transforms ...string) string {
	s := "!SECKEY_" + name + "_" + uuid
	for _, t := range transforms {
		s += ":" + t
	}
	return s + "!"
}

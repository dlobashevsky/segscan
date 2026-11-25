package main

import (
	"reflect"
	"strings"
	"testing"
)

const testUUID = "19cb3a1b-749b-4af9-86b2-da0f8dd8b1f7"

func TestParsePlaceholders(t *testing.T) {
	ph := func(name string, tr ...string) string { return placeholderText(name, testUUID, tr...) }
	for _, c := range []struct {
		line  string
		names []string
		trans [][]string
		bad   []string
	}{
		{"key " + ph("ch_sts") + ";", []string{"ch_sts"}, [][]string{nil}, nil},
		{"Basic " + ph("ch.sts_2", "b64", "urlenc"), []string{"ch.sts_2"}, [][]string{{"b64", "urlenc"}}, nil},
		{ph("a") + ph("b"), []string{"a", "b"}, [][]string{nil, nil}, nil},
		{"!SECKEY_a_" + strings.ToUpper(testUUID) + "!", nil, nil, []string{"lower-case"}},
		{"!SECKEY_" + testUUID + "!", nil, nil, []string{"no name"}},
		{"!SECKEY__" + testUUID + "!", nil, nil, []string{"no name"}},
		{"!SECKEY_a-b_" + testUUID + "!", nil, nil, []string{"'-' in the name"}},
		{"!SECKEY_a" + testUUID + "!", nil, nil, []string{"no '_'"}},
		{"!SECKEY_a_" + testUUID, nil, nil, []string{"no closing"}},
		{"!SECKEY_a_" + testUUID + ":!", nil, nil, []string{"empty transform"}},
		{"!SECKEY_bad! and " + ph("ok"), []string{"ok"}, [][]string{nil}, []string{"no uuid"}},
	} {
		good, bad := parsePlaceholders([]byte(c.line))
		var names []string
		var trans [][]string
		for _, p := range good {
			names = append(names, p.Name)
			trans = append(trans, p.Transforms)
			if p.UUID != testUUID || c.line[p.Col] != '!' || c.line[p.End-1] != '!' {
				t.Errorf("%q: bad span or uuid: %+v", c.line, p)
			}
		}
		if !reflect.DeepEqual(names, c.names) || !reflect.DeepEqual(trans, c.trans) {
			t.Errorf("%q: got %v %v, want %v %v", c.line, names, trans, c.names, c.trans)
		}
		if len(bad) != len(c.bad) {
			t.Errorf("%q: bad = %+v, want %v", c.line, bad, c.bad)
			continue
		}
		for i := range bad {
			if !strings.Contains(bad[i].Why, c.bad[i]) {
				t.Errorf("%q: why %q, want %q", c.line, bad[i].Why, c.bad[i])
			}
		}
	}
}

func TestBlankSpans(t *testing.T) {
	ph := placeholderText("k", testUUID, "b64")
	bare := "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	line := "a " + ph + " b " + bare + " c"
	var buf []byte
	if got := string(blankSpans([]byte(line), &buf, skipOff)); got != line {
		t.Errorf("off changed the line: %q", got)
	}
	got := string(blankSpans([]byte(line), &buf, skipPlaceholders))
	if want := "a " + strings.Repeat(" ", len(ph)) + " b " + bare + " c"; got != want {
		t.Errorf("placeholders: %q", got)
	}
	got = string(blankSpans([]byte(line), &buf, skipAll))
	if want := "a " + strings.Repeat(" ", len(ph)) + " b " + strings.Repeat(" ", len(bare)) + " c"; got != want {
		t.Errorf("all: %q", got)
	}
	// A UUID glued to other alphanumerics is not a UUID.
	glued := "x" + bare
	if got := string(blankSpans([]byte(glued), &buf, skipAll)); got != glued {
		t.Errorf("glued uuid blanked: %q", got)
	}
}

func TestScannerSkip(t *testing.T) {
	if baseModel == nil {
		t.Skip("no built-in model")
	}
	scan := func(line string, skip int) []string {
		o := defaultOpts
		o.Skip = skip
		var out []string
		NewScanner(baseModel, o).Line([]byte(line), func(_ int, text []byte, _, _ float64) {
			out = append(out, string(text))
		})
		return out
	}
	ph := placeholderText("ch_sts", testUUID)
	line := "proxy_set_header X-ClickHouse-key " + ph + ";"
	if f := scan(line, skipOff); len(f) == 0 {
		t.Errorf("without skip the uuid should be found: %s", line)
	}
	if f := scan(line, skipPlaceholders); len(f) != 0 {
		t.Errorf("placeholder scored: %q", f)
	}
	secret := "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5q"
	if f := scan("key "+ph+" "+secret, skipAll); len(f) != 1 || f[0] != secret {
		t.Errorf("a secret next to a placeholder: %q", f)
	}
	bare := `"token":"3fa85f64-5717-4562-b3fc-2c963f66afa6",`
	if f := scan(bare, skipPlaceholders); len(f) == 0 {
		t.Errorf("placeholders mode should keep bare uuids")
	}
	if f := scan(bare, skipAll); len(f) != 0 {
		t.Errorf("all mode scored a bare uuid: %q", f)
	}
}

func TestParseSecConfig(t *testing.T) {
	cfg, err := parseSecConfig(nil, "cluster")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Keystore != "~/.secshell/cluster" || cfg.SkipUUIDs != skipAll || cfg.HookScan != "warn" || !reflect.DeepEqual(cfg.Roots, []string{"nodes/*"}) {
		t.Errorf("defaults: %+v", cfg)
	}
	cfg, err = parseSecConfig([]byte("# c\nproject = p # inline\nroots = a/*, b/*\nskip_uuids=placeholders\nforbid = .htpasswd*,*.key\n"), "x")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "p" || cfg.Keystore != "~/.secshell/p" || cfg.SkipUUIDs != skipPlaceholders ||
		!reflect.DeepEqual(cfg.Roots, []string{"a/*", "b/*"}) || !reflect.DeepEqual(cfg.Forbid, []string{".htpasswd*", "*.key"}) {
		t.Errorf("parsed: %+v", cfg)
	}
	for _, bad := range []string{"nokey\n", "colour = red\n", "skip_uuids = some\n", "hook_scan = maybe\n", "forbid = [\n"} {
		if _, err := parseSecConfig([]byte(bad), "x"); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestMatchPath(t *testing.T) {
	for _, c := range []struct {
		pat, path string
		want      bool
	}{
		{".htpasswd*", "nodes/n1/etc/nginx/.htpasswd.subs", true},
		{"*.key", "a/b/c.key", true},
		{"*.key", "a/b/c.keys", false},
		{"nodes/*/etc/nginx/**", "nodes/n1/etc/nginx/conf.d/x.conf", true},
		{"nodes/*/etc/nginx/**", "nodes/n1/etc/nginx", true},
		{"nodes/*/etc/nginx/**", "nodes/n1/etc/telegraf/t.conf", false},
		{"nodes/**/users.xml", "nodes/n1/etc/clickhouse-server/users.xml", true},
		{"nodes/*", "nodes/n1/etc", false},
	} {
		if got := matchPath(c.pat, c.path); got != c.want {
			t.Errorf("matchPath(%q, %q) = %v", c.pat, c.path, got)
		}
	}
	cfg := &secConfig{Roots: []string{"nodes/*", "extra/root"}}
	for p, want := range map[string]string{"nodes/n1/etc/x": "nodes/n1", "extra/root/y": "extra/root", "README.md": "", "nodes/top": ""} {
		if got, _ := cfg.nodeRoot(p); got != want {
			t.Errorf("nodeRoot(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestNames(t *testing.T) {
	u2 := "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	l, probs := parseNames([]byte(namesHeader + "b\t" + u2 + "\tnodes/**\na\t" + testUUID + "\n"))
	if len(probs) != 0 {
		t.Fatal(probs)
	}
	if got := string(l.format()); got != namesHeader+"a\t"+testUUID+"\nb\t"+u2+"\tnodes/**\n" {
		t.Errorf("format: %q", got)
	}
	// Flags: base58 with and without a scope.
	l, probs = parseNames([]byte("a\t" + testUUID + "\t\tbase58\nb\t" + u2 + "\tnodes/**\tbase58\n"))
	if len(probs) != 0 || !l.ByName["a"].Base58 || !l.ByName["b"].Base58 || len(l.ByName["a"].Scope) != 0 {
		t.Fatal(l.ByName, probs)
	}
	if got := string(l.format()); got != namesHeader+"a\t"+testUUID+"\t\tbase58\nb\t"+u2+"\tnodes/**\tbase58\n" {
		t.Errorf("format with flags: %q", got)
	}
	_, probs = parseNames([]byte("a\t" + testUUID + "\na\t" + u2 + "\nb\t" + testUUID + "\nc-d\t" + u2 + "\ne\tnot-a-uuid\nf\ng\t" + u2 + "\t\thex\n"))
	if len(probs) != 6 {
		t.Errorf("problems: %+v", probs)
	}
}

func TestManifest(t *testing.T) {
	data := manifestHeader + "nodes/n1/etc/x\tf\t0640\troot\tadm\tacl=u:www:r\n" +
		"nodes/n1/etc/.htpasswd\ts\t0640\troot\twww-data\tsecret=htpasswd\n"
	es, probs := parseManifest([]byte(data))
	if len(probs) != 0 || len(es) != 2 {
		t.Fatal(es, probs)
	}
	if got := string(formatManifest(es)); got != manifestHeader+"nodes/n1/etc/.htpasswd\ts\t0640\troot\twww-data\tsecret=htpasswd\n"+
		"nodes/n1/etc/x\tf\t0640\troot\tadm\tacl=u:www:r\n" {
		t.Errorf("format: %q", got)
	}
	for _, bad := range []string{
		"/abs\tf\t0644\troot\troot",
		"a/../b\tf\t0644\troot\troot",
		"a\tx\t0644\troot\troot",
		"a\tf\t644x\troot\troot",
		"a\tf\t0644\t\troot",
		"a\ts\t0600\troot\troot",
		"a\tf\t0644\troot\troot\tnoequals",
		"a\tf\t0644",
	} {
		if _, probs := parseManifest([]byte(bad)); len(probs) == 0 {
			t.Errorf("accepted %q", bad)
		}
	}
	for dir, want := range map[string]string{"0755": "0644", "2770": "0660", "0700": "0600", "1777": "0666"} {
		if got := fileMode(dir); got != want {
			t.Errorf("fileMode(%s) = %s, want %s", dir, got, want)
		}
	}
}

func TestPrivateKeyAfterUnterminatedBlock(t *testing.T) {
	data := "-----BEGIN CERTIFICATE-----\nMIIB\n-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
	fi := analyzeFile([]byte(data), loadAllow("", false))
	if len(fi.finds) != 1 || fi.finds[0].Check != ckPrivate || fi.finds[0].Line != 3 {
		t.Errorf("finds: %+v", fi.finds)
	}
	var p pemState
	for i, l := range strings.Split(data, "\n") {
		if _, private := p.feed([]byte(l)); private != (i == 2) {
			t.Errorf("line %d: private = %v", i+1, private)
		}
	}
}

func TestNewUUID(t *testing.T) {
	a, b := newUUID(), newUUID()
	if !isUUID([]byte(a), false) || a == b || a[14] != '4' || !strings.ContainsRune("89ab", rune(a[19])) {
		t.Errorf("uuids %s %s", a, b)
	}
}

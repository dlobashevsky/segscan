//go:build linux

package main

// Tests of the keystore, transforms, check 6, import and expand -to.

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransforms(t *testing.T) {
	cases := []struct{ chain, in, out string }{
		{"sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"dsha1", "abc", "0d3ced9bec10a777aec23ccc353a8c08a633045e"},
		{"b64", "ab?", "YWI/"},
		{"b64nl", "abc", "YWJjCg=="},
		{"b64url", "ab?", "YWI_"},
		{"urlenc", "a b/c~", "a%20b%2Fc~"},
		{"dq", "a\"b\\c\td\x01", `a\"b\\c\td\u0001`},
		{"nginxq", "a\"b", `a\"b`},
		{"sq", "it's", `it'\''s`},
		{"xml", "a<b&'\"\n", "a&lt;b&amp;&apos;&quot;&#10;"},
		{"sha256:urlenc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, c := range cases {
		got, err := applyChain(strings.Split(c.chain, ":"), []byte(c.in), true)
		if err != nil || string(got) != c.out {
			t.Errorf("%s(%q) = %q, %v; want %q", c.chain, c.in, got, err, c.out)
		}
	}
	for _, c := range []struct{ t, in string }{{"nginxq", "a$b"}, {"nginxq", "a\x01"}, {"sq", "a\x00"}, {"dq", "\xff"}, {"xml", "\x01"}} {
		if _, err := applyTransform(c.t, []byte(c.in)); err == nil {
			t.Errorf("%s(%q): no error", c.t, c.in)
		}
	}
	// Singles and pairs always, longer chains only when used.
	if n := len(searchChains(nil)); n != 1+10+100 {
		t.Errorf("chains: %d", n)
	}
	if n := len(searchChains(map[string]bool{"b64:sha256:urlenc": true, "b64": true})); n != 112 {
		t.Errorf("chains with one long one: %d", n)
	}
}

func TestRedundantChain(t *testing.T) {
	for _, c := range []struct {
		chain  string
		base58 bool
		want   bool
	}{
		{"sha256:urlenc", false, true},
		{"dq:sha256", false, true}, // a keystore value has nothing dq escapes
		{"urlenc:sha256", false, false},
		{"urlenc", false, false},
		{"urlenc", true, true},
		{"b64:urlenc", false, false},
		{"b64:xml", false, true},
		{"b64url:urlenc", false, true},
		{"sha256", false, false},
	} {
		if got := redundantChain(strings.Split(c.chain, ":"), c.base58); got != c.want {
			t.Errorf("redundantChain(%s, base58=%v) = %v", c.chain, c.base58, got)
		}
	}
}

func TestWeakForm(t *testing.T) {
	for s, want := range map[string]bool{
		"0": true, "admin": true, "password": true, "aaaaaaaaaaaa": true,
		"8f3Kq2mZbW9xLp4R": false,
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad": false,
	} {
		if baseModel == nil && len(s) >= 8 && want {
			continue // the built-in model decides these
		}
		if got := weakForm([]byte(s)); got != want {
			t.Errorf("weakForm(%q) = %v", s, got)
		}
	}
}

func TestSecretPatterns(t *testing.T) {
	whole, lines, values := secretPatterns([]byte("A=1\nTOKEN=\"Zx81\"\n\n  x y  \nEMPTY=\n"))
	if whole == nil {
		t.Error("no whole")
	}
	got := func(xs [][]byte) string {
		var s []string
		for _, x := range xs {
			s = append(s, string(x))
		}
		return strings.Join(s, "|")
	}
	if g := got(lines); g != `A=1|TOKEN="Zx81"|x y|EMPTY=` {
		t.Errorf("lines %s", g)
	}
	if g := got(values); g != `1|"Zx81"|Zx81` {
		t.Errorf("values %s", g)
	}
}

// ---------- end to end ----------

func newKSRepo(t *testing.T) (*repo, string) {
	r := newRepo(t)
	ks := filepath.Join(t.TempDir(), "ks")
	for i, e := range r.env {
		if strings.HasPrefix(e, "SEGSCAN_KEYSTORE=") {
			r.env[i] = "SEGSCAN_KEYSTORE=" + ks
		}
	}
	r.must("segscan", "init")
	return r, ks
}

func (r *repo) runIn(stdin, name string, args ...string) (string, string, int) {
	r.t.Helper()
	cmd := exec.Command(filepath.Join(r.bin, "segscan"), args...)
	if name != "segscan" {
		cmd = exec.Command(name, args...)
	}
	cmd.Dir, cmd.Env, cmd.Stdin = r.dir, r.env, strings.NewReader(stdin)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		r.t.Fatal(err)
	}
	return out.String(), errb.String(), code
}

// setKey adds name if needed and gives it value.
func (r *repo) setKey(name, value string, addArgs ...string) {
	r.t.Helper()
	if !strings.Contains(r.read(".sec/names"), name+"\t") {
		r.must("segscan", append([]string{"key", "add", name}, addArgs...)...)
	}
	if out, errs, code := r.runIn(value+"\n", "segscan", "key", "set", name); code != 0 {
		r.t.Fatalf("key set %s: exit %d %s%s", name, code, out, errs)
	}
}

func placeholderOf(r *repo, name string) string {
	for _, l := range strings.Split(r.read(".sec/names"), "\n") {
		if f := strings.Split(l, "\t"); len(f) >= 2 && f[0] == name {
			return placeholderText(name, f[1])
		}
	}
	r.t.Fatalf("no key %s", name)
	return ""
}

func TestCLIKeystoreModes(t *testing.T) {
	r, ks := newKSRepo(t)
	r.must("segscan", "key", "add", "a", "-base58")
	if _, errs, code := r.run("segscan", "key", "check"); code != 2 || !strings.Contains(errs, "no keystore at "+ks) {
		t.Errorf("key check without keystore: exit %d %s", code, errs)
	}
	if _, errs, _ := r.run("segscan", "check"); !strings.Contains(errs, "known values not checked: no keystore") {
		t.Errorf("check without keystore: %s", errs)
	}
	if _, _, code := r.runIn("not base58 0OIl\n", "segscan", "key", "set", "a"); code != 2 {
		t.Errorf("non-base58 value for a base58 key: exit %d", code)
	}
	if _, _, code := r.runIn("has space\n", "segscan", "key", "set", "b"); code != 2 {
		t.Errorf("unknown key: exit %d", code)
	}
	r.must("segscan", "key", "set", "a", "-gen", "20")
	st, err := os.Stat(ks)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("keystore dir: %v %v", st, err)
	}
	st, _ = os.Stat(filepath.Join(ks, "keys"))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("keys mode %v", st.Mode())
	}
	r.must("segscan", "key", "check")
	os.Chmod(filepath.Join(ks, "keys"), 0o644)
	if _, errs, code := r.run("segscan", "key", "check"); code != 2 || !strings.Contains(errs, "must be 0600") {
		t.Errorf("keys 0644: exit %d %s", code, errs)
	}
	if _, _, code := r.run("segscan", "check"); code != 2 {
		t.Errorf("check with an untrusted keystore must fail: exit %d", code)
	}
	os.Chmod(filepath.Join(ks, "keys"), 0o600)
	// The keystore through a symlink is refused.
	alias := filepath.Join(t.TempDir(), "alias")
	os.Symlink(ks, alias)
	for i, e := range r.env {
		if strings.HasPrefix(e, "SEGSCAN_KEYSTORE=") {
			r.env[i] = "SEGSCAN_KEYSTORE=" + alias
		}
	}
	if _, errs, code := r.run("segscan", "key", "check"); code != 2 || !strings.Contains(errs, "symlink") {
		t.Errorf("keystore through a symlink: exit %d %s", code, errs)
	}
}

func TestCLIKeyCheck(t *testing.T) {
	r, ks := newKSRepo(t)
	r.setKey("a", "Zx81kq9PmW3vT7bR")
	r.must("segscan", "key", "add", "b")
	r.setKey("gone", "Qw7ErT9yUi3OpLk2")
	r.must("segscan", "key", "rm", "gone")
	out, _, code := r.run("segscan", "key", "check")
	if code != 1 || !strings.Contains(out, "key\tb\tno value") || !strings.Contains(out, "key\tgone\tnot in .sec/names") {
		t.Errorf("key check: exit %d\n%s", code, out)
	}
	r.must("segscan", "key", "retire", "gone")
	if !strings.Contains(readKS(t, ks, "retired"), "\tQw7ErT9yUi3OpLk2") {
		t.Error("retire did not keep the value in retired")
	}
	r.setKey("b", "admin")
	out, _, code = r.run("segscan", "key", "check", "-weak")
	if code != 0 || !strings.Contains(out, "key\tb\tweak forms, not searched by check: bare") || strings.Contains(out, "key\ta\t") {
		t.Errorf("key check -weak: exit %d\n%s", code, out)
	}
	if _, errs, code := r.runIn("Zx81kq9PmW3vT7bR\n", "segscan", "key", "set", "b"); code != 2 || !strings.Contains(errs, "same value") {
		t.Errorf("two keys with one value: exit %d %s", code, errs)
	}
}

func readKS(t *testing.T, ks, name string) string {
	data, err := os.ReadFile(filepath.Join(ks, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCLIRotationAndJournal(t *testing.T) {
	r, ks := newKSRepo(t)
	r.setKey("a", "Ol7dVq2Xz9Lk4Mn8Bv")
	r.setKey("a", "Nw3Ev5Qa8Zx1Rt6Yp4")
	if !strings.Contains(readKS(t, ks, "retired"), "\tOl7dVq2Xz9Lk4Mn8Bv") {
		t.Fatal("old value not retired")
	}
	r.write("nodes/n1/etc/x.conf", "pass=Ol7dVq2Xz9Lk4Mn8Bv\n")
	r.must("segscan", "manifest", "fix")
	out, _, code := r.run("segscan", "check")
	if code != 1 || !strings.Contains(out, "retired value of key a") {
		t.Errorf("retired value: exit %d\n%s", code, out)
	}
	// An interrupted rotation: the journal holds the new files whole. A
	// reader uses it; the next writer finishes it.
	keys := readKS(t, ks, "keys")
	retired := readKS(t, ks, "retired")
	uuid := strings.Split(strings.Split(keys, "\n")[1], "\t")[1]
	j, _ := json.Marshal(journal{"r1", strings.Replace(keys, "Nw3Ev5Qa8Zx1Rt6Yp4", "Th9Rd2Wq7Ek4Zm8Xc5", 1),
		retired + "a\t" + uuid + "\tr1\t2026-01-01T00:00:00Z\tNw3Ev5Qa8Zx1Rt6Yp4\n"})
	os.WriteFile(filepath.Join(ks, "pending"), j, 0o600)
	r.write("nodes/n1/etc/x.conf", "pass=Nw3Ev5Qa8Zx1Rt6Yp4\n")
	out, _, _ = r.run("segscan", "check")
	if !strings.Contains(out, "retired value of key a") {
		t.Errorf("reader ignored the journal:\n%s", out)
	}
	r.must("segscan", "key", "set", "a", "-gen", "16")
	if _, err := os.Stat(filepath.Join(ks, "pending")); !os.IsNotExist(err) {
		t.Error("pending left behind")
	}
	if got := readKS(t, ks, "retired"); !strings.Contains(got, "\tNw3Ev5Qa8Zx1Rt6Yp4") || !strings.Contains(got, "\tTh9Rd2Wq7Ek4Zm8Xc5") {
		t.Errorf("retired after recovery:\n%s", got)
	}
}

func TestCLICheckKnownValues(t *testing.T) {
	r, ks := newKSRepo(t)
	v := "Zx81kq9PmW3vT7bRq2"
	r.setKey("a", v)
	r.setKey("w", "admin")
	sha, _ := applyTransform("sha256", []byte(v))
	b64, _ := applyTransform("b64", []byte(v))
	wsha, _ := applyTransform("sha256", []byte("admin"))
	r.write("nodes/n1/etc/bare.conf", "x = "+v+"\n")
	r.write("nodes/n1/etc/sha.conf", "h: "+string(sha)+"\n")
	r.write("nodes/n1/etc/b64.conf", "\n\nk "+string(b64)+"\n")
	r.write("nodes/n1/etc/weak.conf", "user admin\nlisten 0\n")
	r.write("nodes/n1/etc/weaksha.conf", string(wsha)+"\n")
	r.write("nodes/n1/etc/utf16.bin", string(utf16([]byte("pre "+v), false)))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("inside " + v))
	zw.Close()
	r.write("nodes/n1/etc/self.sh", "#!/bin/sh\nexit 0\n"+gz.String())
	var zb bytes.Buffer
	z := zip.NewWriter(&zb)
	f, _ := z.Create("conf/a.txt")
	f.Write([]byte("k=" + v))
	z.Close()
	r.write("nodes/n1/etc/a.zip", zb.String())
	r.write("nodes/n1/etc/pic.png", "\x89PNG\r\n\x1a\n\x00\x00binary")
	r.write("nodes/n1/etc/ok.png", "\x89PNG\r\n\x1a\n\x00\x00binary2")
	r.write(".sec/allow", "path:nodes/*/etc/ok.png\n")
	// A secret file: its lines and values are searched too.
	os.MkdirAll(filepath.Join(ks, "files"), 0o700)
	os.WriteFile(filepath.Join(ks, "files", "app.env"), []byte("PORT=8080\nAPI_TOKEN=\"Hy7Gt5Rf4Ed3Ws2Qa1\"\n"), 0o600)
	r.write("nodes/n1/etc/other.env", "TOKEN=Hy7Gt5Rf4Ed3Ws2Qa1\nPORT=8080\n")
	r.must("segscan", "manifest", "fix")
	out, _, code := r.run("segscan", "check")
	if code != 1 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	want := []string{
		"nodes/n1/etc/bare.conf\t1\t5\tknown_value\tvalue of key a",
		"nodes/n1/etc/sha.conf\t1\t4\tknown_value\tvalue of key a (form sha256)",
		"nodes/n1/etc/b64.conf\t3\t3\tknown_value\tvalue of key a (form b64)",
		"nodes/n1/etc/weaksha.conf\t1\t1\tknown_value\tvalue of key w (form sha256)",
		"nodes/n1/etc/utf16.bin\t0\t9\tknown_value\tvalue of key a in UTF-16LE",
		"nodes/n1/etc/self.sh\t0\t0\tknown_value\tvalue of key a inside gzip@",
		"nodes/n1/etc/a.zip\t0\t0\tknown_value\tvalue of key a inside conf/a.txt",
		"nodes/n1/etc/pic.png\t0\t0\tknown_value\tbinary file not fully scanned",
		"nodes/n1/etc/other.env\t1\t7\tknown_value\ta value of secret file app.env",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q", w)
		}
	}
	for _, bad := range []string{"weak.conf", "ok.png", v, "Hy7Gt5"} {
		if strings.Contains(out, bad) {
			t.Errorf("unexpected %q in\n%s", bad, out)
		}
	}
	// Committed history: -all finds it once, in the oldest commit.
	r.must("git", "add", "-A")
	r.must("git", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "x")
	out, _, code = r.run("segscan", "check", "-all")
	if code != 1 || strings.Count(out, "bare.conf\t1\t5\tknown_value") != 1 {
		t.Errorf("check -all: exit %d\n%s", code, out)
	}
}

func TestCLITrainGuard(t *testing.T) {
	r, _ := newKSRepo(t)
	r.setKey("a", "Zx81kq9PmW3vT7bRq2")
	r.write("corpus.txt", "some text Zx81kq9PmW3vT7bRq2 more\n")
	if _, errs, code := r.run("segscan", "train", "corpus.txt"); code != 2 || !strings.Contains(errs, "value of key a") {
		t.Errorf("train with a known value: exit %d %s", code, errs)
	}
}

// mkLive makes a fake live system under a temporary directory; import
// maps its absolute paths under the node root as they are.
func mkLive(t *testing.T, dir, p, data string) string {
	full := filepath.Join(dir, p)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestCLIImportExpand(t *testing.T) {
	r, _ := newKSRepo(t)
	v := "Zx81kq9PmW3vT7bRq2"
	r.setKey("ch", v, "-base58")
	sha, _ := applyTransform("sha256", []byte(v))
	live := t.TempDir()
	src := mkLive(t, live, "etc/ch/users.xml", "<password>"+v+"</password>\n<sha>"+string(sha)+"</sha>\nport 9000\n")
	link := filepath.Join(live, "etc/ch/current.xml")
	os.Symlink("users.xml", link)
	os.MkdirAll(filepath.Join(r.dir, "nodes/n1"), 0o755)

	out := r.must("segscan", "import", "-n", "-node", "n1", src, link)
	if !strings.Contains(out, "would import") || !strings.Contains(out, "ch x2") {
		t.Errorf("import -n:\n%s", out)
	}
	rp := "nodes/n1" + src
	if _, err := os.Stat(filepath.Join(r.dir, rp)); !os.IsNotExist(err) {
		t.Fatal("import -n wrote the file")
	}
	r.must("segscan", "import", "-node", "n1", src, link)
	got := r.read(rp)
	ph := placeholderOf(r, "ch")
	if want := "<password>" + ph + "</password>\n<sha>" + strings.TrimSuffix(ph, "!") + ":sha256!</sha>\nport 9000\n"; got != want {
		t.Errorf("imported:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(r.read(".sec/manifest"), rp+"\tf\t0640\t") || !strings.Contains(r.read(".sec/manifest"), "nodes/n1"+link+"\tl\t0777\t") {
		t.Errorf("manifest:\n%s", r.read(".sec/manifest"))
	}
	if out, errs, code := r.run("segscan", "check"); code != 0 {
		t.Errorf("check after import: exit %d\n%s%s", code, out, errs)
	}
	to := filepath.Join(t.TempDir(), "stage")
	out = r.must("segscan", "expand", "-node", "n1", "-to", to)
	if !strings.Contains(out, src) {
		t.Errorf("expand did not list the file:\n%s", out)
	}
	data, err := os.ReadFile(filepath.Join(to, src))
	if err != nil || string(data) != "<password>"+v+"</password>\n<sha>"+string(sha)+"</sha>\nport 9000\n" {
		t.Errorf("expanded: %q %v", data, err)
	}
	if st, _ := os.Stat(filepath.Join(to, src)); st.Mode().Perm() != 0o600 {
		t.Errorf("expanded mode %v", st.Mode())
	}
	if l, err := os.Readlink(filepath.Join(to, link)); err != nil || l != "users.xml" {
		t.Errorf("expanded link %q %v", l, err)
	}
	if out := r.must("segscan", "expand", "-node", "n1", "-to", to); out != "" {
		t.Errorf("second expand changed:\n%s", out)
	}
	// Into the repository: refused.
	if _, _, code := r.run("segscan", "expand", "-node", "n1", "-to", filepath.Join(r.dir, "out")); code != 2 {
		t.Errorf("expand into the repository: exit %d", code)
	}
	// A missing value: reported, nothing written.
	r.must("segscan", "key", "add", "nv")
	r.write(rp, r.read(rp)+placeholderOf(r, "nv")+"\n")
	to2 := filepath.Join(t.TempDir(), "stage")
	if _, errs, code := r.run("segscan", "expand", "-node", "n1", "-to", to2); code != 1 || !strings.Contains(errs, "no value for nv") {
		t.Errorf("missing value: exit %d %s", code, errs)
	}
	if _, err := os.Stat(to2); !os.IsNotExist(err) {
		t.Error("expand wrote despite a missing value")
	}
	// The staging directory through a symlink is refused.
	r.write(rp, strings.Replace(r.read(rp), placeholderOf(r, "nv")+"\n", "", 1))
	alias := filepath.Join(t.TempDir(), "alias")
	os.Symlink(to, alias)
	if _, _, code := r.run("segscan", "expand", "-node", "n1", "-to", alias); code != 2 {
		t.Errorf("expand -to through a symlink: exit %d", code)
	}
}

func TestCLIImportRefusals(t *testing.T) {
	r, _ := newKSRepo(t)
	live := t.TempDir()
	os.MkdirAll(filepath.Join(r.dir, "nodes/n1"), 0o755)
	r.setKey("scoped", "Pq8Wn3Ld6Kj2Hg5Fz9", "-base58", "-scope", "nodes/*/etc/app/**")
	src := mkLive(t, live, "etc/other/x.conf", "k="+"Pq8Wn3Ld6Kj2Hg5Fz9\n")
	if _, errs, code := r.run("segscan", "import", "-node", "n1", src); code != 1 || !strings.Contains(errs, "outside its scope") {
		t.Errorf("out of scope: exit %d %s", code, errs)
	}
	// A short value: listed, and replaced only with -accept.
	r.setKey("short", "on", "-base58")
	src = mkLive(t, live, "etc/s.conf", "ssl on;\nonline=yes\n")
	if _, errs, code := r.run("segscan", "import", "-node", "n1", src); code != 1 || !strings.Contains(errs, "-accept short") || !strings.Contains(errs, src+":1:5") {
		t.Errorf("weak value: exit %d %s", code, errs)
	}
	r.must("segscan", "import", "-node", "n1", "-accept", "short", src)
	if got := r.read("nodes/n1" + src); !strings.HasPrefix(got, "ssl "+placeholderOf(r, "short")+";\n") || !strings.Contains(got, "\nonline=yes") {
		t.Errorf("accepted:\n%s", got)
	}
	// A value that fits several transforms: refused, then -form, then kept.
	r.setKey("alnum", "abcDEF123ghiJKL456")
	src = mkLive(t, live, "etc/a.conf", "x=abcDEF123ghiJKL456\n")
	if _, errs, code := r.run("segscan", "import", "-node", "n1", src); code != 1 || !strings.Contains(errs, "could be any of bare, urlenc, xml") {
		t.Errorf("ambiguous: exit %d %s", code, errs)
	}
	r.must("segscan", "import", "-node", "n1", "-form", src+":1=urlenc", src)
	if got := r.read("nodes/n1" + src); got != "x="+strings.TrimSuffix(placeholderOf(r, "alnum"), "!")+":urlenc!\n" {
		t.Errorf("-form:\n%s", got)
	}
	r.must("segscan", "import", "-node", "n1", src) // the existing placeholder decides now
	// Two keys whose forms overlap.
	r.setKey("k1", "Rt5Yu8Ko2Pa4Sd7Fg1", "-base58")
	r.setKey("k2", "Rt5Yu8Ko2Pa4Sd7Fg1Hj3Kk6", "-base58")
	src = mkLive(t, live, "etc/o.conf", "v=Rt5Yu8Ko2Pa4Sd7Fg1Hj3Kk6\n")
	if _, errs, code := r.run("segscan", "import", "-node", "n1", src); code != 1 || !strings.Contains(errs, "forms of k2 and k1 overlap") {
		t.Errorf("overlap: exit %d %s", code, errs)
	}
	// A secret file goes to the keystore, the manifest gets type s, and
	// expand -to writes it.
	src = mkLive(t, live, "etc/nginx/.htpasswd", "u:$apr1$x$Yh7Tg5Rf4Ed3Ws2Qa1Zx\n")
	r.must("segscan", "import", "-node", "n1", "-secret", "htpasswd", src)
	if _, err := os.Stat(filepath.Join(r.dir, "nodes/n1"+src)); !os.IsNotExist(err) {
		t.Error("secret file copied into the tree")
	}
	if !strings.Contains(r.read(".sec/manifest"), "nodes/n1"+src+"\ts\t0640\t") {
		t.Errorf("manifest:\n%s", r.read(".sec/manifest"))
	}
	r.write("nodes/n1/etc/leak.conf", "u:$apr1$x$Yh7Tg5Rf4Ed3Ws2Qa1Zx\n")
	r.must("segscan", "manifest", "fix")
	if out, _, code := r.run("segscan", "check"); code != 1 || !strings.Contains(out, "a line of secret file htpasswd") {
		t.Errorf("secret file line in the tree: exit %d\n%s", code, out)
	}
	os.Remove(filepath.Join(r.dir, "nodes/n1/etc/leak.conf"))
	r.must("segscan", "manifest", "fix")
	to := filepath.Join(t.TempDir(), "stage")
	r.must("segscan", "expand", "-node", "n1", "-to", to, "/"+strings.TrimPrefix(filepath.Dir(src), "/"))
	if data, _ := os.ReadFile(filepath.Join(to, src)); string(data) != "u:$apr1$x$Yh7Tg5Rf4Ed3Ws2Qa1Zx\n" {
		t.Errorf("expanded secret file: %q", data)
	}
	// A binary file with a value in it belongs in the keystore.
	src = mkLive(t, live, "etc/b.bin", "\x00\x01Rt5Yu8Ko2Pa4Sd7Fg1")
	if _, errs, code := r.run("segscan", "import", "-node", "n1", src); code != 1 || !strings.Contains(errs, "-secret") {
		t.Errorf("binary with a value: exit %d %s", code, errs)
	}
}

func TestCLIImportPreflightAndLinks(t *testing.T) {
	r, _ := newKSRepo(t)
	v := "Zx81kq9PmW3vT7bRq2"
	r.setKey("a", v, "-base58")
	live := t.TempDir()
	// The node directory does not exist yet: import makes it.
	good := mkLive(t, live, "etc/app/good.conf", "k="+v+"\n")
	r.must("segscan", "import", "-node", "n9", good)
	if !strings.Contains(r.read("nodes/n9"+good), placeholderOf(r, "a")) {
		t.Fatal("import into a new node")
	}
	// A symlink in the tree where a directory is needed stops the whole
	// import before anything is written.
	other := mkLive(t, live, "etc/zzz/x.conf", "x=1\n")
	first := mkLive(t, live, "etc/aaa/y.conf", "y=1\n")
	os.MkdirAll(filepath.Join(r.dir, "nodes/n9"+filepath.Dir(filepath.Dir(other))), 0o755)
	os.Symlink(t.TempDir(), filepath.Join(r.dir, "nodes/n9"+filepath.Dir(other)))
	if _, _, code := r.run("segscan", "import", "-node", "n9", first, other); code != 1 {
		t.Errorf("symlinked directory in the tree: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "nodes/n9"+first)); !os.IsNotExist(err) {
		t.Error("import wrote a file before failing")
	}
	os.Remove(filepath.Join(r.dir, "nodes/n9"+filepath.Dir(other)))
	// expand: an entry below a declared link lands where the link points.
	r.write("nodes/n9/etc/real/z.conf", "z="+placeholderOf(r, "a")+"\n")
	os.Symlink("real", filepath.Join(r.dir, "nodes/n9/etc/alias"))
	r.must("segscan", "manifest", "fix")
	m := r.read(".sec/manifest") + "nodes/n9/etc/alias/w.conf\ts\t0600\troot\troot\tsecret=w\n"
	r.write(".sec/manifest", m)
	if _, errs, code := r.run("segscan", "expand", "-node", "n9", "-to", filepath.Join(t.TempDir(), "s")); code != 1 || !strings.Contains(errs, "no secret file w") {
		t.Errorf("missing secret file: exit %d %s", code, errs)
	}
	src := mkLive(t, live, "w", "W=Qa1Ws2Ed3Rf4Tg5Yh6\n")
	r.must("segscan", "import", "-node", "n9", "-secret", "w", src)
	// import -secret added its own entry; drop it again
	var keep []string
	for _, l := range strings.Split(r.read(".sec/manifest"), "\n") {
		if !strings.HasPrefix(l, "nodes/n9"+src+"\t") {
			keep = append(keep, l)
		}
	}
	r.write(".sec/manifest", strings.Join(keep, "\n"))
	to := filepath.Join(t.TempDir(), "s")
	r.must("segscan", "expand", "-node", "n9", "-to", to)
	if data, err := os.ReadFile(filepath.Join(to, "etc/real/w.conf")); err != nil || string(data) != "W=Qa1Ws2Ed3Rf4Tg5Yh6\n" {
		t.Errorf("entry below a declared link: %q %v", data, err)
	}
	if l, _ := os.Readlink(filepath.Join(to, "etc/alias")); l != "real" {
		t.Errorf("link %q", l)
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const planSecret = "Zx81kq9PmW3vT7bRq2Lp"

func TestCLIAllowCommands(t *testing.T) {
	r := newRepo(t)
	r.write("app.yaml", "db:\n  password: "+planSecret+"\n")
	r.write("we*ird.txt", "token = "+planSecret+"x\n")
	r.write("a b.txt", "token = "+planSecret+"y\n")

	// -n writes nothing.
	r.must("segscan", "allow", "line", "-n", "app.yaml:2")
	if strings.Contains(r.read("app.yaml"), "segscan:allow") {
		t.Fatal("-n wrote the file")
	}
	r.must("segscan", "allow", "line", "app.yaml:2")
	r.must("segscan", "allow", "line", "app.yaml:2") // idempotent
	if got := r.read("app.yaml"); got != "db:\n  password: "+planSecret+" # segscan:allow\n" {
		t.Errorf("marker: %q", got)
	}

	r.must("segscan", "allow", "path", "we*ird.txt")
	if _, errs, code := r.run("segscan", "allow", "path", "a b.txt"); code != 1 || !strings.Contains(errs, "white space") {
		t.Errorf("a name with a space: exit %d %s", code, errs)
	}
	r.must("segscan", "allow", "fp", "ABCDEF012345")
	r.must("segscan", "allow", "fp", "abcdef012345") // no duplicate
	allow := r.read(".segscan-allow")
	if strings.Count(allow, "abcdef012345") != 1 || !strings.Contains(allow, `path:/we\*ird.txt`) {
		t.Errorf(".segscan-allow:\n%s", allow)
	}
	// path: lines keep their case: Foo.txt is not foo.txt.
	r.write("Foo.txt", "x\n")
	r.write("foo.txt", "x\n")
	r.must("segscan", "allow", "path", "Foo.txt")
	r.must("segscan", "allow", "path", "foo.txt")
	if allow := r.read(".segscan-allow"); !strings.Contains(allow, "path:/Foo.txt") || !strings.Contains(allow, "path:/foo.txt") {
		t.Errorf("case of path: lines:\n%s", allow)
	}
	if _, _, code := r.run("segscan", "allow", "fp", "nothex"); code != 2 {
		t.Errorf("a bad fingerprint should be refused")
	}
	out, _, _ := r.run("segscan", "scan", "-no-header")
	if strings.Contains(out, "app.yaml") || strings.Contains(out, "we*ird") || !strings.Contains(out, "a b.txt") {
		t.Errorf("scan after the actions:\n%s", out)
	}
}

func TestCLIIgnore(t *testing.T) {
	r := newRepo(t)
	r.write("committed.txt", "token = "+planSecret+"\n")
	r.write("staged.txt", "token = "+planSecret+"\n")
	r.write("new.txt", "token = "+planSecret+"\n")
	r.must("git", "add", "committed.txt")
	r.must("git", "commit", "-q", "-m", "c")
	r.must("git", "add", "staged.txt")

	r.must("segscan", "ignore", "new.txt", "staged.txt")
	if got := r.read(".gitignore"); got != "/new.txt\n/staged.txt\n" {
		t.Errorf(".gitignore: %q", got)
	}
	if out := r.must("git", "ls-files", "staged.txt"); out != "" {
		t.Errorf("staged.txt still in the index")
	}
	if _, err := os.Stat(filepath.Join(r.dir, "staged.txt")); err != nil {
		t.Errorf("staged.txt should stay on disk: %v", err)
	}

	// In HEAD: refused without -history.
	if _, errs, code := r.run("segscan", "ignore", "committed.txt"); code != 1 || !strings.Contains(errs, "HEAD") {
		t.Errorf("committed file: exit %d %s", code, errs)
	}
	_, errs, code := r.run("segscan", "ignore", "-history", "committed.txt")
	if code != 0 || !strings.Contains(errs, "history") || !strings.Contains(r.read(".gitignore"), "/committed.txt") {
		t.Errorf("-history: exit %d %s", code, errs)
	}
	if out, _, _ := r.run("segscan", "scan", "-no-header"); out != "" {
		t.Errorf("scan after ignore: %s", out)
	}
}

// A file changed since the scan keeps its actions.
func TestPlanHashCheck(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.yaml")
	os.WriteFile(f, []byte("k: v\n"), 0o644)
	p := &plan{top: dir, allowPath: filepath.Join(dir, ".segscan-allow"), actions: []action{
		{Kind: actMarker, File: "a.yaml", Line: 1, Hash: fileHash([]byte("k: old\n"))},
		{Kind: actAllowFP, FP: "abcdef012345", File: "a.yaml", Line: 1, Hash: fileHash([]byte("k: old\n"))},
	}}
	r, err := p.apply(false)
	if err != nil || len(r.Done) != 0 || len(r.Skipped) != 1 || !strings.Contains(r.Skipped[0], "changed since the scan") {
		t.Fatalf("%+v %v", r, err)
	}
	if data, _ := os.ReadFile(f); string(data) != "k: v\n" {
		t.Errorf("changed file was written: %q", data)
	}
	if _, err := os.Stat(p.allowPath); err == nil {
		t.Errorf("the allowlist was written for a changed file")
	}
	// With the right hash both apply, and the file keeps its mode.
	os.Chmod(f, 0o600)
	data, _ := os.ReadFile(f)
	for i := range p.actions {
		p.actions[i].Hash = fileHash(data)
	}
	if r, err := p.apply(false); err != nil || len(r.Done) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
}

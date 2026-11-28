package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const planSecret = "Zx81kq9PmW3vT7bRq2Lp"

func TestCLIAllowCommands(t *testing.T) {
	r := newRepo(t)
	r.write("we*ird.txt", "token = "+planSecret+"x\n")
	r.write("a b.txt", "token = "+planSecret+"y\n")

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
	if strings.Contains(out, "we*ird") || !strings.Contains(out, "a b.txt") {
		t.Errorf("scan after the actions:\n%s", out)
	}
}

// fpOf returns the fingerprint of the first finding in file.
func fpOf(t *testing.T, r *repo, file string) string {
	t.Helper()
	out, _, _ := r.run("segscan", "scan", "-json", file)
	var f struct{ FP string }
	if err := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &f); err != nil || f.FP == "" {
		t.Fatalf("no finding in %s: %q %v", file, out, err)
	}
	return f.FP
}

// An fp allowed in some files only: the same value elsewhere is reported.
func TestCLIAllowFPScoped(t *testing.T) {
	r := newRepo(t)
	line := "token = " + planSecret + "\n"
	for _, f := range []string{"nodes/n1/nginx.conf", "nodes/n2/nginx.conf", "app/x.conf", "app/y.conf"} {
		r.write(f, line)
	}
	fp := fpOf(t, r, "app/x.conf")

	r.must("segscan", "allow", "fp", "-n", "-file", "app/x.conf", fp)
	if _, err := os.Stat(filepath.Join(r.dir, ".segscan-allow")); err == nil {
		t.Fatal("-n wrote")
	}
	r.must("segscan", "allow", "fp", "-file", "app/x.conf", fp)
	r.must("segscan", "allow", "fp", fp, "-path", "/nodes/*/nginx.conf") // flags after the operands
	r.must("segscan", "allow", "fp", "-file", "app/x.conf", fp)          // no duplicate
	allow := r.read(".segscan-allow")
	if strings.Count(allow, "path:/app/x.conf") != 1 || !strings.Contains(allow, fp+" path:/nodes/*/nginx.conf") {
		t.Errorf(".segscan-allow:\n%s", allow)
	}
	out, _, _ := r.run("segscan", "scan", "-no-header")
	if strings.Contains(out, "nodes/") || strings.Contains(out, "app/x.conf") || !strings.Contains(out, "app/y.conf") {
		t.Errorf("scan:\n%s", out)
	}
	// From another directory, the path is still the repository path.
	// The allowlist is the one at the top, from here too.
	cmd := exec.Command(filepath.Join(r.bin, "segscan"), "scan", "-no-header", "x.conf", "y.conf")
	cmd.Dir, cmd.Env = filepath.Join(r.dir, "app"), r.env
	if out, err := cmd.CombinedOutput(); strings.Contains(string(out), "x.conf") || !strings.Contains(string(out), "y.conf") {
		t.Errorf("scan from app/: %v\n%s", err, out)
	}

	// A bare fp line covers the scoped ones.
	r.must("segscan", "allow", "fp", fp)
	r.must("segscan", "allow", "fp", "-file", "app/y.conf", fp)
	if strings.Contains(r.read(".segscan-allow"), "path:/app/y.conf") {
		t.Errorf("a scoped line after a bare one:\n%s", r.read(".segscan-allow"))
	}
	if out, _, _ := r.run("segscan", "scan", "-no-header"); out != "" {
		t.Errorf("scan after the bare fp: %s", out)
	}

	if _, errs, code := r.run("segscan", "allow", "fp", "-path", "/a b", fp); code != 1 || !strings.Contains(errs, "white space") {
		t.Errorf("a glob with a space: exit %d %s", code, errs)
	}
	if _, _, code := r.run("segscan", "allow", "fp", "-path", "/x", "-file", "app/y.conf", fp); code == 0 {
		t.Errorf("-path and -file together should be refused")
	}
	if _, errs, code := r.run("segscan", "allow", "fp", "-file", "nodes", fp); code == 0 || !strings.Contains(errs, "a directory") {
		t.Errorf("-file with a directory: exit %d %s", code, errs)
	}

	// Run from a subdirectory: the allowlist at the top is written.
	cmd = exec.Command(filepath.Join(r.bin, "segscan"), "allow", "fp", "-file", "y.conf", fp)
	cmd.Dir, cmd.Env = filepath.Join(r.dir, "app"), r.env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("allow from app/: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "app", ".segscan-allow")); err == nil {
		t.Errorf("allow from app/ wrote app/.segscan-allow")
	}
}

func TestAllowListScoped(t *testing.T) {
	a := &allowList{fp: map[string]bool{}}
	a.add([]byte("aaaaaaaaaaaa path:/nodes/*/nginx.conf path:secrets/  # two globs\n" +
		"bbbbbbbbbbbb pth:/x\n" + // a typo: the line counts for nothing
		"cccccccccccc path:\n" +
		"DDDDDDDDDDDD path:*.yaml\n"))
	for _, c := range []struct {
		fp, file string
		want     bool
	}{
		{"aaaaaaaaaaaa", "nodes/n1/nginx.conf", true},
		{"aaaaaaaaaaaa", "nodes/n1/sub/nginx.conf", false},
		{"aaaaaaaaaaaa", "secrets/a/b.txt", true},
		{"aaaaaaaaaaaa", "other.txt", false},
		{"aaaaaaaaaaaa", "", false},
		{"bbbbbbbbbbbb", "x", false},
		{"bbbbbbbbbbbb", "other", false},
		{"cccccccccccc", "x", false},
		{"dddddddddddd", "deep/a.yaml", true},
	} {
		if got := a.allowFP(c.fp, c.file); got != c.want {
			t.Errorf("allowFP(%s, %q) = %v", c.fp, c.file, got)
		}
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

	// A pathspec character in the name: only that file leaves the index.
	r.write("foo?.txt", "x\n")
	r.write("foo1.txt", "x\n")
	r.must("git", "add", "foo?.txt", "foo1.txt")
	r.must("segscan", "ignore", "foo?.txt")
	if out := r.must("git", "ls-files", "foo1.txt"); out != "foo1.txt\n" {
		t.Errorf("ignore foo?.txt took foo1.txt out of the index too")
	}
	r.must("git", "rm", "-q", "--cached", "foo1.txt")
	r.write(".gitignore", "")

	// Staged content different from both the file and HEAD: refused
	// before .gitignore changes.
	r.write("part.txt", "v1\n")
	r.must("git", "add", "part.txt")
	r.must("git", "commit", "-q", "-m", "p", "--", "part.txt")
	r.write("part.txt", "v2\n")
	r.must("git", "add", "part.txt")
	r.write("part.txt", "v3\n")
	if _, errs, code := r.run("segscan", "ignore", "-history", "part.txt"); code != 1 || !strings.Contains(errs, "staged version") {
		t.Errorf("partly staged: exit %d %s", code, errs)
	}
	if strings.Contains(r.read(".gitignore"), "part.txt") {
		t.Errorf(".gitignore changed for a refused file")
	}

	// A tracked directory gone from the working tree: still a directory.
	r.write("gone/y.txt", "y\n")
	r.must("git", "add", "gone/y.txt")
	r.must("git", "commit", "-q", "-m", "g", "--", "gone/y.txt")
	os.RemoveAll(filepath.Join(r.dir, "gone"))
	if _, errs, code := r.run("segscan", "ignore", "-history", "gone"); code != 1 || !strings.Contains(errs, "a directory") {
		t.Errorf("deleted directory: exit %d %s", code, errs)
	}
	// A directory: refused before .gitignore changes.
	r.write("dir/x.txt", "x\n")
	if _, errs, code := r.run("segscan", "ignore", "-history", "dir"); code != 1 || !strings.Contains(errs, "a directory") {
		t.Errorf("directory: exit %d %s", code, errs)
	}
	if strings.Contains(r.read(".gitignore"), "dir") {
		t.Errorf(".gitignore changed for a directory")
	}

	r.must("segscan", "ignore", "new.txt", "-n")
	if _, err := os.Stat(filepath.Join(r.dir, "-n")); err == nil || strings.Contains(r.read(".gitignore"), "new.txt") {
		t.Fatalf("ignore FILE -n wrote")
	}
	r.must("segscan", "ignore", "new.txt", "staged.txt", "staged.txt") // twice: once
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
		{Kind: actAllowFP, FP: "abcdef012345", File: "a.yaml", Line: 1, Hash: fileHash([]byte("k: old\n"))},
		{Kind: actAllowFP, FP: "abcdef012346", File: "a.yaml", Line: 1, Glob: "/a.yaml", Hash: fileHash([]byte("k: old\n"))},
	}}
	r, err := p.apply(false)
	if err != nil || len(r.Done) != 0 || len(r.Skipped) != 1 || !strings.Contains(r.Skipped[0], "changed since the scan") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := os.Stat(p.allowPath); err == nil {
		t.Errorf("the allowlist was written for a changed file")
	}
	// With the right hash both apply.
	data, _ := os.ReadFile(f)
	for i := range p.actions {
		p.actions[i].Hash = fileHash(data)
	}
	if r, err := p.apply(false); err != nil || len(r.Done) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if allow, _ := os.ReadFile(p.allowPath); !strings.Contains(string(allow), "abcdef012346 path:/a.yaml  # a.yaml:1") {
		t.Errorf("allowlist: %s", allow)
	}
	if data, _ := os.ReadFile(f); string(data) != "k: v\n" {
		t.Errorf("the file itself was written: %q", data)
	}
}

// .gitignore cannot take the rule: the file stays in the index.
func TestCLIIgnoreGitignoreNotFile(t *testing.T) {
	r := newRepo(t)
	r.write("new.txt", "token = "+planSecret+"\n")
	r.must("git", "add", "new.txt")
	os.Mkdir(filepath.Join(r.dir, ".gitignore"), 0o755)
	if _, errs, code := r.run("segscan", "ignore", "new.txt"); code == 0 || !strings.Contains(errs, "regular file") {
		t.Errorf("exit %d %s", code, errs)
	}
	if out := r.must("git", "ls-files", "new.txt"); out != "new.txt\n" {
		t.Errorf("new.txt left the index without a rule")
	}
}

// The saved index entry comes back as it was, staged content included.
func TestRestoreIndex(t *testing.T) {
	r := newRepo(t)
	r.write("a,b.txt", "v1\n")
	r.must("git", "add", "a,b.txt")
	r.write("a,b.txt", "v2\n")
	before := r.must("git", "ls-files", "-s", "-z", "--", "a,b.txt")
	r.must("git", "update-index", "--force-remove", "--", "a,b.txt")
	if err := (&plan{top: r.dir}).restoreIndex([]byte(before)); err != nil {
		t.Fatal(err)
	}
	if after := r.must("git", "ls-files", "-s", "-z", "--", "a,b.txt"); after != before {
		t.Errorf("index %q, want %q", after, before)
	}
}

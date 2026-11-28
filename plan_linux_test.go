//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The allowlist written is the one the scan reads: .sec/allow in a .sec/
// repository.
func TestCLIAllowSecRepo(t *testing.T) {
	r, _ := newKSRepo(t)
	r.must("segscan", "allow", "fp", "abcdef012345")
	if !strings.Contains(r.read(".sec/allow"), "abcdef012345") {
		t.Errorf(".sec/allow: %q", r.read(".sec/allow"))
	}
	if _, err := os.Stat(filepath.Join(r.dir, ".segscan-allow")); err == nil {
		t.Errorf(".segscan-allow should not be created in a .sec/ repository")
	}
}

// A symlinked .sec/ is never written through, nor a symlinked directory
// holding a file to mark.
func TestCLIAllowSymlinkedDirs(t *testing.T) {
	r := newRepo(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(r.dir, ".sec")); err != nil {
		t.Skip(err)
	}
	// secRoot needs .sec to be a directory: here the allowlist is named.
	_, errs, code := r.run("segscan", "allow", "fp", "-allow", ".sec/allow", "abcdef012345")
	if code != 2 || !strings.Contains(errs, "symlink") {
		t.Errorf("allow through a symlinked .sec: exit %d %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(outside, "allow")); err == nil {
		t.Errorf("wrote outside the repository")
	}
	os.WriteFile(filepath.Join(outside, "a.yaml"), []byte("k: v\n"), 0o644)
	os.Symlink(outside, filepath.Join(r.dir, "conf"))
	if _, errs, code := r.run("segscan", "allow", "line", "conf/a.yaml:1"); code == 0 || !strings.Contains(errs, "symlink") {
		t.Errorf("marker through a symlinked directory: exit %d %s", code, errs)
	}
	if data, _ := os.ReadFile(filepath.Join(outside, "a.yaml")); string(data) != "k: v\n" {
		t.Errorf("marked a file outside the repository: %q", data)
	}
}

// When git rm --cached refuses (here: a file outside the sparse-checkout
// cone), .gitignore stays as it was.
func TestCLIIgnoreRmRefused(t *testing.T) {
	r := newRepo(t)
	r.write("in/a.txt", "a\n")
	r.write("out/b.txt", "b\n")
	r.must("git", "add", "-A")
	r.must("git", "commit", "-q", "-m", "c")
	if _, _, code := r.run("git", "sparse-checkout", "set", "--cone", "in"); code != 0 {
		t.Skip("no sparse-checkout")
	}
	// out/b.txt is refused before anything changes for it; in/a.txt goes
	// on, out of the index and with its rule.
	_, errs, code := r.run("segscan", "ignore", "-history", "in/a.txt", "out/b.txt")
	if code != 1 || !strings.Contains(errs, "sparse") {
		t.Errorf("exit %d %s", code, errs)
	}
	if got := r.read(".gitignore"); got != "/in/a.txt\n" {
		t.Errorf(".gitignore: %q", got)
	}
	if out := r.must("git", "ls-files"); out != "out/b.txt\n" {
		t.Errorf("index: %q", out)
	}
}

// A symlinked .gitignore (a shared ignore file) is not replaced by a copy.
func TestCLIIgnoreSymlinkedGitignore(t *testing.T) {
	r := newRepo(t)
	shared := filepath.Join(t.TempDir(), "shared-ignore")
	os.WriteFile(shared, []byte("*.log\n"), 0o644)
	if err := os.Symlink(shared, filepath.Join(r.dir, ".gitignore")); err != nil {
		t.Fatal(err)
	}
	r.write("new.txt", "x\n")
	if _, errs, code := r.run("segscan", "ignore", "new.txt"); code == 0 || !strings.Contains(errs, "regular file") {
		t.Errorf("exit %d %s", code, errs)
	}
	if st, err := os.Lstat(filepath.Join(r.dir, ".gitignore")); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf(".gitignore is no longer a symlink")
	}
	if data, _ := os.ReadFile(shared); string(data) != "*.log\n" {
		t.Errorf("shared file: %q", data)
	}
}

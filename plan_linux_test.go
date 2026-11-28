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

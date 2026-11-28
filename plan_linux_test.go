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

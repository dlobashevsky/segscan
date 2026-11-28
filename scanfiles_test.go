package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func scannedFiles(t *testing.T, r *repo, dir string, args ...string) []string {
	t.Helper()
	saved := r.dir
	r.dir = filepath.Join(r.dir, dir)
	out, errs, code := r.run("segscan", append([]string{"scan", "-json"}, args...)...)
	r.dir = saved
	if code == 2 {
		t.Fatalf("scan %v: %s", args, errs)
	}
	files := []string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" {
			continue
		}
		var f struct{ File string }
		if err := json.Unmarshal([]byte(l), &f); err != nil {
			t.Fatal(l, err)
		}
		files = append(files, f.File)
	}
	sort.Strings(files)
	return files
}

func TestCLIScanFileSet(t *testing.T) {
	r := newRepo(t)
	const secret = "token = Zx81kq9PmW3vT7bRq2Lp\n"
	for _, f := range []string{"tracked.txt", "untracked.txt", "ignored.txt", "d/e.txt", ".sec/words.txt"} {
		r.write(f, secret)
	}
	r.write(".gitignore", "ignored.txt\n")
	r.must("git", "add", "tracked.txt", ".gitignore")
	outside := filepath.Join(t.TempDir(), "o.txt")
	if err := os.WriteFile(outside, []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		dir  string
		args []string
		want []string
	}{
		// What git would commit: no ignored files, no .sec/.
		{"", nil, []string{"d/e.txt", "tracked.txt", "untracked.txt"}},
		{"", []string{"."}, []string{"d/e.txt", "tracked.txt", "untracked.txt"}},
		{"", []string{"d"}, []string{"d/e.txt"}},
		// A file named explicitly is read even if ignored.
		{"", []string{"ignored.txt"}, []string{"ignored.txt"}},
		// -scanall walks everything.
		{"", []string{"-scanall"}, []string{".sec/words.txt", "d/e.txt", "ignored.txt", "tracked.txt", "untracked.txt"}},
		{"", []string{"-scanall", "d"}, []string{"d/e.txt"}},
		// Outside the repository paths are walked as they are.
		{"", []string{outside}, []string{outside}},
		// From a subdirectory: its part of the set, relative names.
		{"d", nil, []string{"e.txt"}},
		{"d", []string{".."}, []string{"../tracked.txt", "../untracked.txt", "e.txt"}},
	} {
		if got := scannedFiles(t, r, c.dir, c.args...); !reflect.DeepEqual(got, c.want) {
			t.Errorf("scan %v in %q: got %v, want %v", c.args, c.dir, got, c.want)
		}
	}
}

func TestCLIScanOutsideGit(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("token = Zx81kq9PmW3vT7bRq2Lp\n"), 0o644)
	r := &repo{t: t, dir: dir, bin: segscanBin(t), env: append(os.Environ(), "SEGSCAN_MODEL=", "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))}
	if got := scannedFiles(t, r, "", "."); !reflect.DeepEqual(got, []string{"a.txt"}) {
		t.Errorf("outside git: %v", got)
	}
	if _, errs, code := r.run("segscan", "scan"); code != 2 || !strings.Contains(errs, "not a git repository") {
		t.Errorf("no paths outside git: exit %d %s", code, errs)
	}
}

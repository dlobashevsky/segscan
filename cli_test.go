package main

// End-to-end tests of the .sec/ commands: build the binary, run it in
// temporary git repositories, with the hooks installed by init.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	binOnce sync.Once
	binDir  string
	binErr  error
)

func segscanBin(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "segscan-bin")
		if binErr == nil {
			out, err := exec.Command("go", "build", "-o", filepath.Join(binDir, "segscan"), ".").CombinedOutput()
			if err != nil {
				binErr = err
				binDir = string(out)
			}
		}
	})
	if binErr != nil {
		t.Fatalf("build: %v %s", binErr, binDir)
	}
	return binDir
}

type repo struct {
	t   *testing.T
	dir string
	bin string
	env []string
}

func newRepo(t *testing.T) *repo {
	bin := segscanBin(t)
	dir := t.TempDir()
	r := &repo{t: t, dir: dir, bin: bin, env: append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+dir, "GIT_CONFIG_NOSYSTEM=1", "SEGSCAN_MODEL=", "SEGSCAN_KEYSTORE=",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")}
	r.must("git", "init", "-q", "-b", "main")
	return r
}

// run returns stdout, stderr and the exit code.
func (r *repo) run(name string, args ...string) (string, string, int) {
	r.t.Helper()
	if name == "segscan" {
		name = filepath.Join(r.bin, "segscan")
	}
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env = r.dir, r.env
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		r.t.Fatalf("%s %v: %v", name, args, err)
	}
	return out.String(), errb.String(), code
}

func (r *repo) must(name string, args ...string) string {
	r.t.Helper()
	out, errs, code := r.run(name, args...)
	if code != 0 {
		r.t.Fatalf("%s %v: exit %d\n%s%s", name, args, code, out, errs)
	}
	return out
}

func (r *repo) write(p, data string) {
	r.t.Helper()
	full := filepath.Join(r.dir, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *repo) read(p string) string {
	r.t.Helper()
	data, err := os.ReadFile(filepath.Join(r.dir, p))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(data)
}

// checks returns the "check" column of segscan check output, one per finding.
func checks(out string) []string {
	var res []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 6 && f[4] != "check" {
			res = append(res, f[4]+": "+f[5])
		}
	}
	return res
}

func TestCLIConfigRepository(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	if hp := strings.TrimSpace(r.must("git", "config", "core.hooksPath")); hp != ".sec/hooks" {
		t.Fatalf("core.hooksPath = %q", hp)
	}
	ph := strings.TrimSpace(r.must("segscan", "key", "add", "ch_sts", "-scope", "nodes/*/etc/nginx/**"))
	if good, bad := parsePlaceholders([]byte(ph)); len(good) != 1 || len(bad) != 0 || good[0].Name != "ch_sts" {
		t.Fatalf("key add printed %q", ph)
	}
	if _, _, code := r.run("segscan", "key", "add", "ch_sts"); code != 2 {
		t.Errorf("duplicate key add: exit %d", code)
	}
	b64 := strings.TrimSuffix(ph, "!") + ":b64!"
	r.write("nodes/n1/etc/nginx/sts.conf", "proxy_set_header X-ClickHouse-key "+ph+";\nproxy_set_header Authorization \"Basic "+b64+"\";\n")
	r.write("nodes/n1/etc/nginx/.htpasswd", "dima:$apr1$x\n")
	r.write(".sec/manifest", manifestHeader+"nodes/n1/etc\td\t0750\troot\tadm\n")
	_, errs, _ := r.run("segscan", "manifest", "fix")
	if !strings.Contains(errs, "+ nodes/n1/etc/nginx/sts.conf\tf 0640 root:adm") || !strings.Contains(errs, "not added: matches forbid") {
		t.Errorf("manifest fix:\n%s", errs)
	}
	r.must("rm", "nodes/n1/etc/nginx/.htpasswd")
	if out, errs, code := r.run("segscan", "check"); code != 0 {
		t.Fatalf("check of a clean tree: exit %d\n%s%s", code, out, errs)
	}

	// The statistical scanner skips the placeholders inside .sec/.
	r.must("git", "add", "-A")
	if out, _, code := r.run("segscan", "scan", "-no-header", "nodes"); code != 0 {
		t.Errorf("scan reported placeholders:\n%s", out)
	}
	if out, _, code := r.run("segscan", "scan", "-no-header", "-skip-uuids=false", "nodes"); code != 1 || strings.Count(out, "\n") != 2 {
		t.Errorf("scan -skip-uuids=false: exit %d\n%s", code, out)
	}

	// The pre-commit hook passes a clean commit and only warns about a random string.
	r.write("nodes/n1/etc/nginx/x.conf", "secret 5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5q;\n")
	r.must("segscan", "manifest", "fix")
	r.must("git", "add", "-A")
	if _, errs, code := r.run("git", "commit", "-q", "-m", "one"); code != 0 || !strings.Contains(errs, "not blocking") {
		t.Fatalf("first commit: exit %d\n%s", code, errs)
	}

	// Every blocking check.
	other := "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	r.write("nodes/n1/etc/telegraf/t.conf", "dsn = clickhouse://u:"+ph+"@h\nx = "+placeholderText("nope", other)+"\ny = !SECKEY_bad!\nz = "+
		strings.TrimSuffix(ph, "!")+":rot13!\nw = "+placeholderText("ch_sts", other)+"\n")
	r.write("nodes/n1/etc/ssl/k.pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n")
	r.write("nodes/n1/etc/nginx/.htpasswd", "dima:$apr1$x\n")
	r.write(".sec/keys/keys", "x\n")
	r.write(".sec/config", r.read(".sec/config")+"keystore = vault\n")
	r.write("vault/keys", "x\n")
	r.must("git", "add", "-A", "-f")
	out, _, code := r.run("segscan", "check", "-staged")
	got := strings.Join(checks(out), "\n") + "\n" + out
	for _, want := range []string{
		"names: key ch_sts used outside its scope",
		"names: unknown key nope",
		"grammar: malformed placeholder: no uuid after the name",
		"grammar: unknown transform rot13",
		"names: uuid of ch_sts does not match",
		"private_key: -----BEGIN PRIVATE KEY-----",
		"forbidden: matches forbid = .htpasswd*",
		"forbidden: the keystore must not be in the repository",
		"vault/keys\t0\t0\tforbidden",
		"manifest: no manifest entry",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("check -staged: missing %q", want)
		}
	}
	if code != 1 {
		t.Errorf("check -staged: exit %d", code)
	}
	if _, _, code := r.run("git", "commit", "-q", "-m", "bad"); code == 0 {
		t.Fatal("the pre-commit hook let a bad commit through")
	}

	// -range and -all: a problem is reported once, at the oldest commit that has it.
	r.must("git", "reset", "-q")
	r.must("git", "add", "nodes/n1/etc/telegraf/t.conf")
	r.must("git", "commit", "-q", "--no-verify", "-m", "bad, bypassing the hook")
	bad := strings.TrimSpace(r.must("git", "rev-parse", "HEAD"))
	r.write("README.md", "x\n")
	r.must("git", "add", "README.md")
	r.must("git", "commit", "-q", "--no-verify", "-m", "later")
	out, _, code = r.run("segscan", "check", "-all")
	if code != 1 || strings.Count(out, "uuid of ch_sts does not match") != 1 || !strings.Contains(out, bad+"\tnodes/n1/etc/telegraf/t.conf") {
		t.Errorf("check -all: exit %d\n%s", code, out)
	}
	if _, _, code := r.run("segscan", "check", "-range", "HEAD~1..HEAD"); code != 1 {
		t.Errorf("check -range of a commit that keeps the problem: exit %d", code)
	}
	if out, _, code := r.run("segscan", "check", "-range", "HEAD~2"); code != 0 {
		t.Errorf("check -range of the first commit: exit %d\n%s", code, out)
	}

	// A private key under .sec/ is found too; the allowlist is the one of
	// the checked snapshot, so an unstaged fingerprint does not hide it.
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----"
	r.write(".sec/leak.pem", pem+"\nb3Bl\n-----END OPENSSH PRIVATE KEY-----\n")
	r.must("git", "add", ".sec/leak.pem")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, ".sec/leak.pem\t1\t1\tprivate_key") {
		t.Errorf("private key under .sec/: exit %d\n%s", code, out)
	}
	fp := (&Finding{Text: pem}).FP()
	allowBefore := r.read(".sec/allow")
	r.write(".sec/allow", allowBefore+fp+"\n")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, "private_key") {
		t.Errorf("an unstaged allowlist entry hid a staged key: exit %d\n%s", code, out)
	}
	if out, _, _ := r.run("segscan", "check"); strings.Contains(out, ".sec/leak.pem") {
		t.Errorf("the working tree allowlists the key, but it was reported:\n%s", out)
	}
	r.write(".sec/allow", allowBefore)
	r.must("git", "rm", "-q", "--cached", ".sec/leak.pem")
	r.must("rm", ".sec/leak.pem")

	// A broken .sec/config in the working tree does not stop checking the
	// history; it is only a finding of the working tree.
	cfg := r.read(".sec/config")
	r.write(".sec/config", cfg+"colour = red\n")
	if out, _, code := r.run("segscan", "check", "-range", "HEAD~2"); code != 0 {
		t.Errorf("check -range with a broken working-tree config: exit %d\n%s", code, out)
	}
	if out, _, code := r.run("segscan", "check"); code != 1 || !strings.Contains(out, "\tconfig\t") {
		t.Errorf("check of a broken working-tree config: exit %d\n%s", code, out)
	}
	r.write(".sec/config", cfg)

	// The pre-push hook blocks the push of the bad commits.
	remote := t.TempDir()
	r.must("git", "init", "-q", "--bare", remote)
	r.must("git", "remote", "add", "origin", remote)
	if _, errs, code := r.run("git", "push", "-q", "origin", "main"); code == 0 || !strings.Contains(errs, "problem(s)") {
		t.Errorf("pre-push let the bad commits through: exit %d\n%s", code, errs)
	}

	// key list and key rm.
	list := r.must("segscan", "key", "list", "-no-header")
	if !strings.HasPrefix(list, "ch_sts\t") {
		t.Errorf("key list: %q", list)
	}
	if _, _, code := r.run("segscan", "key", "rm", "ch_sts"); code != 2 {
		t.Errorf("key rm of a used key: exit %d", code)
	}
	r.must("segscan", "key", "add", "unused")
	r.must("segscan", "key", "rm", "unused")
	r.must("segscan", "key", "add", "own", "-base58")
	if list := r.must("segscan", "key", "list", "-no-header"); !strings.Contains(list, "own\t") || !strings.Contains(list, "\tbase58\t") {
		t.Errorf("key list with flags: %q", list)
	}
	if names := r.read(".sec/names"); !strings.Contains(names, "\t\tbase58\n") {
		t.Errorf("names with flags: %q", names)
	}
}

func TestCLIWithoutSec(t *testing.T) {
	r := newRepo(t)
	r.write("a.conf", "id = 3fa85f64-5717-4562-b3fc-2c963f66afa6\n")
	r.must("git", "add", "a.conf")
	// No .sec/: UUIDs are scored as before, -skip-uuids hides them.
	if _, _, code := r.run("segscan", "scan"); code != 1 {
		t.Errorf("scan without .sec/: exit %d, want 1", code)
	}
	if out, _, code := r.run("segscan", "scan", "-skip-uuids"); code != 0 {
		t.Errorf("scan -skip-uuids: exit %d\n%s", code, out)
	}
	if _, errs, code := r.run("segscan", "check"); code != 2 || !strings.Contains(errs, "segscan init") {
		t.Errorf("check without .sec/: exit %d %s", code, errs)
	}
}

func TestCLIHistoryBeforeSec(t *testing.T) {
	r := newRepo(t)
	// A placeholder committed before .sec/ existed: only grammar, forbidden
	// paths and private keys apply to that commit.
	r.write("nodes/n1/etc/a.conf", "k = "+placeholderText("old", testUUID)+"\n")
	r.must("git", "add", "-A")
	r.must("git", "commit", "-q", "-m", "before .sec/")
	r.must("segscan", "init")
	if out, _, code := r.run("segscan", "check", "-all"); code != 0 {
		t.Errorf("check -all of a commit before .sec/: exit %d\n%s", code, out)
	}
	if out, _, code := r.run("segscan", "check"); code != 1 || !strings.Contains(out, "unknown key old") {
		t.Errorf("working tree with .sec/: exit %d\n%s", code, out)
	}
}

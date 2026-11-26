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
		"HOME="+t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "SEGSCAN_MODEL=", "SEGSCAN_KEYSTORE=",
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

	// The hook follows the staged .sec/config: hook_scan = block in the index
	// blocks even if the working tree says off.
	cfgText := r.read(".sec/config")
	r.write(".sec/config", strings.Replace(cfgText, "hook_scan   = warn", "hook_scan   = block", 1))
	r.must("git", "add", ".sec/config")
	r.write(".sec/config", strings.Replace(cfgText, "hook_scan   = warn", "hook_scan   = off", 1))
	r.write("nodes/n1/etc/nginx/y.conf", "secret 7hQmWvKx3NpZr9bTfYs2LcJd8GaEuV4o;\n")
	r.must("segscan", "manifest", "fix")
	r.must("git", "add", "nodes", ".sec/manifest")
	if _, errs, code := r.run("segscan", "hook"); code != 1 || !strings.Contains(errs, "commit blocked") {
		t.Errorf("hook followed the unstaged hook_scan = off: exit %d\n%s", code, errs)
	}
	r.write(".sec/config", cfgText)
	r.must("git", "add", ".sec/config")
	r.must("git", "rm", "-q", "--cached", "nodes/n1/etc/nginx/y.conf")
	r.must("rm", "nodes/n1/etc/nginx/y.conf")
	r.must("segscan", "manifest", "fix")
	r.must("git", "add", ".sec/manifest")

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

	// Submodules (gitlinks) keep their paths: forbidden paths and node roots
	// are checked for them too.
	head := strings.TrimSpace(r.must("git", "rev-parse", "HEAD"))
	r.must("git", "update-index", "--add", "--cacheinfo", "160000,"+head+",.sec/keys")
	r.must("git", "update-index", "--add", "--cacheinfo", "160000,"+head+",nodes/n1/etc/sub")
	out, _, code = r.run("segscan", "check", "-staged")
	if code != 1 || !strings.Contains(out, ".sec/keys\t0\t0\tforbidden") || !strings.Contains(out, "nodes/n1/etc/sub\t0\t0\tmanifest\ta submodule") {
		t.Errorf("gitlinks in the index: exit %d\n%s", code, out)
	}
	r.must("git", "rm", "-q", "-f", "--cached", ".sec/keys", "nodes/n1/etc/sub")

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

	// The pre-push hook blocks the push of the bad commits, also when another
	// remote already has them: only the refs of the target remote count.
	otherRemote := t.TempDir()
	r.must("git", "init", "-q", "--bare", otherRemote)
	r.must("git", "remote", "add", "other", otherRemote)
	r.must("git", "push", "-q", "--no-verify", "other", "main")
	r.must("git", "fetch", "-q", "other")
	remote := t.TempDir()
	r.must("git", "init", "-q", "--bare", remote)
	r.must("git", "remote", "add", "origin", remote)
	if _, errs, code := r.run("git", "push", "-q", "origin", "main"); code == 0 || !strings.Contains(errs, "problem(s)") {
		t.Errorf("pre-push let the bad commits through: exit %d\n%s", code, errs)
	}
	if _, errs, code := r.run("git", "push", "-q", remote, "main"); code == 0 || !strings.Contains(errs, "problem(s)") {
		t.Errorf("pre-push to a URL let the bad commits through: exit %d\n%s", code, errs)
	}
	// Deleting a ref has nothing to check.
	if _, errs, code := r.run("git", "push", "-q", "other", ":main"); code != 0 {
		t.Errorf("pre-push blocked a deletion: exit %d\n%s", code, errs)
	}
	// A stale remote-tracking ref is not trusted: origin had the bad commits
	// on a branch that was deleted on the server, but refs/remotes/origin/old
	// is still here. Pushing them again under a new name must be checked.
	r.must("git", "push", "-q", "--no-verify", "origin", "main:old")
	r.must("git", "fetch", "-q", "origin")
	r.must("git", "-C", remote, "branch", "-q", "-D", "old")
	if _, errs, code := r.run("git", "push", "-q", "origin", "main:new"); code == 0 || !strings.Contains(errs, "problem(s)") {
		t.Errorf("pre-push trusted a stale remote-tracking ref: exit %d\n%s", code, errs)
	}
	// What the destination advertises now does count as checked: after the
	// bad commits are on origin (pushed with --no-verify), pushing a clean
	// commit on top checks only that commit.
	r.must("git", "push", "-q", "--no-verify", "origin", "main")
	r.must("git", "checkout", "-q", "-b", "clean", "HEAD")
	r.must("git", "rm", "-q", "nodes/n1/etc/telegraf/t.conf")
	r.must("git", "commit", "-q", "--no-verify", "-m", "fix")
	if _, errs, code := r.run("git", "push", "-q", "origin", "clean"); code != 0 {
		t.Errorf("pre-push of a clean commit on advertised history: exit %d\n%s", code, errs)
	}
	// A tag on a blob pushes the blob, which check cannot read as a commit:
	// refused with a clear message, not a bad-object error, and not let through.
	blob := strings.TrimSpace(r.must("git", "hash-object", "-w", "nodes/n1/etc/nginx/x.conf"))
	r.must("git", "tag", "blobtag", blob)
	if _, errs, code := r.run("git", "push", "-q", "origin", "refs/tags/blobtag"); code == 0 || !strings.Contains(errs, "is not a commit") {
		t.Errorf("pre-push of a tag on a blob: exit %d\n%s", code, errs)
	}
	// An annotated tag on a commit is checked like the commit.
	r.must("git", "tag", "-a", "-m", "v", "v1", "clean")
	if _, errs, code := r.run("git", "push", "-q", "origin", "refs/tags/v1"); code != 0 {
		t.Errorf("pre-push of an annotated tag on a clean commit: exit %d\n%s", code, errs)
	}
	r.must("git", "checkout", "-q", "main")

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

func TestCLISecFilesAndKeystore(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	// A symlink in place of .sec/config must not silently bring back the
	// defaults (and drop forbid = forbidden.txt).
	r.write("real.conf", "forbid = forbidden.txt\n")
	r.must("rm", ".sec/config")
	r.must("ln", "-s", "../real.conf", ".sec/config")
	r.write("forbidden.txt", "x\n")
	r.must("git", "add", "-A")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, ".sec/config\t0\t0\tconfig\tmust be a regular file") {
		t.Errorf("symlinked .sec/config: exit %d\n%s", code, out)
	}
	if _, errs, code := r.run("segscan", "hook"); code != 2 || !strings.Contains(errs, "not a regular file") {
		t.Errorf("hook with a symlinked .sec/config: exit %d\n%s", code, errs)
	}
	r.must("rm", ".sec/config")
	// Nor may a directory take its place: git then lists only .sec/config/x.
	r.must("git", "rm", "-q", "--cached", ".sec/config")
	r.write(".sec/config/x", "forbid = \n")
	r.must("git", "add", "-A")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, ".sec/config\t0\t0\tconfig\tmust be a regular file, not a directory") {
		t.Errorf(".sec/config as a directory: exit %d\n%s", code, out)
	}
	if _, errs, code := r.run("segscan", "hook"); code != 2 || !strings.Contains(errs, "not a regular file") {
		t.Errorf("hook with .sec/config as a directory: exit %d\n%s", code, errs)
	}
	r.must("git", "rm", "-q", "-r", "--cached", ".sec/config")
	r.must("rm", "-r", ".sec/config")
	// A keystore reached through a symlink alias of the repository is
	// still inside it.
	alias := filepath.Join(t.TempDir(), "alias")
	r.must("ln", "-s", r.dir, alias)
	r.write(".sec/config", "keystore = "+filepath.Join(alias, "vault")+"\n")
	r.write("vault/keys", "x\n")
	r.must("git", "add", "-A")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, "vault/keys\t0\t0\tforbidden") {
		t.Errorf("keystore through a symlink alias: exit %d\n%s", code, out)
	}
	r.must("git", "rm", "-q", "--cached", "vault/keys")
	r.must("rm", "-r", "vault")
	// A relative keystore is in the repository whatever the working tree has
	// at that path: the index has vault/keys, the working tree a symlink
	// pointing outside.
	r.write(".sec/config", "keystore = vault\n")
	r.write("vault/keys", "x\n")
	r.must("git", "add", "-A")
	r.must("rm", "-r", "vault")
	r.must("ln", "-s", t.TempDir(), "vault")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, "vault/keys\t0\t0\tforbidden") {
		t.Errorf("relative keystore replaced by a symlink in the working tree: exit %d\n%s", code, out)
	}
	r.must("rm", "vault")
	r.must("git", "rm", "-q", "--cached", "vault/keys")
	// The same for an absolute keystore path below the repository, written
	// directly and through the alias.
	// The last one goes through the alias and then "..": resolved first, it
	// is the repository again; collapsed lexically first, it is not.
	for _, ks := range []string{filepath.Join(r.dir, "vault"), filepath.Join(alias, "vault"),
		alias + "/../" + filepath.Base(r.dir) + "/vault"} {
		r.write(".sec/config", "keystore = "+ks+"\n")
		r.write("vault/keys", "x\n")
		r.must("git", "add", "-A")
		r.must("rm", "-r", "vault")
		r.must("ln", "-s", t.TempDir(), "vault")
		if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, "vault/keys\t0\t0\tforbidden") {
			t.Errorf("absolute keystore %s replaced by a symlink in the working tree: exit %d\n%s", ks, code, out)
		}
		r.must("rm", "vault")
		r.must("git", "rm", "-q", "--cached", "vault/keys")
	}
	// A path that leaves the repository with ".." and comes back is refused
	// as such: in the snapshot it may land somewhere the working tree cannot
	// show.
	r.write(".sec/config", "keystore = "+r.dir+"/link/../../"+filepath.Base(r.dir)+"/vault\n")
	r.must("git", "add", "-A")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, "no . or .. components allowed") {
		t.Errorf("keystore path with ..: exit %d\n%s", code, out)
	}
	// The keystore cannot be the repository itself.
	r.write(".sec/config", "keystore = .\n")
	r.must("git", "add", "-A")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, "the keystore cannot be the repository itself") {
		t.Errorf("keystore = .: exit %d\n%s", code, out)
	}
	// The hook never reads an unstaged model: a broken one in the working
	// tree is ignored when none is staged.
	r.write(".sec/config", "")
	r.write(".sec/segscan.model", "not a model")
	r.must("git", "add", ".sec/config")
	if _, errs, code := r.run("segscan", "hook"); code != 0 {
		t.Errorf("hook read the unstaged model: exit %d\n%s", code, errs)
	}
	// hook_scan = off in the index: a broken staged model is not even read.
	r.write(".sec/config", "hook_scan = off\n")
	r.must("git", "add", "-f", ".sec/config", ".sec/segscan.model")
	if _, errs, code := r.run("segscan", "hook"); code != 0 {
		t.Errorf("hook_scan = off read the staged model: exit %d\n%s", code, errs)
	}
	r.write(".sec/config", "")
	r.must("git", "add", ".sec/config")
	if _, errs, code := r.run("segscan", "hook"); code != 2 {
		t.Errorf("a broken staged model with the scan on: exit %d\n%s", code, errs)
	}
	r.must("git", "rm", "-q", "--cached", ".sec/segscan.model")
	// Nor is it checked for being a regular file: a symlink staged in its
	// place is fine with the scan off, an error with it on.
	model := r.read(".sec/segscan.model")
	r.must("rm", ".sec/segscan.model")
	r.must("ln", "-s", "elsewhere", ".sec/segscan.model")
	r.write(".sec/config", "hook_scan = off\n")
	r.must("git", "add", "-f", ".sec/config", ".sec/segscan.model")
	if _, errs, code := r.run("segscan", "hook"); code != 0 {
		t.Errorf("hook_scan = off checked the staged model: exit %d\n%s", code, errs)
	}
	r.write(".sec/config", "")
	r.must("git", "add", ".sec/config")
	if _, errs, code := r.run("segscan", "hook"); code != 2 || !strings.Contains(errs, "not a regular file") {
		t.Errorf("a symlinked staged model with the scan on: exit %d\n%s", code, errs)
	}
	r.must("git", "rm", "-q", "--cached", ".sec/segscan.model")
	r.must("rm", ".sec/segscan.model")
	r.write(".sec/segscan.model", model)
	// Nor an unstaged broken config: the staged one is valid.
	r.write(".sec/config", "colour = red\n")
	if _, errs, code := r.run("segscan", "hook"); code != 0 {
		t.Errorf("hook parsed the unstaged config: exit %d\n%s", code, errs)
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

// Writes into .sec/ must not follow symlinks the checkout put there: neither a
// planted temporary name nor .sec itself.
func TestCLISecWritesNoSymlinks(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("precious\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tmp := range []string{".sec/names.tmp", ".sec/manifest.tmp"} {
		if err := os.Symlink(victim, filepath.Join(r.dir, tmp)); err != nil {
			t.Fatal(err)
		}
	}
	r.must("segscan", "key", "add", "db_pass")
	r.write("nodes/n1/etc/a.conf", "x\n")
	r.must("segscan", "manifest", "fix")
	if got, _ := os.ReadFile(victim); string(got) != "precious\n" {
		t.Errorf("victim overwritten through a planted temporary symlink: %q", got)
	}
	if !strings.Contains(r.read(".sec/names"), "db_pass\t") || !strings.Contains(r.read(".sec/manifest"), "nodes/n1/etc/a.conf\t") {
		t.Errorf("names or manifest not written")
	}

	// .sec as a symlink to a directory outside the repository.
	r2 := newRepo(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(r2.dir, ".sec")); err != nil {
		t.Fatal(err)
	}
	if _, errs, code := r2.run("segscan", "init"); code == 0 || !strings.Contains(errs, "not a directory") {
		t.Errorf("init through a symlinked .sec: exit %d\n%s", code, errs)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("init wrote outside the repository: %v", ents)
	}
	r.must("rm", "-r", ".sec/hooks")
	r.must("mv", ".sec", "real-sec")
	r.must("ln", "-s", "real-sec", ".sec")
	if _, errs, code := r.run("segscan", "key", "add", "other"); code == 0 || !strings.Contains(errs, "not a directory") {
		t.Errorf("key add through a symlinked .sec: exit %d\n%s", code, errs)
	}
}

// .sec itself replaced by a symlink or a submodule in a snapshot: that is a
// config finding, not a snapshot from before adoption.
func TestCLISecNotADirectory(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	r.write(".sec/config", "forbid = forbidden.txt\n")
	r.must("git", "add", "-A")
	r.must("git", "commit", "-q", "-m", "adopt")
	r.must("git", "rm", "-q", "-r", "--cached", ".sec")
	r.must("mv", ".sec", "real-sec")
	r.must("ln", "-s", "real-sec", ".sec")
	r.write("forbidden.txt", "x\n")
	r.must("git", "add", ".sec", "forbidden.txt")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, ".sec\t0\t0\tconfig\tmust be a directory") {
		t.Errorf("staged symlink .sec: exit %d\n%s", code, out)
	}
	if _, errs, code := r.run("segscan", "hook"); code != 2 || !strings.Contains(errs, "not a directory") {
		t.Errorf("hook with a staged symlink .sec: exit %d\n%s", code, errs)
	}
	r.must("git", "commit", "-q", "--no-verify", "-m", "symlink .sec")
	if out, _, code := r.run("segscan", "check", "-range", "HEAD~1..HEAD"); code != 1 || !strings.Contains(out, "must be a directory") {
		t.Errorf("commit with a symlink .sec: exit %d\n%s", code, out)
	}
	// A submodule (gitlink) at .sec.
	r.must("git", "rm", "-q", "--cached", ".sec")
	head := strings.TrimSpace(r.must("git", "rev-parse", "HEAD"))
	r.must("git", "update-index", "--add", "--cacheinfo", "160000,"+head+",.sec")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, ".sec\t0\t0\tconfig\tmust be a directory") {
		t.Errorf("staged gitlink .sec: exit %d\n%s", code, out)
	}
}

// manifest fix drops only f and l entries whose file is gone: d and s entries
// describe the target and have no file in the tree.
func TestCLIManifestFixKeepsTargetEntries(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	r.write(".sec/manifest", manifestHeader+
		"nodes/n1/etc/gone.conf\tf\t0644\troot\troot\n"+
		"nodes/n1/etc/htpasswd\ts\t0640\troot\twww-data\tsecret=htpasswd\n"+
		"nodes/n1/var/log/app\td\t0750\tapp\tadm\n")
	_, errs, _ := r.run("segscan", "manifest", "fix")
	m := r.read(".sec/manifest")
	if strings.Contains(m, "gone.conf") || !strings.Contains(m, "nodes/n1/etc/htpasswd\ts") || !strings.Contains(m, "nodes/n1/var/log/app\td") {
		t.Errorf("manifest after fix:\n%s\n%s", m, errs)
	}
}

// No manifest entry may lie below an f or s entry.
func TestCLIManifestEntryBelowFile(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	r.write(".sec/manifest", manifestHeader+
		"nodes/n1/etc/credential\ts\t0600\troot\troot\tsecret=cred\n"+
		"nodes/n1/etc/credential/token\ts\t0600\troot\troot\tsecret=token\n")
	if out, _, code := r.run("segscan", "check"); code != 1 || !strings.Contains(out, "nodes/n1/etc/credential/token lies below nodes/n1/etc/credential, which is type s") {
		t.Errorf("entry below an s entry: exit %d\n%s", code, out)
	}
}

// A keystore inside the checkout is a config finding even while nothing of
// it is tracked.
func TestCLIKeystoreInsideRepository(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	r.write(".sec/config", "keystore = secrets\n")
	if out, _, code := r.run("segscan", "check"); code != 1 || !strings.Contains(out, "the keystore must be outside the repository (it is at secrets)") {
		t.Errorf("keystore inside the repository: exit %d\n%s", code, out)
	}
}

// Files hidden by a sparse checkout are still part of the tree: manifest fix
// keeps their entries, and key rm still sees their placeholders.
func TestCLISparseCheckout(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	ph := strings.TrimSpace(r.must("segscan", "key", "add", "db_pass"))
	r.write("nodes/n1/etc/a.conf", "x\n")
	r.write("nodes/n2/etc/b.conf", "p = "+ph+"\n")
	r.must("segscan", "manifest", "fix")
	r.must("git", "add", "-A")
	r.must("git", "commit", "-q", "--no-verify", "-m", "one")
	r.must("git", "sparse-checkout", "set", "--no-cone", "/*", "!/nodes/n2/")
	if _, err := os.Stat(filepath.Join(r.dir, "nodes/n2/etc/b.conf")); err == nil {
		t.Skip("sparse checkout did not hide the file")
	}
	r.must("segscan", "manifest", "fix")
	if !strings.Contains(r.read(".sec/manifest"), "nodes/n2/etc/b.conf\t") {
		t.Errorf("manifest fix dropped the entry of a sparse file:\n%s", r.read(".sec/manifest"))
	}
	if _, errs, code := r.run("segscan", "key", "rm", "db_pass"); code == 0 {
		t.Errorf("key rm removed a key still used in a sparse file\n%s", errs)
	}
}

// A node root must be a directory: a submodule or file at nodes/n1 itself
// would hide everything below it from check.
func TestCLINodeRootNotADirectory(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	r.must("git", "add", ".sec")
	r.must("git", "commit", "-q", "--no-verify", "-m", "base")
	commit := strings.TrimSpace(r.must("git", "rev-parse", "HEAD"))
	r.must("git", "update-index", "--add", "--cacheinfo", "160000,"+commit+",nodes/n1")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, "nodes/n1\t0\t0\tmanifest\ta node root must be a directory") {
		t.Errorf("gitlink at a node root: exit %d\n%s", code, out)
	}
}

// A keystore reached through an outside symlink whose target in the
// repository has been removed from the working tree is still inside it.
func TestCLIKeystoreThroughDanglingLink(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	ext := filepath.Join(t.TempDir(), "ext")
	if err := os.Symlink(filepath.Join(r.dir, "missing"), ext); err != nil {
		t.Fatal(err)
	}
	r.write(".sec/config", "keystore = "+ext+"/vault\n")
	r.write("missing/vault/keys", "x\n")
	r.must("git", "add", "-A")
	r.must("rm", "-r", "missing")
	if out, _, code := r.run("segscan", "check", "-staged"); code != 1 || !strings.Contains(out, "missing/vault/keys\t0\t0\tforbidden") {
		t.Errorf("keystore through a dangling link: exit %d\n%s", code, out)
	}
}

func TestCLIScanThresholdsFromConfig(t *testing.T) {
	r := newRepo(t)
	r.must("segscan", "init")
	r.write("app.conf", "token = Zx81kq9PmW3vT7bRq2Lp4\nid = k9Pm\n")
	out, _, code := r.run("segscan", "scan", "app.conf")
	if code != 1 || !strings.Contains(out, "app.conf") {
		t.Fatalf("baseline: exit %d\n%s", code, out)
	}
	cfg := r.read(".sec/config")
	r.write(".sec/config", cfg+"scan_minlen = 30\n")
	if out, _, code := r.run("segscan", "scan", "app.conf"); code != 0 {
		t.Errorf("scan_minlen = 30: exit %d\n%s", code, out)
	}
	if _, _, code := r.run("segscan", "scan", "-minlen", "6", "app.conf"); code != 1 {
		t.Errorf("-minlen on the command line must win: exit %d", code)
	}
	r.write(".sec/config", cfg+"scan_bpc = 8\n")
	if out, _, code := r.run("segscan", "scan", "app.conf"); code != 0 {
		t.Errorf("scan_bpc = 8: exit %d\n%s", code, out)
	}
	// The hook takes the thresholds from the index.
	r.write(".sec/config", cfg+"scan_bpc = 8\nhook_scan = block\n")
	r.must("git", "add", ".sec")
	r.must("git", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "sec")
	r.write(".sec/config", cfg+"hook_scan = block\n") // unstaged: no threshold
	r.must("git", "add", "app.conf")
	if out, errs, code := r.run("segscan", "hook"); code != 0 {
		t.Errorf("hook with the staged scan_bpc = 8: exit %d\n%s%s", code, out, errs)
	}
	// And the other way round: an unstaged threshold must not hide what
	// the staged config, which has none, reports.
	r.write(".sec/config", cfg+"hook_scan = block\n")
	r.must("git", "add", ".sec")
	r.write(".sec/config", cfg+"hook_scan = block\nscan_bpc = 8\nscan_minlen = 30\n")
	if _, _, code := r.run("segscan", "hook"); code != 1 {
		t.Errorf("hook with an unstaged scan_bpc = 8: exit %d, want the staged config's finding", code)
	}
}

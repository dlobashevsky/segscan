//go:build linux

package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLetterFragments(t *testing.T) {
	got := letterFragments("Xk9PmQwLz_abc")
	if want := []string{"xk", "pm", "qw", "lz", "abc"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A lower-case key copied into three files: a plain train takes it into the
// dictionary, model check reports it, train -guard keeps it out.
const spoilKey = "qwhrtzvkmlpxsdfgnb"

func writeSpoilCorpus(r *repo) {
	for _, n := range []string{"n1", "n2", "n3"} {
		r.write("conf/"+n+".conf", "user = admin\nsecret = "+spoilKey+"\nlisten = 8080\n")
	}
	r.write("README.txt", strings.Repeat("the server listens on the port given in the configuration file\n", 20))
}

func modelWords(t *testing.T, out string) map[string]string {
	t.Helper()
	words := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n")[1:] {
		if f := strings.Split(l, "\t"); len(f) == 4 {
			words[f[1]] = f[0]
		}
	}
	return words
}

func TestCLITrainGuardAndModelCheck(t *testing.T) {
	r := newRepo(t)
	writeSpoilCorpus(r)
	r.must("git", "add", "-A")

	r.must("segscan", "train")
	out, _, code := r.run("segscan", "model", "check")
	if code != 1 || modelWords(t, out)[spoilKey] != "random" {
		t.Fatalf("spoiled model: exit %d\n%s", code, out)
	}
	if out, _, _ := r.run("segscan", "scan", "-json", "conf"); strings.Contains(out, "qwhrtz") {
		t.Errorf("the spoiled model should hide the key (that is the problem): %s", out)
	}

	// word: accepts a harmless word.
	r.write(".segscan-allow", "word:"+spoilKey+"\n")
	if out, _, code := r.run("segscan", "model", "check"); code != 0 {
		t.Errorf("word: allowed: exit %d\n%s", code, out)
	}
	r.write(".segscan-allow", "")

	_, errs, _ := r.run("segscan", "train", "-guard")
	if !strings.Contains(errs, "fragments left out") {
		t.Errorf("train -guard: %s", errs)
	}
	if out, _, code := r.run("segscan", "model", "check"); code != 0 {
		t.Errorf("guarded model: exit %d\n%s", code, out)
	}
	if out, _, _ := r.run("segscan", "scan", "-json", "conf"); strings.Count(out, "qwhrtz") != 3 {
		t.Errorf("guarded model should report the key in all three files: %s", out)
	}

	// A finding whose fp is in the allowlist is reviewed: it is learnt.
	out, _, _ = r.run("segscan", "scan", "-json", "conf/n1.conf")
	var f struct{ FP string }
	if err := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &f); err != nil || f.FP == "" {
		t.Fatalf("no finding to allow: %q %v", out, err)
	}
	r.write(".segscan-allow", f.FP+"\n")
	r.must("segscan", "train", "-guard")
	if out, _, _ := r.run("segscan", "model", "check"); modelWords(t, out)[spoilKey] != "random" {
		t.Errorf("an allowed finding should be learnt:\n%s", out)
	}
}

func TestCLIModelCheckSince(t *testing.T) {
	r := newRepo(t)
	r.write("a.txt", strings.Repeat("alpha beta gamma\n", 5)+strings.Repeat("alpha beta gamma\n", 5))
	r.write("b.txt", strings.Repeat("alpha beta gamma\n", 5))
	r.must("git", "add", "-A")
	r.must("segscan", "train", "-m", "m.model")
	r.must("git", "add", "m.model")
	r.must("git", "commit", "-q", "-m", "one")
	r.write("a.txt", strings.Repeat("alpha beta gamma zebra\n", 5))
	r.write("b.txt", strings.Repeat("alpha beta gamma zebra\n", 5))
	r.must("segscan", "train", "-m", "m.model", "a.txt", "b.txt")
	out := r.must("segscan", "model", "check", "-m", "m.model", "-since", "HEAD")
	if modelWords(t, out)["zebra"] != "new" {
		t.Errorf("zebra should be listed as new:\n%s", out)
	}
}

func TestCLIModelCheckKeystore(t *testing.T) {
	r, _ := newKSRepo(t)
	// The value itself is never in the corpus (train would refuse it), but
	// its letter part is, in three files.
	r.setKey("a", "Qwhrtzvkmlpxsdfgnb9")
	writeSpoilCorpus(r)
	r.must("git", "add", "-A")
	r.must("segscan", "train")
	out, _, code := r.run("segscan", "model", "check")
	if code != 1 || modelWords(t, out)[spoilKey] != "keystore" || !strings.Contains(out, "value of a") {
		t.Errorf("keystore fragment: exit %d\n%s", code, out)
	}
}

// scan_minlen and scan_bpc are for reporting: the guard keeps its own
// thresholds.
func TestCLITrainGuardIgnoresScanThresholds(t *testing.T) {
	r, _ := newKSRepo(t)
	r.write(".sec/config", r.read(".sec/config")+"scan_minlen = 100\nscan_bpc = 7.5\n")
	writeSpoilCorpus(r)
	r.must("git", "add", "-A")
	r.must("segscan", "train", "-guard")
	if out, _, code := r.run("segscan", "model", "check"); code != 0 {
		t.Errorf("guarded model with scan_minlen = 100: exit %d\n%s", code, out)
	}
}

func TestCLIHookModel(t *testing.T) {
	r, _ := newKSRepo(t)
	writeSpoilCorpus(r)
	r.must("git", "add", "-A") // train without paths reads git ls-files
	r.must("segscan", "train")
	r.must("git", "add", "-A")

	// Default off: the model is not checked.
	if _, errs, _ := r.run("segscan", "hook"); strings.Contains(errs, "segscan.model") {
		t.Errorf("hook_model off: %s", errs)
	}
	for _, mode := range []string{"warn", "block"} {
		r.write(".sec/config", r.read(".sec/config")+"hook_model = "+mode+"\n")
		r.must("git", "add", ".sec/config")
		_, errs, code := r.run("segscan", "hook")
		if !strings.Contains(errs, spoilKey) || (mode == "block") != (code == 1) {
			t.Errorf("hook_model = %s: exit %d\n%s", mode, code, errs)
		}
		if mode == "block" {
			// -m and $SEGSCAN_MODEL choose the scan's model; the model
			// being committed is still checked.
			env := r.env
			r.env = append(append([]string{}, env...), "SEGSCAN_MODEL="+filepath.Join(t.TempDir(), "other.model"))
			_, errs, code := r.run("segscan", "hook")
			r.env = env
			if code != 1 || !strings.Contains(errs, spoilKey) {
				t.Errorf("hook_model = block with SEGSCAN_MODEL: exit %d\n%s", code, errs)
			}
		}
		r.write(".sec/config", strings.Replace(r.read(".sec/config"), "hook_model = "+mode+"\n", "", 1))
	}
}

// -words entries go through the guard too.
func TestCLITrainGuardWordList(t *testing.T) {
	r := newRepo(t)
	r.write("README.txt", strings.Repeat("the server listens on the port given in the configuration file\n", 20))
	r.write("words.txt", "transliteration\n"+spoilKey+"\n")
	r.must("git", "add", "README.txt")
	r.must("segscan", "train", "-words", "words.txt")
	if _, _, code := r.run("segscan", "model", "check"); code != 1 {
		t.Errorf("a random list word without -guard should be in the model")
	}
	_, errs, _ := r.run("segscan", "train", "-guard", "-words", "words.txt")
	if !strings.Contains(errs, "word-list entries") {
		t.Errorf("train -guard -words: %s", errs)
	}
	if out, _, code := r.run("segscan", "model", "check"); code != 0 {
		t.Errorf("guarded list: exit %d\n%s", code, out)
	}
}

// The hook takes the keystore from the staged config, not the working tree's.
func TestCLIHookModelStagedKeystore(t *testing.T) {
	r, ks := newKSRepo(t)
	const word = "correcthorsebattery" // a word, not random: only the keystore check finds it
	r.setKey("a", "Correcthorsebattery7")
	for _, n := range []string{"n1", "n2", "n3"} {
		r.write("conf/"+n+".conf", "pass = "+word+"\n")
	}
	r.write("README.txt", strings.Repeat("the server listens on the port given in the configuration file\n", 20))
	r.must("git", "add", "-A")
	r.must("segscan", "train")
	withKeystore := func(path string) string {
		lines := strings.Split(r.read(".sec/config"), "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "keystore") {
				lines[i] = "keystore = " + path
			}
		}
		return strings.Join(lines, "\n")
	}
	cfg := withKeystore(ks) + "hook_model = block\n"
	r.write(".sec/config", cfg)
	r.must("git", "add", "-A")
	// The working tree's config points elsewhere, unstaged.
	r.write(".sec/config", withKeystore(filepath.Join(t.TempDir(), "none")))
	env := r.env
	defer func() { r.env = env }()
	r.env = append(append([]string{}, env...), "SEGSCAN_KEYSTORE=")
	_, errs, code := r.run("segscan", "hook")
	if code != 1 || !strings.Contains(errs, "value of a") {
		t.Errorf("staged keystore: exit %d\n%s", code, errs)
	}
}

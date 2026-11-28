package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// A trained model keeps a dictionary of letter fragments seen in the
// repository. A key that occurs often enough becomes one of them: it is then
// stored in the model, and the scan with that model no longer reports it.
// model check looks for such words, against the built-in model, which no
// training can spoil.

type modelIssue struct {
	Kind   string  // random, keystore or new
	Word   string  // the dictionary word
	Bpc    float64 // bits per letter under the built-in model
	Detail string
}

type modelCheckOpts struct {
	MinLen int        // words at least this long are checked for randomness
	MaxBpc float64    // a word costing more per letter under the built-in model looks random
	Allow  *allowList // word: lines are accepted
	KS     *keystore  // values whose letter fragments must not be words; may be nil
	Prev   *Model     // the words new against it are listed; may be nil
}

const (
	modelCheckMinLen = dictGuardLen
	modelCheckMaxBpc = 4.0
)

// checkModel returns the suspicious words of m: random-looking (kind
// random) or a fragment of a keystore value (kind keystore); with Prev also
// every word added since (kind new, for review only).
func checkModel(m *Model, o modelCheckOpts) []modelIssue {
	frags := map[string]string{} // letter fragment of a value -> key name
	if o.KS != nil {
		add := func(name, value string) {
			for _, f := range letterFragments(value) {
				if len(f) >= 4 {
					frags[f] = name
				}
			}
		}
		for _, k := range o.KS.keys {
			add(k.Name, k.Value)
		}
		for _, k := range o.KS.invalid {
			add(k.Name, k.Value)
		}
		for _, r := range o.KS.retired {
			add(r.Name+" (retired)", r.Value)
		}
	}
	var out []modelIssue
	for w := range m.Words {
		bpc := 0.0
		if baseModel != nil && len(w) > 0 {
			bpc = baseModel.wordBits(w) / float64(len(w))
		}
		accepted := o.Allow != nil && o.Allow.words[w]
		switch {
		case frags[w] != "" && !accepted:
			out = append(out, modelIssue{"keystore", w, bpc, "a letter fragment of the value of " + frags[w]})
		case len(w) >= o.MinLen && bpc > o.MaxBpc && !accepted && !inBase(w):
			out = append(out, modelIssue{"random", w, bpc, "looks random under the built-in model"})
		case o.Prev != nil && !hasWord(o.Prev, w):
			out = append(out, modelIssue{"new", w, bpc, "added since the previous model"})
		}
	}
	rank := map[string]int{"keystore": 0, "random": 1, "new": 2}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		if out[i].Bpc != out[j].Bpc {
			return out[i].Bpc > out[j].Bpc
		}
		return out[i].Word < out[j].Word
	})
	return out
}

func inBase(w string) bool { return baseModel != nil && hasWord(baseModel, w) }

func hasWord(m *Model, w string) bool { _, ok := m.Words[w]; return ok }

// letterFragments splits a string into lower-cased letter fragments the way
// training does (a fragment ends at a non-letter or a camelCase boundary).
func letterFragments(s string) []string {
	a := annotate([]byte(s), nil)
	var out []string
	start := -1
	flush := func(end int) {
		if start >= 0 {
			out = append(out, strings.ToLower(s[start:end]))
			start = -1
		}
	}
	for i := range a {
		if a[i].cls != cLetter {
			flush(i)
			continue
		}
		if a[i].ws {
			flush(i)
			start = i
		}
	}
	flush(len(s))
	return out
}

// failing reports whether the issues include more than new words.
func failing(issues []modelIssue) bool {
	for _, x := range issues {
		if x.Kind != "new" {
			return true
		}
	}
	return false
}

func printModelIssues(issues []modelIssue, header bool) {
	if header {
		fmt.Println("kind\tword\tbits_per_char\tdetail")
	}
	for _, x := range issues {
		fmt.Printf("%s\t%s\t%.2f\t%s\n", x.Kind, x.Word, x.Bpc, x.Detail)
	}
}

func cmdModel(args []string) {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(os.Stderr, "usage: segscan model check [-m model] [-since REV] [-wordlen N] [-maxbpc N] [-no-header]")
		os.Exit(2)
	}
	fs, c := flags("model check")
	since := fs.String("since", "", "also list the words added since the model in this git revision")
	minLen := fs.Int("wordlen", modelCheckMinLen, "check words at least this long for randomness")
	maxBpc := fs.Float64("maxbpc", modelCheckMaxBpc, "a word above this many bits per letter under the built-in model looks random")
	fs.Parse(args[1:])
	c.finish(fs)
	path := modelPath(c.model)
	m, err := loadModel(path)
	if err != nil {
		die(err)
	}
	o := modelCheckOpts{MinLen: *minLen, MaxBpc: *maxBpc, Allow: loadAllow(c.allow, false)}
	if *since != "" {
		if o.Prev, err = modelAt(*since, path); err != nil {
			die(err)
		}
	}
	if c.top != "" {
		ks, why := checkKeystore(c.top)
		if ks == nil {
			fmt.Fprintln(os.Stderr, "segscan: model check: keystore values not checked: "+why)
		} else {
			defer ks.close()
			o.KS = ks
		}
	}
	issues := checkModel(m, o)
	printModelIssues(issues, !c.noHeader)
	if failing(issues) {
		fmt.Fprintf(os.Stderr, "segscan: model %s: suspicious dictionary words; retrain with -guard, or add word:<word> to the allowlist for a harmless one\n", path)
		os.Exit(1)
	}
}

// modelAt reads the model file as it was in a git revision.
func modelAt(rev, path string) (*Model, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	rel := repoPath(abs)
	out, err := exec.Command("git", "show", rev+":"+rel).Output()
	if err != nil {
		return nil, fmt.Errorf("git show %s:%s: %v", rev, rel, err)
	}
	return decodeModel(bytes.NewReader(out), rev+":"+rel)
}

// hookModelCheck is hook_model: model check of the staged model, when it
// differs from the one in HEAD. With block, suspicious words stop the
// commit; with warn they are only printed.
func (c *common) hookModelCheck() {
	c.stagedRegular("segscan.model")
	staged, err := exec.Command("git", "-C", c.top, "show", ":"+secDir+"/segscan.model").Output()
	if err != nil {
		return // no model staged
	}
	head, err := exec.Command("git", "-C", c.top, "show", "HEAD:"+secDir+"/segscan.model").Output()
	if err == nil && bytes.Equal(head, staged) {
		return
	}
	m, err := decodeModel(bytes.NewReader(staged), "staged "+secDir+"/segscan.model")
	if err != nil {
		die(err)
	}
	o := modelCheckOpts{MinLen: modelCheckMinLen, MaxBpc: modelCheckMaxBpc, Allow: c.allowList}
	if o.Allow == nil {
		o.Allow = loadAllow(c.allow, false)
	}
	if ks, _ := checkKeystore(c.top); ks != nil {
		defer ks.close()
		o.KS = ks
	}
	var bad []modelIssue
	for _, x := range checkModel(m, o) {
		if x.Kind != "new" {
			bad = append(bad, x)
		}
	}
	if len(bad) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "segscan: staged %s/segscan.model has %d suspicious dictionary word(s):\n", secDir, len(bad))
	for _, x := range bad {
		fmt.Fprintf(os.Stderr, "  %s\t%s\t%.2f\t%s\n", x.Kind, x.Word, x.Bpc, x.Detail)
	}
	fmt.Fprintln(os.Stderr, "segscan: retrain with -guard, or add word:<word> to .sec/allow for a harmless one (hook_model in .sec/config)")
	if c.sec.HookModel == "block" {
		os.Exit(1)
	}
}

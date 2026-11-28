package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The non-interactive forms of the TUI's actions (docs/tui.md 7):
//
//	segscan allow fp FP...             fingerprints -> allowlist
//	segscan allow fp -file FILE FP...  the same, in that file only
//	segscan allow fp -path GLOB FP...  the same, in the files GLOB covers
//	segscan allow path FILE...         path:/FILE -> allowlist
//	segscan ignore FILE...          -> .gitignore, and out of the index

var fpRE = regexp.MustCompile(`^[0-9a-f]{12}$`)

func cmdAllow(args []string) {
	if len(args) == 0 || (args[0] != "fp" && args[0] != "path") {
		fmt.Fprintln(os.Stderr, "usage: segscan allow fp [-file FILE | -path GLOB] FP... | allow path FILE... [-n] [-allow file]")
		os.Exit(2)
	}
	what := args[0]
	fs, c := flags("allow " + what)
	dry := fs.Bool("n", false, "only print what would be done")
	var inFile, inGlob *string
	if what == "fp" {
		inFile = fs.String("file", "", "only in this file")
		inGlob = fs.String("path", "", "only in the files this path: glob covers (/nodes/*/nginx.conf)")
	}
	operands := parseInterspersed(fs, args[1:])
	c.finish(fs)
	p := newPlan(c)
	glob := ""
	if what == "fp" {
		switch {
		case *inFile != "" && *inGlob != "":
			die(fmt.Errorf("allow fp: -file or -path, not both"))
		case *inFile != "":
			glob = "/" + globEscape(p.mustNotDir(*inFile, "use -path for a glob"))
		case *inGlob != "":
			if err := checkPathGlob(*inGlob); err != nil {
				die(fmt.Errorf("allow fp -path %s: %v", *inGlob, err))
			}
			glob = *inGlob
		}
	}
	for _, a := range operands {
		switch what {
		case "fp":
			fp := strings.ToLower(a)
			if !fpRE.MatchString(fp) {
				die(fmt.Errorf("%q is not a fingerprint (12 hex digits, the fp column)", a))
			}
			p.actions = append(p.actions, action{Kind: actAllowFP, FP: fp, Glob: glob})
		case "path":
			p.actions = append(p.actions, action{Kind: actAllowFile, File: p.mustNotDir(a, "add path:DIR/ by hand to skip a whole directory")})
		}
	}
	runPlan(p, *dry)
}

func cmdIgnore(args []string) {
	fs := flag.NewFlagSet("ignore", flag.ExitOnError)
	dry := fs.Bool("n", false, "only print what would be done")
	history := fs.Bool("history", false, "also for a file committed in HEAD (its content stays in the history)")
	operands := parseInterspersed(fs, args)
	top := repoTop()
	if top == "" {
		die(fmt.Errorf("ignore: not a git repository"))
	}
	p := &plan{top: top}
	for _, a := range operands {
		p.actions = append(p.actions, action{Kind: actIgnore, File: mustRepoFile(a), History: *history})
	}
	runPlan(p, *dry)
}

// parseInterspersed parses flags before, between and after the operands
// (the flag package stops at the first operand, so "ignore FILE -n" would
// take -n for a file and do it for real). "--" ends the flags: a name
// starting with "-" goes after it.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var rest []string
	for i, a := range args {
		if a == "--" {
			args, rest = args[:i], args[i+1:]
			break
		}
	}
	var operands []string
	for {
		fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return append(operands, rest...)
		}
		operands = append(operands, args[0])
		args = args[1:]
	}
}

// newPlan starts a plan in the current repository, with the allowlist the
// scan would read.
func newPlan(c *common) *plan {
	top := repoTop()
	if top == "" {
		die(fmt.Errorf("not a git repository"))
	}
	return &plan{top: top, allowPath: allowFilePath(c.allow)}
}

// allowFilePath makes the allowlist path absolute without resolving
// symlinks on the way, so that repoDir can refuse a symlinked .sec/.
func allowFilePath(p string) string {
	if !filepath.IsAbs(p) {
		return filepath.Join(repoCwd(), p)
	}
	p = filepath.Clean(p)
	// .sec/allow comes as <git toplevel>/.sec/allow; give it the canonical
	// top the plan uses, so that the part below it is what repoDir checks.
	if raw, err := gitOut("rev-parse", "--show-toplevel"); err == nil && raw != "" {
		if rest, ok := strings.CutPrefix(p, filepath.Clean(raw)+string(filepath.Separator)); ok {
			return filepath.Join(repoTop(), rest)
		}
	}
	return p
}

// checkPathGlob reports a path: glob that can never match: empty, or a
// part path.Match calls malformed ("[", "a[b").
func checkPathGlob(pat string) error {
	if p := strings.TrimSuffix(cleanRel(strings.TrimLeft(pat, "/")), "/"); p == "" || p == "." {
		return fmt.Errorf("an empty glob")
	}
	return checkGlob(pat)
}

// mustNotDir is mustRepoFile for an operand that must name one file: a
// directory, on disk or in the index, would make path:/dir, which covers
// every file below it.
func (p *plan) mustNotDir(a, hint string) string {
	f := mustRepoFile(a)
	if st, err := os.Stat(a); (err == nil && st.IsDir()) || p.indexDir(f) {
		die(fmt.Errorf("%s: a directory; %s", a, hint))
	}
	return f
}

// mustRepoFile gives a command-line path as a repository path; it must lie
// inside the repository.
func mustRepoFile(a string) string {
	if _, ok := cwdRelInRepo(a); !ok {
		die(fmt.Errorf("%s: outside the repository", a))
	}
	rp := repoPath(a)
	if rp == "." || rp == "" {
		die(fmt.Errorf("%s: names the repository itself", a))
	}
	return rp
}

func runPlan(p *plan, dry bool) {
	if len(p.actions) == 0 {
		die(fmt.Errorf("nothing given"))
	}
	r, err := p.apply(dry)
	for _, l := range r.Done {
		fmt.Println(l)
	}
	for _, l := range r.Warn {
		fmt.Fprintln(os.Stderr, "segscan: warning:", l)
	}
	for _, l := range r.Skipped {
		fmt.Fprintln(os.Stderr, "segscan: not done:", l)
	}
	if err != nil {
		die(err)
	}
	if len(r.Skipped) > 0 {
		os.Exit(1)
	}
}

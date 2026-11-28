package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// The non-interactive forms of the TUI's actions (docs/tui.md 7):
//
//	segscan allow fp FP...          fingerprints -> allowlist
//	segscan allow path FILE...      path:/FILE -> allowlist
//	segscan allow line FILE:LINE... segscan:allow in a comment on the line
//	segscan ignore FILE...          -> .gitignore, and out of the index

var fpRE = regexp.MustCompile(`^[0-9a-f]{12}$`)

func cmdAllow(args []string) {
	if len(args) == 0 || (args[0] != "fp" && args[0] != "path" && args[0] != "line") {
		fmt.Fprintln(os.Stderr, "usage: segscan allow fp FP... | allow path FILE... | allow line FILE:LINE... [-n] [-allow file]")
		os.Exit(2)
	}
	what := args[0]
	fs, c := flags("allow " + what)
	dry := fs.Bool("n", false, "only print what would be done")
	fs.Parse(args[1:])
	c.finish(fs)
	p := newPlan(c)
	for _, a := range fs.Args() {
		switch what {
		case "fp":
			fp := strings.ToLower(a)
			if !fpRE.MatchString(fp) {
				die(fmt.Errorf("%q is not a fingerprint (12 hex digits, the fp column)", a))
			}
			p.actions = append(p.actions, action{Kind: actAllowFP, FP: fp})
		case "path":
			p.actions = append(p.actions, action{Kind: actAllowFile, File: mustRepoFile(a)})
		case "line":
			i := strings.LastIndexByte(a, ':')
			no, err := strconv.Atoi(a[i+1:])
			if i < 0 || err != nil || no < 1 {
				die(fmt.Errorf("%q: want FILE:LINE", a))
			}
			p.actions = append(p.actions, action{Kind: actMarker, File: mustRepoFile(a[:i]), Line: no})
		}
	}
	runPlan(p, *dry)
}

func cmdIgnore(args []string) {
	fs := flag.NewFlagSet("ignore", flag.ExitOnError)
	dry := fs.Bool("n", false, "only print what would be done")
	history := fs.Bool("history", false, "also for a file committed in HEAD (its content stays in the history)")
	fs.Parse(args)
	top := repoTop()
	if top == "" {
		die(fmt.Errorf("ignore: not a git repository"))
	}
	p := &plan{top: top}
	for _, a := range fs.Args() {
		p.actions = append(p.actions, action{Kind: actIgnore, File: mustRepoFile(a), History: *history})
	}
	runPlan(p, *dry)
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

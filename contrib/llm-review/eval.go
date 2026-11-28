package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// cmdEval compares the scores with an allowlist. Findings whose fp is in it
// are known false positives; the rest are "others": real secrets and
// findings nobody has looked at yet. A good threshold filters out most of
// the known false positives and hides few others.
func cmdEval(args []string, in io.Reader, out io.Writer) int {
	fs := flag.NewFlagSet("llm-review eval", flag.ExitOnError)
	allowPath := fs.String("allow", "", "allowlist: its fp lines are the known false positives")
	top := fs.Int("top", 10, "list this many disagreements of each kind")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "llm-review eval -allow FILE < scored.jsonl\n\n"+
			"Scan without the fp lines of the allowlist (keep its path: lines), score, then:\n\n"+
			"  grep '^[[:space:]]*path:' .segscan-allow > paths.allow\n"+
			"  segscan scan -allow paths.allow -json . | llm-review > scored.jsonl\n"+
			"  llm-review eval -allow .segscan-allow < scored.jsonl\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if *allowPath == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	allow, err := readAllowFPs(*allowPath)
	if err != nil {
		return fail(err)
	}

	type row struct {
		f     finding
		score float64
	}
	var neg, oth []row
	skipped := 0
	sc := bufio.NewScanner(in)
	sc.Buffer(nil, 64<<20)
	for sc.Scan() {
		l := bytes.TrimSpace(sc.Bytes())
		if len(l) == 0 {
			continue
		}
		var r struct {
			finding
			Score *float64 `json:"llm_score"`
		}
		if err := json.Unmarshal(l, &r); err != nil {
			return fail(err)
		}
		if r.Score == nil {
			skipped++
			continue
		}
		x := row{r.finding, *r.Score}
		if allow[strings.ToLower(r.FP)] {
			neg = append(neg, x)
		} else {
			oth = append(oth, x)
		}
	}
	if err := sc.Err(); err != nil {
		return fail(err)
	}

	w := bufio.NewWriter(out)
	defer w.Flush()
	fmt.Fprintf(w, "known false positives (fp in %s): %d\nothers: %d\n", *allowPath, len(neg), len(oth))
	if skipped > 0 {
		fmt.Fprintf(w, "without a score (llm_error): %d\n", skipped)
	}
	if len(neg) == 0 {
		fmt.Fprintln(w, "\nno finding is in the allowlist: scan with an allowlist of path: lines only (see -h)")
		return 0
	}
	fmt.Fprintf(w, "\n%-9s  %-28s  %s\n", "threshold", "known FP below (filtered)", "others below (would be hidden)")
	for _, t := range []float64{0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9} {
		nb, ob := 0, 0
		for _, r := range neg {
			if r.score < t {
				nb++
			}
		}
		for _, r := range oth {
			if r.score < t {
				ob++
			}
		}
		fmt.Fprintf(w, "%-9.2f  %5d %6.1f%%                %5d\n", t, nb, 100*float64(nb)/float64(len(neg)), ob)
	}

	list := func(title string, rows []row, desc bool) {
		sort.SliceStable(rows, func(a, b int) bool {
			if desc {
				return rows[a].score > rows[b].score
			}
			return rows[a].score < rows[b].score
		})
		fmt.Fprintf(w, "\n%s\n", title)
		for i := 0; i < len(rows) && i < *top; i++ {
			r := rows[i]
			loc := fmt.Sprintf("%s:%d", r.f.File, r.f.Line)
			if r.f.Commit != "" {
				loc = r.f.Commit[:min(len(r.f.Commit), 10)] + " " + loc
			}
			fmt.Fprintf(w, "  %.4f  %5.2f bpc  %s  %s\n", r.score, r.f.Bits, r.f.FP, loc)
		}
	}
	list("known false positives the model calls secrets (highest scores):", neg, true)
	if len(oth) > 0 {
		list("others the model calls harmless (lowest scores):", oth, false)
	}
	return 0
}

// readAllowFPs reads the fp lines of an allowlist (path: lines and comments
// are skipped), the way segscan does.
func readAllowFPs(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fps := map[string]bool{}
	for _, l := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		f := strings.Fields(l)
		if len(f) == 0 || strings.HasPrefix(f[0], "path:") {
			continue
		}
		fps[strings.ToLower(f[0])] = true
	}
	return fps, nil
}

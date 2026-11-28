// llm-review scores segscan findings with a local LLM: how likely each one
// is a real secret. It reads `segscan scan -json` (or `segscan diff -json`)
// on stdin, takes the context of every finding from the source, asks a
// llama-server for a yes/no answer and prints the same JSON Lines with
// llm_score added: P(yes) from the first token's probabilities.
//
//	segscan scan -json | llm-review > scored.jsonl
//	llm-review eval -allow .segscan-allow < scored.jsonl
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const usage = `llm-review: score segscan findings with a local LLM

  segscan scan -json [paths] | llm-review [flags] > scored.jsonl
  git log -p --all -U0 | segscan diff -json | llm-review [flags]
  llm-review eval -allow FILE < scored.jsonl

Every output line is segscan's JSON object plus "llm_score" (0..1, the
probability that the finding is a real secret), or "llm_score": null and
"llm_error". Run it from the directory segscan ran in, or give -C.

Flags:
`

// finding is one line of segscan's JSON output.
type finding struct {
	Commit    string  `json:"commit"`
	File      string  `json:"file"`
	Line      int     `json:"line"`
	Col       int     `json:"col"`
	Bits      float64 `json:"bits_per_char"`
	Length    int     `json:"length"`
	Kind      string  `json:"kind"`
	FP        string  `json:"fp"`
	Text      string  `json:"text"`
	Truncated bool    `json:"truncated"`

	raw []byte
}

type result struct {
	f     *finding
	score float64
	err   error
	done  bool
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "eval" {
		os.Exit(cmdEval(os.Args[2:], os.Stdin, os.Stdout))
	}
	os.Exit(cmdScore(os.Args[1:], os.Stdin, os.Stdout))
}

func cmdScore(args []string, in io.Reader, out io.Writer) int {
	fs := flag.NewFlagSet("llm-review", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	url := fs.String("url", "http://127.0.0.1:8080", "llama-server address")
	dir := fs.String("C", ".", "directory the finding paths are relative to")
	var o ctxOpts
	fs.IntVar(&o.K, "k", 3, "context on each side of a finding: k × its length (lines longer than -maxline)")
	fs.IntVar(&o.MinSide, "minctx", 24, "context on each side: at least this many bytes")
	fs.IntVar(&o.MaxSide, "maxctx", 200, "context on each side: at most this many bytes")
	fs.IntVar(&o.MaxLine, "maxline", 200, "a line up to this many bytes goes to the model whole")
	fs.IntVar(&o.MaxFind, "maxfind", 120, "a longer finding is shown as head…tail")
	jobs := fs.Int("j", 2, "requests in flight (match llama-server -np)")
	timeout := fs.Duration("timeout", 10*time.Minute, "timeout of one request")
	cachePath := fs.String("cache", "", "cache file: scores by prompt hash (e.g. .git/segscan-llm.cache)")
	systemPath := fs.String("system", "", "file with the instruction (default: built in)")
	examplesPath := fs.String("examples", "", `few-shot file: JSON Lines {"user": "...", "answer": "yes"|"no"}`)
	minScore := fs.Float64("min", 0, "print only findings with at least this score (errors are always printed)")
	sortOut := fs.Bool("sort", false, "print the highest scores first instead of the input order")
	dry := fs.Bool("dry", false, "print the user messages as JSON Lines and exit (no server needed)")
	fs.Parse(args)
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}

	system := defaultSystem
	if *systemPath != "" {
		data, err := os.ReadFile(*systemPath)
		if err != nil {
			return fail(err)
		}
		system = strings.TrimSpace(string(data))
	}
	shots, err := loadExamples(*examplesPath)
	if err != nil {
		return fail(err)
	}
	prefix := append([]message{{"system", system}}, shots...)

	findings, err := readFindings(in)
	if err != nil {
		return fail(err)
	}

	// Prompts are built up front, in input order: reading the sources is
	// fast next to the model, and one goroutine keeps the file cache simple.
	src := newSources(*dir)
	res := make([]result, len(findings))
	prompts := make([][]message, len(findings))
	for i, f := range findings {
		res[i].f = f
		if f.Kind == "private_key" {
			res[i].score, res[i].done = 1, true // always a secret; nothing to ask
			continue
		}
		e, err := locate(src, f, o)
		if err != nil {
			res[i].err, res[i].done = err, true
			if *dry {
				fmt.Fprintf(os.Stderr, "llm-review: %s:%d (fp %s): %v\n", f.File, f.Line, f.FP, err)
			}
			continue
		}
		u := userMessage(f, e)
		if *dry {
			enc := json.NewEncoder(out)
			enc.SetEscapeHTML(false)
			enc.Encode(map[string]string{"fp": f.FP, "user": u})
			continue
		}
		prompts[i] = append(append([]message(nil), prefix...), message{"user", u})
	}
	if *dry {
		for _, r := range res {
			if r.err != nil {
				return 1 // the output lacks the findings reported on stderr
			}
		}
		return 0
	}

	cl := newClient(*url, *timeout)
	if cl.model, err = cl.modelID(); err != nil {
		return fail(fmt.Errorf("%v (is llama-server running at %s?)", err, *url))
	}
	fmt.Fprintf(os.Stderr, "llm-review: model %s, %d findings\n", cl.model, len(findings))

	cache, err := openCache(*cachePath)
	if err != nil {
		return fail(err)
	}
	defer cache.close()

	var st stats
	t0 := time.Now()
	work := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < max(*jobs, 1); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				key := promptKey(cl.model, prompts[i])
				if s, ok := cache.get(key); ok {
					res[i].score = s
					st.add(verdict{}, true, nil)
					continue
				}
				v, err := cl.ask(prompts[i])
				res[i].score, res[i].err = v.Score, err
				st.add(v, false, err)
				if err == nil {
					cache.put(key, v.Score)
				}
				st.progress(len(findings))
			}
		}()
	}
	for i := range res {
		if !res[i].done {
			work <- i
		}
	}
	close(work)
	wg.Wait()
	st.report(time.Since(t0))

	if *sortOut {
		sort.SliceStable(res, func(a, b int) bool {
			ea, eb := res[a].err != nil, res[b].err != nil
			if ea != eb {
				return eb // errors last
			}
			return res[a].score > res[b].score
		})
	}
	failed := 0
	w := bufio.NewWriter(out)
	defer w.Flush()
	for _, r := range res {
		if r.err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "llm-review: %s:%d (fp %s): %v\n", r.f.File, r.f.Line, r.f.FP, r.err)
		} else if r.score < *minScore {
			continue
		}
		w.Write(annotate(r))
		w.WriteByte('\n')
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// annotate appends the llm fields to segscan's object, keeping its field order.
func annotate(r result) []byte {
	raw := bytes.TrimSpace(r.f.raw)
	out := append([]byte(nil), raw[:len(raw)-1]...) // without the closing brace
	if r.err != nil {
		msg, _ := json.Marshal(r.err.Error())
		out = fmt.Appendf(out, `,"llm_score":null,"llm_error":%s}`, msg)
	} else {
		out = fmt.Appendf(out, `,"llm_score":%.4f}`, r.score)
	}
	return out
}

func readFindings(in io.Reader) ([]*finding, error) {
	var fs []*finding
	sc := bufio.NewScanner(in)
	sc.Buffer(nil, 64<<20) // -show prints a base64 image in full
	for n := 1; sc.Scan(); n++ {
		l := bytes.TrimSpace(sc.Bytes())
		if len(l) == 0 {
			continue
		}
		if l[0] != '{' {
			return nil, fmt.Errorf("input line %d is not JSON: run segscan with -json", n)
		}
		f := &finding{raw: append([]byte(nil), l...)}
		if err := json.Unmarshal(l, f); err != nil {
			return nil, fmt.Errorf("input line %d: %v", n, err)
		}
		fs = append(fs, f)
	}
	return fs, sc.Err()
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "llm-review:", err)
	return 2
}

// ---------- cache ----------

// promptKey hashes everything that decides the answer: the model and the
// whole prompt. A changed instruction, example or context gives a new key.
func promptKey(model string, msgs []message) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", model)
	json.NewEncoder(h).Encode(msgs)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// cache keeps scores only (key, score), never the text of a finding.
type cache struct {
	mu sync.Mutex
	m  map[string]float64
	fh *os.File
}

type cacheLine struct {
	K string  `json:"k"`
	S float64 `json:"s"`
}

func openCache(path string) (*cache, error) {
	c := &cache{m: map[string]float64{}}
	if path == "" {
		return c, nil
	}
	if data, err := os.ReadFile(path); err == nil {
		for _, l := range bytes.Split(data, []byte("\n")) {
			var cl cacheLine
			if json.Unmarshal(l, &cl) == nil && cl.K != "" {
				c.m[cl.K] = cl.S
			}
		}
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	c.fh = fh
	return c, nil
}

func (c *cache) get(k string) (float64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.m[k]
	return s, ok
}

func (c *cache) put(k string, s float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[k] = s
	if c.fh != nil {
		line, _ := json.Marshal(cacheLine{k, s})
		c.fh.Write(append(line, '\n'))
	}
}

func (c *cache) close() {
	if c.fh != nil {
		c.fh.Close()
	}
}

// ---------- progress and statistics ----------

type stats struct {
	mu                         sync.Mutex
	asked, cached, errs, lowMs int
	promptN                    int
	last                       time.Time
}

func (s *stats) add(v verdict, cached bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case cached:
		s.cached++
	case err != nil:
		s.errs++
	default:
		s.asked++
		s.promptN += v.PromptN
		if v.Mass < 0.5 {
			s.lowMs++
		}
	}
}

func (s *stats) progress(total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.last) < 10*time.Second {
		return
	}
	s.last = time.Now()
	fmt.Fprintf(os.Stderr, "llm-review: %d/%d\n", s.asked+s.cached+s.errs, total)
}

func (s *stats) report(d time.Duration) {
	fmt.Fprintf(os.Stderr, "llm-review: asked %d, from cache %d, failed %d in %s",
		s.asked, s.cached, s.errs, d.Round(time.Second))
	if s.asked > 0 {
		// If this is close to the whole prompt, the server reprocesses the
		// instruction every time: its prompt cache is not working.
		fmt.Fprintf(os.Stderr, "; %.1f s and %d new prompt tokens per finding",
			d.Seconds()/float64(s.asked), s.promptN/s.asked)
	}
	fmt.Fprintln(os.Stderr)
	if s.lowMs > 0 {
		fmt.Fprintf(os.Stderr, "llm-review: %d answers put less than half the probability on yes/no; check the prompt with -dry\n", s.lowMs)
	}
}

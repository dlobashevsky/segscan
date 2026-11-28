package main

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

var opts = ctxOpts{K: 3, MinSide: 8, MaxSide: 40, MaxLine: 60, MaxFind: 30}

func TestWindowShortLineWhole(t *testing.T) {
	line := []byte(`password: "Xk29fQpL8zR"`)
	e := window(line, 11, 22, opts)
	if e.Before != `password: "` || e.Cand != "Xk29fQpL8zR" || e.After != `"` || e.CutLeft || e.CutRight {
		t.Fatalf("%+v", e)
	}
}

func TestWindowLongLineK(t *testing.T) {
	line := []byte(strings.Repeat("a", 100) + "key=" + "SECRET" + strings.Repeat("b", 100))
	start := 104
	e := window(line, start, start+6, opts) // pad = 3*6 = 18
	if len(e.Before) != 18 || len(e.After) != 18 || !e.CutLeft || !e.CutRight {
		t.Fatalf("%+v", e)
	}
	if !strings.HasSuffix(e.Before, "key=") {
		t.Fatalf("before %q", e.Before)
	}
}

func TestWindowCaps(t *testing.T) {
	// A 10 KB base64 blob: context capped by MaxSide, the blob by MaxFind.
	blob := strings.Repeat("QUJD", 2500)
	line := []byte(`<img src="data:image/png;base64,` + blob + `" alt="logo">`)
	start := strings.Index(string(line), "QUJD")
	e := window(line, start, start+len(blob), opts)
	if len(e.Before) > 40 || len(e.After) > 40 {
		t.Fatalf("context %d/%d", len(e.Before), len(e.After))
	}
	if !strings.Contains(e.Cand, "bytes omitted") || len(e.Cand) > 80 {
		t.Fatalf("cand %q", e.Cand)
	}
	if !strings.Contains(e.Before, "base64,") {
		t.Fatalf("before %q", e.Before)
	}
}

func TestWindowRuneBoundary(t *testing.T) {
	line := []byte(strings.Repeat("é", 40) + "TOKENVALUE" + strings.Repeat("ü", 40))
	start := 80
	e := window(line, start, start+10, ctxOpts{K: 1, MinSide: 7, MaxSide: 7, MaxLine: 10, MaxFind: 100})
	for _, s := range []string{e.Before, e.After} {
		if strings.Contains(s, `\x`) {
			t.Fatalf("split rune: %q", s)
		}
	}
}

func TestEscape(t *testing.T) {
	if got := escape([]byte("a\tb\x01c\xffé")); got != `a\tb\x01c\xffé` {
		t.Fatal(got)
	}
}

func TestLocate(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "conf.yaml"), []byte("a: 1\r\ntoken: Zq8vN2kLpX7wR4tY\n"), 0o644)
	src := newSources(dir)
	f := &finding{File: "conf.yaml", Line: 2, Col: 8, Length: 16, Text: "Zq8vN2kLpX", Truncated: true}
	e, err := locate(src, f, opts)
	if err != nil || e.Before != "token: " || e.Cand != "Zq8vN2kLpX7wR4tY" {
		t.Fatalf("%+v %v", e, err)
	}
	// Moved within the line since the scan: found by text.
	f = &finding{File: "conf.yaml", Line: 2, Col: 1, Length: 16, Text: "Zq8vN2kLpX7wR4tY"}
	if e, err = locate(src, f, opts); err != nil || e.Before != "token: " {
		t.Fatalf("%+v %v", e, err)
	}
	// Gone: falls back to the text, or fails if the text is a preview.
	f = &finding{File: "conf.yaml", Line: 1, Col: 1, Length: 16, Text: "Zq8vN2kLpX7wR4tY"}
	if e, err = locate(src, f, opts); err != nil || !e.NoSource {
		t.Fatalf("%+v %v", e, err)
	}
	f.Truncated = true
	if _, err = locate(src, f, opts); err == nil {
		t.Fatal("want an error")
	}
}

// fakeServer answers like llama-server: P(yes) = 0.9 when the prompt holds
// "token:", 0.05 otherwise.
func fakeServer(t *testing.T, calls *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			w.Write([]byte(`{"data":[{"id":"fake.gguf"}]}`))
		case "/v1/chat/completions":
			atomic.AddInt32(calls, 1)
			var req chatRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.MaxTokens != 1 || !req.Logprobs || req.TemplateKw["enable_thinking"] != false {
				t.Errorf("request %+v", req)
			}
			p := 0.05
			if strings.Contains(req.Messages[len(req.Messages)-1].Content, "token:") {
				p = 0.9
			}
			json.NewEncoder(w).Encode(map[string]any{
				"choices": []any{map[string]any{
					"message": map[string]any{"role": "assistant", "content": "yes"},
					"logprobs": map[string]any{"content": []any{map[string]any{
						"token": "yes", "logprob": math.Log(p),
						"top_logprobs": []any{
							map[string]any{"token": "yes", "logprob": math.Log(p * 0.9)},
							map[string]any{"token": "Yes", "logprob": math.Log(p * 0.1)},
							map[string]any{"token": " no", "logprob": math.Log(1 - p)},
						},
					}}},
				}},
				"timings": map[string]any{"prompt_n": 42},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestScoreEndToEnd(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("token: Zq8vN2kLpX7wR4tY\nsum: 3f9a8c7b6d5e4f3a\n"), 0o644)
	in := `{"commit":"","file":"a.yaml","line":1,"col":8,"bits_per_char":5.1,"length":16,"kind":"entropy","fp":"aaa","text":"Zq8vN2kLpX","truncated":true}
{"commit":"","file":"a.yaml","line":2,"col":6,"bits_per_char":4.6,"length":16,"kind":"entropy","fp":"bbb","text":"3f9a8c7b6d","truncated":true}
{"commit":"","file":"a.yaml","line":9,"col":1,"bits_per_char":0,"length":0,"kind":"private_key","fp":"ccc","text":"-----BEGIN RSA PRIVATE KEY-----","truncated":false}
`
	var calls int32
	srv := fakeServer(t, &calls)
	defer srv.Close()
	cachePath := filepath.Join(dir, "cache")
	run := func(extra ...string) []map[string]any {
		var out bytes.Buffer
		args := append([]string{"-url", srv.URL, "-C", dir, "-cache", cachePath, "-sort"}, extra...)
		if code := cmdScore(args, strings.NewReader(in), &out); code != 0 {
			t.Fatalf("exit %d", code)
		}
		var rows []map[string]any
		for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatal(l, err)
			}
			rows = append(rows, m)
		}
		return rows
	}
	rows := run()
	if len(rows) != 3 || rows[0]["fp"] != "ccc" || rows[1]["fp"] != "aaa" || rows[2]["fp"] != "bbb" {
		t.Fatalf("%v", rows)
	}
	if s := rows[1]["llm_score"].(float64); math.Abs(s-0.9) > 1e-3 {
		t.Fatalf("score %v", s)
	}
	if calls != 2 {
		t.Fatalf("calls %d", calls)
	}
	rows = run("-min", "0.5") // all from the cache now
	if calls != 2 || len(rows) != 2 {
		t.Fatalf("calls %d rows %d", calls, len(rows))
	}
}

func TestDryAndOrder(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("k=Zq8vN2kLpX7wR4tY\n"), 0o644)
	in := `{"file":"a.txt","line":1,"col":3,"bits_per_char":5,"length":16,"kind":"entropy","fp":"aaa","text":"Zq8vN2kLpX7wR4tY"}`
	var out bytes.Buffer
	if code := cmdScore([]string{"-dry", "-C", dir}, strings.NewReader(in), &out); code != 0 {
		t.Fatal(code)
	}
	// A finding not found in its source, with only a preview: skipped, exit 1.
	in2 := in + "\n" + `{"file":"a.txt","line":5,"col":1,"length":16,"kind":"entropy","fp":"bbb","text":"Zq8vN2kLpX","truncated":true}`
	var out2 bytes.Buffer
	if code := cmdScore([]string{"-dry", "-C", dir}, strings.NewReader(in2), &out2); code != 1 || strings.Count(out2.String(), "\n") != 1 {
		t.Fatalf("exit %d, output %q", code, out2.String())
	}
	if !strings.Contains(out.String(), `line: k=<candidate>Zq8vN2kLpX7wR4tY</candidate>"`) {
		t.Fatal(out.String())
	}
}

func TestAnnotateKeepsOrder(t *testing.T) {
	f := &finding{raw: []byte(`{"commit":"","file":"x","fp":"aaa"}`)}
	if got := string(annotate(result{f: f, score: 0.25})); got != `{"commit":"","file":"x","fp":"aaa","llm_score":0.2500}` {
		t.Fatal(got)
	}
}

func TestEval(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow")
	os.WriteFile(allow, []byte("# known\npath:vendor/\nAAA\nbbb # uuid\n"), 0o644)
	in := `{"file":"a","line":1,"fp":"aaa","llm_score":0.01}
{"file":"a","line":2,"fp":"bbb","llm_score":0.6}
{"file":"a","line":3,"fp":"ccc","llm_score":0.95}
{"file":"a","line":4,"fp":"ddd","llm_score":null,"llm_error":"x"}
`
	var out bytes.Buffer
	if code := cmdEval([]string{"-allow", allow}, strings.NewReader(in), &out); code != 0 {
		t.Fatal(code)
	}
	s := out.String()
	for _, want := range []string{"known false positives (fp in " + allow + "): 2", "others: 1", "without a score (llm_error): 1",
		"0.50           1   50.0%                    0"} {
		if !strings.Contains(s, want) {
			t.Fatalf("no %q in\n%s", want, s)
		}
	}
}

func TestNoServerNeeded(t *testing.T) {
	dead := []string{"-url", "http://127.0.0.1:1"}
	var out bytes.Buffer
	if code := cmdScore(dead, strings.NewReader(""), &out); code != 0 || out.Len() != 0 {
		t.Fatalf("empty input: exit %d, output %q", code, out.String())
	}
	in := `{"file":"k.pem","line":1,"col":1,"length":0,"kind":"private_key","fp":"ccc","text":"-----BEGIN RSA PRIVATE KEY-----"}`
	if code := cmdScore(dead, strings.NewReader(in), &out); code != 0 || !strings.Contains(out.String(), `"llm_score":1.0000`) {
		t.Fatalf("private key only: exit %d, output %q", code, out.String())
	}
}

func TestNegativeContextRejected(t *testing.T) {
	for _, f := range []string{"-k", "-minctx", "-maxctx", "-maxline", "-maxfind"} {
		var out bytes.Buffer
		if code := cmdScore([]string{"-dry", f + "=-1"}, strings.NewReader(""), &out); code != 2 {
			t.Fatalf("%s=-1: exit %d", f, code)
		}
	}
}

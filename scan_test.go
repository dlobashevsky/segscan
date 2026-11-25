package main

import "testing"

// The tests run on the built-in model alone, with no repository training.
func found(t *testing.T, line string) []string {
	t.Helper()
	if baseModel == nil {
		t.Skip("no built-in model")
	}
	var out []string
	NewScanner(baseModel, defaultOpts).Line([]byte(line), func(_ int, text []byte, _, _ float64) {
		out = append(out, string(text))
	})
	return out
}

func TestSecretsAreFound(t *testing.T) {
	for _, line := range []string{
		"X-API-Key: 5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5q",
		`  password: "kT7#vQ2m!xZ9"`,
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		`"token":"3fa85f6457174562b3fc2c963f66afa6",`,
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	} {
		if len(found(t, line)) == 0 {
			t.Errorf("missed: %s", line)
		}
	}
}

func TestOrdinaryTextIsQuiet(t *testing.T) {
	for _, line := range []string{
		"# example: password12345",
		"password: changeme",
		"func (s *Server) handleAuthorizationRequest(w http.ResponseWriter, r *http.Request) {",
		"    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"listen_addresses = '0.0.0.0'  # which interfaces to listen on",
		"mot_de_passe_utilisateur = identifiant_de_connexion",
		"const maxValue = 0xFFFFFFFFFFFFFFFF",
		"/usr/local/share/ca-certificates/extra/internal-root.crt",
	} {
		if f := found(t, line); len(f) != 0 {
			t.Errorf("false positive %q in: %s", f, line)
		}
	}
}

func TestDiffParser(t *testing.T) {
	diff := "commit abc123\ndiff --git a/x.conf b/x.conf\n--- a/x.conf\n+++ b/x.conf\n@@ -3,0 +4,2 @@ ctx\n+first\n+++ tricky\n@@ -9 +11 @@\n-old\n+new\n"
	type add struct {
		file string
		line int
		text string
	}
	var got []add
	err := scanDiff(stringsReader(diff), func(commit, file string, line int, text []byte) {
		got = append(got, add{file, line, string(text)})
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []add{{"x.conf", 4, "first"}, {"x.conf", 5, "++ tricky"}, {"x.conf", 11, "new"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d: %v, want %v", i, got[i], want[i])
		}
	}
}

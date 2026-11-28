package main

import (
	"strings"
	"testing"
)

func TestMarkLine(t *testing.T) {
	for _, c := range []struct {
		file, in string
		line     int
		want     string // "" = refused
	}{
		{"a.yaml", "db:\n  password: abc123\n", 2, "db:\n  password: abc123 # segscan:allow\n"},
		{"a.yaml", "k: \"a#b\"\n", 1, ""}, // any # on the line refuses
		{"a.yaml", "k: \"ab\"\n", 1, "k: \"ab\" # segscan:allow\n"},
		{"a.yaml", "name: don't\n", 1, "name: don't # segscan:allow\n"},
		{"a.yaml", "k: v # note\n", 1, ""},       // never into an existing comment
		{"a.yaml", "k: \"abc\n  def\"\n", 1, ""}, // quoted scalar open at the end
		{"a.yaml", "cert: |\n  ABC\n", 2, ""},    // block scalar
		{"a.yaml", "cert: >-\n  ABC\n", 2, ""},   // folded block scalar
		{"a.yaml", "k: abc\n  def\n", 1, ""},     // multi-line plain scalar
		{"a.yaml", "k: abc\n  def\n", 2, ""},     // its continuation
		{"a.sh", "TOKEN=abc\n", 1, "TOKEN=abc # segscan:allow\n"},
		{"a.sh", "echo \"a\nb\nc\"\n", 2, ""},   // inside a string spanning lines
		{"a.sh", "echo \"a\nb\"\nX=1\n", 3, ""}, // after a string over two lines: in doubt, no
		{"a.sh", "echo \"a b\"\nX=1\n", 2, "echo \"a b\"\nX=1 # segscan:allow\n"},
		{"a.sh", "cat <<EOF\nsecret\nEOF\n", 2, ""}, // heredoc
		{"a.sh", "a=1 \\\n  b=2\n", 1, ""},          // continued
		{"a.go", "x := \"abc\"\n", 1, "x := \"abc\" // segscan:allow\n"},
		{"a.go", "x := `abc\nkey\n`\n", 2, ""}, // raw string
		{"a.go", "x := \"a // b\n", 1, ""},     // unterminated
		{"a.rs", "fn f<'a>(x: &'a str) {}\n", 1, "fn f<'a>(x: &'a str) {} // segscan:allow\n"},
		{"a.xml", "<pass>abc</pass>\n", 1, ""}, // XML, SQL: not offered
		{"a.xml", "<a b=\"x\n y\">\n", 1, ""},
		{"a.xml", "<v>\nabc\n</v>\n", 2, ""},
		{"a.xml", "<![CDATA[\n<x>a</x>\n]]>\n", 2, ""},
		{"nginx/x.conf", "auth_basic_user_file /x; \r\n", 1, "auth_basic_user_file /x;  # segscan:allow\r\n"},
		{"other.conf", "a = b\n", 1, ""},
		{"a.json", "{\"k\": \"v\"}\n", 1, ""},
		{".env", "K=v\n", 1, ""},
		{"Dockerfile", "ENV K=v\n", 1, ""},
		{"a.ini", "k = v\n", 1, ""},
		{"a.py", "k = '''x\ny'''\n", 2, ""},
		{"a.yaml", "k: v\n", 2, ""},                                   // no such line
		{"a.rs", "let s = r#\"first\nsecret\nlast\"#;\n", 2, ""},      // Rust raw string
		{"a.rs", "let s = br\"a\nb\";\n", 2, ""},                      // byte raw string
		{"a.java", "String s = \"\"\"\n  secret\n  \"\"\";\n", 2, ""}, // text block
		{"a.kt", "val s = \"\"\"\nsecret\n\"\"\"\n", 2, ""},
		{"a.cs", "var s = @\"a\nsecret\";\n", 2, ""},
		{"a.cpp", "auto s = R\"(a\nsecret)\";\n", 2, ""},
		// no false alarm: a string ending in r is not a raw string
		{"a.rs", "let u = \"user\";\n", 1, "let u = \"user\"; // segscan:allow\n"},
		{"a.rs", "let s = \"first\nsecret\nlast\";\n", 2, ""},          // a Rust string over lines
		{"a.rs", "let s = cr#\"first \" x\nsecret\nlast\"#;\n", 2, ""}, // raw C string
		{"a.sh", "#!/nix/store/abc-bash/bin/sh\n", 1, ""},              // shebang
		{"a.py", "#!/usr/bin/env python3\nx = 1\n", 1, ""},
		{"a.sh", "x=1 # shellcheck disable=SC2034\n", 1, ""}, // a tool's directive
		{"a.yaml", "k: v # yamllint disable-line\n", 1, ""},
		{"a.py", "k = 1  # noqa: E501\n", 1, ""},
		{"a.sql", "SELECT `first\nsecret\nlast`;\n", 2, ""},    // MySQL identifier over lines
		{"a.sh", "x=$'first\\' quote\nsecret\nlast'\n", 2, ""}, // ANSI-C quoting
		{"a.go", "f(x);// nolint:errcheck\n", 1, ""},           // directive without a space
		{"a.go", "f(x);// plain note\n", 1, ""},
		{"a.go", "//line gen.go:10\n", 1, ""},                             // Go directive
		{"a.yaml", "key: \"first\n  password: secret\n  last\"\n", 2, ""}, // inside a quoted scalar
		{"a.yaml", "k: [a,\n  b: c]\n", 2, ""},                            // inside a flow sequence
		{"a.yaml", "k: [a, b]\nx: y\n", 2, "k: [a, b]\nx: y # segscan:allow\n"},
		{"a.yaml", "key: !!str \"first\n  password: secret\n  last\"\n", 2, ""}, // tag before the quote
		{"a.yaml", "key: &a \"first\n  password: secret\n  last\"\n", 2, ""},    // anchor
		{"a.py", "x=1# noqa: E501\n", 1, ""},                                    // # without a space
		{"a.sh", "x=1;# shellcheck disable=SC2034\n", 1, ""},
		{"a.sh", "echo a#b\n", 1, ""},                         // in doubt: any # on the line
		{"a.js", "const a = <div>\nsecret\n</div>;\n", 2, ""}, // JS/TS: not offered (JSX)
		{"a.sh", "echo 'it''s'\n", 1, "echo 'it''s' # segscan:allow\n"},
		{"a.go", "u := \"server\"\n", 1, "u := \"server\" // segscan:allow\n"},
		{"a.sql", "insert into t values ($p$a\nsecret\n$p$);\n", 2, ""}, // tagged dollar quote
		{"a.sql", "select 1;\n", 1, ""},
		{"a.rb", "s = \"a\nsecret\"\n", 2, ""}, // Ruby and Perl: not offered
		{"a.pl", "my $s = 1;\n", 1, ""},
		{"nginx/n.conf", "return 200 \"a\nsecret\nb\";\n", 2, ""},            // nginx strings span lines
		{"a.sql", "insert into t values (E'it\\'s\nsecret\nend');\n", 2, ""}, // E'...' with \'
		{"a.sql", "SELECT [first\nsecret\nlast];\n", 2, ""},                  // bracketed identifier
		{"a.cs", "var s = @$\"a\nsecret\nb\";\n", 2, ""},                     // @$"..."
		{"a.cs", "var s = $@\"a\nsecret\nb\";\n", 2, ""},                     // $@"..."
		{"a.xml", "<!-- a > b\n<x>y</x>\n-->\n", 2, ""},                      // inside a comment
		{"a.xml", "<v>\nsecret >\n</v>\n", 2, ""},                            // > in text
	} {
		got, err := markLine(c.file, []byte(c.in), c.line)
		switch {
		case c.want == "" && err == nil:
			t.Errorf("%s:%d %q: want a refusal, got %q", c.file, c.line, c.in, got)
		case c.want != "" && err != nil:
			t.Errorf("%s:%d %q: %v", c.file, c.line, c.in, err)
		case c.want != "" && string(got) != c.want:
			t.Errorf("%s:%d %q:\ngot  %q\nwant %q", c.file, c.line, c.in, got, c.want)
		}
	}
	// Already marked: unchanged.
	in := "k: v # segscan:allow\n"
	if got, err := markLine("a.yaml", []byte(in), 1); err != nil || string(got) != in {
		t.Errorf("already marked: %q %v", got, err)
	}
}

func TestEscapes(t *testing.T) {
	if got := gitignoreEscape("a*b/[x]\\ "); got != `a\*b/\[x\]\\\ ` {
		t.Errorf("gitignore: %q", got)
	}
	if _, err := allowPathLine("a b.txt"); err == nil || !strings.Contains(err.Error(), "white space") {
		t.Errorf("a path with a space should be refused: %v", err)
	}
	if line, err := allowPathLine("d/we*ird?.txt"); err != nil || line != `path:/d/we\*ird\?.txt` {
		t.Errorf("%q %v", line, err)
	}
}

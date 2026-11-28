# segscan

A statistical secret scanner. It does not match patterns; it measures
"surprise": a string is segmented into known words and letter patterns, and
whatever cannot be segmented cheaply is reported.

## Build

    go build -o segscan .
    go test .

No dependencies. The built-in model `base.model` is embedded into the binary.

## Usage

    segscan scan                             # what git would commit: tracked and untracked files,
                                             # not ignored ones, not .sec/
    segscan scan conf/ app.yaml              # the same, under these paths
    segscan scan -scanall .                  # every file, ignored ones and .sec/ too
    git log -p --all -U0 | segscan diff      # full history, unique findings
    segscan train -guard                     # repository model -> .git/segscan.model
    segscan model check                      # dictionary words of the model that look like keys
    segscan explain 'X-API-Key: ...'         # why a line did (not) trigger
    segscan calib files...                   # noise and recall at the current thresholds
    segscan install                          # pre-commit hook in the current repository

Without a trained model the built-in one is used. Training on the repository
lowers the noise: its own identifiers and abbreviations become known words.

Exit code: 0 clean, 1 findings, 2 error.

## Output

TSV with a header line (`-no-header` drops it):

    commit  file  line  col  bits_per_char  length  excess_bits  count  kind  fp  text

| Column | Meaning |
|---|---|
| `commit` | commit hash in `diff` mode, empty otherwise |
| `file`, `line`, `col` | position of the finding (1-based) |
| `bits_per_char` | average cost of a character in the finding |
| `length` | length of the finding in bytes |
| `excess_bits` | accumulated cost above the `-tau` threshold |
| `count` | number of occurrences (`diff` mode groups by `fp`) |
| `kind` | `entropy` or `private_key` |
| `fp` | fingerprint of the finding, used in the allowlist |
| `text` | first `-preview` chars (default 10), `...` if cut; `-show` prints all |

In `text`, tab, backslash and every byte outside printable ASCII are written
as `\t`, `\\` and `\xNN`.

`-json` prints JSON Lines instead: one object per finding with the same
fields plus `truncated`.

Sorting by confidence:

    segscan scan -no-header | sort -t$'\t' -k5,5nr

`-bpc N` keeps only findings with at least N bits per char. Random base58 or
base64 scores about 5.5-6.5, hex about 4.5-5, file paths and odd identifiers
about 3.5-4.5.

## False positives

- `.segscan-allow` in the repository root: one `fp` per line, or `path:glob`
  to skip files. `#` starts a comment.
- `segscan:allow` on the line itself: the line is not scanned.
- The same from the command line, without editing by hand:

      segscan allow fp FP...            # fingerprints, with a "# file:line" comment
      segscan allow path FILE...        # path:/FILE, escaped
      segscan allow line FILE:LINE...   # segscan:allow in a comment on the line
      segscan ignore FILE...            # /FILE in .gitignore, and out of the index

  `-n` only prints what would be done. `allow line` writes a comment only
  where it is certainly a comment: for known file types (shell, Python,
  YAML, TOML, Go/C/Rust/JVM/C#, Lua, nginx), never inside a string, a
  comment, a YAML block or multi-line scalar, a heredoc or a raw string,
  never on a `#!` line or a line that already has a comment. In shell, Rust
  and nginx, where strings may run over lines, every line up to the
  marked one must close its quotes however a backslash is read. JSON,
  INI, `.env`, Dockerfiles, SQL, XML/HTML, JS/TS, Ruby and Perl are
  refused: use `allow fp`. `ignore` refuses a file committed in `HEAD`
  without `-history`, a directory, and a file whose staged version
  differs from both the file and `HEAD`: ignoring it does not take the
  value out of the history.
- `word:<word>` in `.segscan-allow`: `model check` accepts that dictionary
  word.
- Lock files, `*.min.js` and `*.map` are always skipped
  (`-no-default-excludes` turns this off).
- `-----BEGIN CERTIFICATE-----` blocks are skipped; a `PRIVATE KEY` block is
  always a finding.
- [contrib/llm-review](contrib/llm-review/README.md) scores the findings with
  a local LLM (llama.cpp on the CPU), to sort and thin the ones checked by
  hand.

## How it works

1. A line is split into chunks at whitespace and quotes.
2. Every character gets a cost in bits:
   - a letter: from a trigram model inside the word (the context resets at a
     camelCase boundary), plus penalties for case changes and letter/digit
     switches;
   - a digit: 3.32 bits; `_-./`: 1 bit; other punctuation: 2.5;
     `:=,;()[]{}<>`: 0.
3. Dynamic programming over positions picks the cheapest segmentation into
   single characters and dictionary words (a word must be lower, UPPER or
   Capitalized).
4. The threshold `-tau` is subtracted from every character cost and the
   segments with the maximum sum are found. A segment is a finding if its sum
   is at least `-excess`.
5. If a word such as `password`, `token`, `key`, `secret` or `auth` precedes
   on the line, the sum threshold is multiplied by `-kw` (default 0.5). These
   words find nothing by themselves.

The working model is the built-in one (Go sources plus English and French
word lists) mixed 50/50 with the repository model. The character model is
trained on the vocabulary, not on the token stream; otherwise a few very
frequent identifiers drown the statistics.

A word enters the dictionary if it occurs at least 3 times in 2 files, and,
from 6 letters on, if it is "pronounceable": it costs at most 4.5 bits per
letter under the character model.

That does not keep keys out. The model learns from the same tree it then
scans, so a key copied into three node configs becomes a dictionary word.
It is then stored in clear in the model, and the scan with that model no
longer reports it. The "pronounceable" test is made with the character
model trained on that tree, which has learnt the key's letters too.

Safeguards:

- `segscan train -guard`: every line is first scanned with the built-in
  model, and a letter fragment inside one of its findings is not counted,
  unless the finding's fp is in the allowlist. Other occurrences of the
  same fragment count as usual. A key is found only inside findings, so it
  never becomes a word. The price: what the built-in model reports is
  learnt only once its fp is in the allowlist, so a guarded model leaves
  more false positives until they are reviewed. The guard uses the default
  thresholds, not `scan_bpc` or `scan_minlen`; `-guard-bpc N` counts only
  findings of at least N bits per char. Entries of `-words` lists that the
  built-in model reports are left out as well.
- `segscan model check`: the dictionary words of length 6 and more that
  look random under the built-in model (above 4.0 bits per letter, `-maxbpc`),
  and, with the keystore, the words that are letter fragments of a value.
  Exit 1 if there are any. A harmless word is accepted with a `word:<word>`
  line in the allowlist. Expect some: names and glued words reach about 4.9
  bits per letter, while about 1% of random 6-letter strings, and fewer of
  the longer ones, cost less than 4.0. Raising `-maxbpc` to 5.0 would let
  through more than 5% of random strings of any length. `-since REV` also lists the words added since the
  model in that git revision.
- `hook_model = warn` or `block` in `.sec/config`: the pre-commit hook runs
  model check on a staged model that differs from `HEAD`'s. Off by default.

A safe order: scan with the built-in model (no trained model yet), review
the findings and put the false positives into the allowlist, `train
-guard`, `model check`, commit the model.

## Thresholds

Defaults: `-tau 3.0 -excess 14 -minlen 6 -kw 0.5`. They were chosen on open
repositories (Kong, nginx, Prometheus). To check them on your own data:

    segscan calib $(git ls-files | head -500)

To add your own words (transliteration, internal abbreviations):

    segscan train -words mywords.txt

## What it does not see

- Passwords made of dictionary words (`Summer2026`): cheap by construction.
- Purely numeric secrets.
- Short hex (8-12 chars) with no keyword on the line.
- Secrets split by whitespace or quotes.
- Binary files (a NUL in the first 8000 bytes skips the file) and files over
  8 MiB.
- In a git repository, files git ignores and `.sec/`, unless named
  explicitly or `-scanall` is given.

## Configuration repositories

A repository with a `.sec/` directory keeps its credentials out of git:
files hold placeholders such as `!SECKEY_ch_sts_<uuid>!`, and the values live
in a keystore outside the repository. How to use it today is in
[MANUAL.md](MANUAL.md); the full design is in [DESIGN.md](DESIGN.md).

Anywhere (no keystore needed):

    segscan init                       # .sec/, and core.hooksPath -> .sec/hooks
    segscan key add ch_sts -scope 'nodes/*/etc/nginx/**'
                                       # prints the placeholder to use
    segscan key list                   # keys and where they are used
    segscan manifest fix               # owner, group, mode for new files under nodes/*
    segscan check                      # blocking checks of the working tree
    segscan check -staged | -range A..B | -all

On the deploy machine (with the keystore):

    segscan key set ch_sts [-gen 32]   # a value from stdin, or a random base58 one
    segscan key check [-weak]          # names <-> keystore
    sudo segscan import -node n1 /etc/nginx/nginx.conf
                                       # live file -> tree, values -> placeholders
    segscan expand -node n1 -to /srv/stage/n1
                                       # tree -> staging directory, placeholders -> values

`check` blocks on malformed placeholders, unknown keys or uuids, keys used
outside their scope, files without a manifest entry, forbidden paths
(`forbid` in `.sec/config`, the keystore) and private keys; with the
keystore, also on any known value (current or retired, in any of its
forms, in text, binary files, gzip and ZIP). The pre-commit hook installed
by `init` runs `check -staged` and then the statistical scan of the added
lines as a warning; the pre-push hook runs `check -range`.

Inside `.sec/` the model is `.sec/segscan.model`, the allowlist
`.sec/allow`, and placeholders and UUIDs are not scored (`skip_uuids` in
`.sec/config`). Elsewhere `-skip-uuids` does the same; without it nothing
changes.

## Data behind the built-in model

- Go sources (BSD-3-Clause);
- npm `an-array-of-english-words` and `an-array-of-french-words` (MIT).

To rebuild it:

    : > base.model && go build -o segscan .
    ./segscan train -top 60000 -words en.txt,fr.txt -m base.model $(go env GOROOT)/src
    go build -o segscan .

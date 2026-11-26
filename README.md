# segscan

A statistical secret scanner. It does not match patterns; it measures
"surprise": a string is segmented into known words and letter patterns, and
whatever cannot be segmented cheaply is reported.

## Build

    go build -o segscan .
    go test .

No dependencies. The built-in model `base.model` is embedded into the binary.

## Usage

    segscan scan                             # the whole working tree (git ls-files)
    segscan scan conf/ app.yaml              # selected paths
    git log -p --all -U0 | segscan diff      # full history, unique findings
    segscan train                            # repository model -> .git/segscan.model
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
- Lock files, `*.min.js` and `*.map` are always skipped
  (`-no-default-excludes` turns this off).
- `-----BEGIN CERTIFICATE-----` blocks are skipped; a `PRIVATE KEY` block is
  always a finding.

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

To keep secrets out of the dictionary during training, a word must occur at
least 3 times in 2 files, and words of 6 letters or more must also be
"pronounceable" under the character model.

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
- Binary files (a NUL in the first 8000 bytes skips the file).

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

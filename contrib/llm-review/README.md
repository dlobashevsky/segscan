# llm-review

Scores segscan findings with a local LLM: how likely each one is a real
secret. It is for sorting and thinning the findings you check by hand. It is
not a filter in the hooks: run it yourself, on demand.

    segscan scan -json . | llm-review -sort > scored.jsonl

llm-review scores whatever segscan prints, so segscan's file set decides
what gets reviewed. In a git repository `segscan scan` (with `.` or without
paths) reads what git would commit: tracked files and files not yet added,
but not ignored ones and not `.sec/`. `-scanall` walks everything except
`.git/` and `node_modules/`. Either way segscan's own exclusions still apply: `path:` lines of the
allowlist, lock files, `*.min.js`, `*.map`, binary files, files over 8 MiB
and anything that is not a regular file (see "False positives" and "What it
does not see" in the [segscan README](../../README.md)). A threshold in
`.sec/config` (`scan_bpc`) applies too; `-bpc 0` lifts it.

Every output line is segscan's JSON object plus `llm_score`: the probability,
0..1, that the finding is a secret. The model answers `yes` or `no`, and the
score is P(yes) / (P(yes) + P(no)), read off the probabilities of that one
token. So it is a continuous score, not a 0/1 verdict, and the model
generates a single token per finding. Without `-sort` the input order is
kept.

A separate Go module with no dependencies; segscan itself does not change.

    cd contrib/llm-review && go build -o llm-review .

## Server

`docker-compose.yml` runs `llama-server` from the official llama.cpp image
on the CPU:

    cp .env.example .env      # MODELS_DIR, MODEL_FILE, THREADS
    docker compose up -d
    curl -s 127.0.0.1:8080/health

- The port is published on 127.0.0.1 only.
- The model is a local file mounted read-only, so the server never goes out
  to the network.
- Nothing is written to disk: there is no `--slot-save-path` and no
  verbose log.
- `/slots`, which would show the prompts being processed, is turned off.
- Thinking is off (`enable_thinking: false`, set on the server and in every
  request).

A model split into parts (`...-00001-of-00002.gguf`, `...-00002-of-00002.gguf`)
is normal for large GGUF files: download both parts into one directory and
name the first one in `MODEL_FILE`. A file named `mmproj-*.gguf` is the
image encoder of a multimodal model; llm-review does not need it.

## Context

The model gets the file path, the length and bits per char of the finding,
and the line around it, with the finding between `<candidate>` and
`</candidate>`.

- A line up to `-maxline` bytes (200) goes in whole.
- On a longer line each side gets `-k` × the finding's length (3), at least
  `-minctx` (24) and at most `-maxctx` (200) bytes.
- A finding longer than `-maxfind` (120) is shown as
  `head…[N bytes omitted]…tail`. A base64 image is recognisable from its first
  and last few dozen chars and from the `data:image/png;base64,` before it.

The line is read from the file (`-C` is the directory segscan ran in). For
`segscan diff` output, it is read from the commit with `git show`. If the line
no longer holds the finding, segscan's own text is used without context; that
needs `-show`, since the default 10-char preview is not enough.

`-dry` prints what the model would see, as JSON Lines, without a server:

    segscan scan -json . | llm-review -dry | head

## Instruction and examples

The built-in instruction is in `llm.go` (`defaultSystem`). `-system FILE`
replaces it; it must still ask for a one-word `yes` / `no` answer.

Where a value stands does not make it harmless: the instruction counts a
credential-like value as a secret also in a comment, in commented-out code,
in documentation and in tests, and lets off only obvious placeholders
(`changeme`, `${VAR}`, `xxxx`). Without that, a real password behind `#` got
0.2 while segscan gave it 6 bits per char. A repository whose tests are full
of made-up passwords says so with examples, below.

`-examples FILE` adds few-shot examples, one per line:

    {"user": "file: conf/app.yaml\nstring: 24 bytes, 5.62 bits per char\nline: token: <candidate>...</candidate>", "answer": "yes"}

The `user` text is in the same form as `-dry` prints it, so examples can be
copied from there. The examples are a fixed prefix of every prompt, so the
server's prompt cache processes them once. What counts as a false positive
depends on the repository (dataset identifiers, test passwords), and the
examples are the place to say it.

## Cache

`-cache FILE` keeps scores by a hash of the model name and the whole prompt.
A rerun asks only for new or changed findings. A different instruction,
examples file, context setting or model gives new keys. The file holds the
hash and the score only, never the text:

    segscan scan -json . | llm-review -cache .git/segscan-llm.cache

## Evaluation against the allowlist

The fingerprints in the allowlist are false positives someone has already
checked, so they serve as the negatives. Scan without them, but keep the
allowlist's `path:` lines, or whole directories come back:

    grep '^[[:space:]]*path:' .segscan-allow > /tmp/paths.allow
    segscan scan -allow /tmp/paths.allow -json . | llm-review -cache .git/segscan-llm.cache > scored.jsonl
    llm-review eval -allow .segscan-allow < scored.jsonl

In a repository with `.sec/`, the allowlist is `.sec/allow`.

`eval` prints, for a range of thresholds, how many known false positives fall
below the threshold (would be filtered out) and how many other findings fall
below it (would be hidden). It then lists the known false positives with the
highest scores and the other findings with the lowest. The others are real
secrets mixed with findings nobody has looked at, so the second column is an
upper bound on what a threshold would hide. For real positives, add
`segscan diff` findings from history, where secrets were committed before
they moved to the keystore.

If you take few-shot examples from the allowlist, evaluate on the rest of
it, not on the same entries.

## Speed

On the CPU nearly all the time goes to processing the prompt; the answer is
one token. At the end llm-review prints the seconds and the new prompt
tokens per finding:

- About 100-200 new tokens per finding: the server's prompt cache works, and
  the instruction and examples are processed once.
- Close to the whole prompt: they are processed again for every finding.
  This happens with hybrid models (recurrent layers next to attention),
  which can reuse a prefix only from a checkpoint. Set
  `CHECKPOINT_MIN_STEP=0` in `.env`, or keep the instruction and examples
  short.

`-j` (2) is the number of requests in flight; give the server the same
`SLOTS`. More does not help on a CPU, since prompt processing already uses
every core.

## Exit code

0 if every finding got a score, 1 if some did not (they are printed with
`"llm_score": null` and `llm_error`, and reported on stderr), 2 on an error.
With `-dry`, 1 means some findings were not found in their source and are
missing from the output (see stderr).

# segscan tui: reviewing findings before a commit

Status: **draft, not implemented**. This is the requirements text for
discussion. The open questions are at the end.

## Goal

Go through the statistical findings of the working tree, decide on each,
and apply all the decisions at once, after one confirmation. It is run by
hand, usually before `git add`, always before `git commit`.

The TUI looks at the working tree only, never at the git history. It
follows `.sec/allow`, `.sec/config` and the other segscan settings.

## 1. Which files are scanned

This needs a change to `segscan scan` itself, so that the TUI, `scan` and
`check` all see the same files.

| Call | Files |
|---|---|
| `segscan scan` in a git repository | tracked and untracked files, without ignored ones (`git ls-files -co --exclude-standard`, the set `check` already uses), without all of `.sec/` |
| `segscan scan PATH...` in a git repository | the same set, limited to PATH |
| `segscan scan -scanall PATH...`, or outside git | every file under PATH except `.git/` and `node_modules/`: for a directory that is not in git |

In every mode the allowlist (`path:` lines and fingerprints), the default
excludes and the limits of `readText` (binary files, files over 8 MiB,
non-regular files) still apply.

This changes `scan .`: today it walks the directory and also reads ignored
files and `.sec/` (word lists, for example).

## 2. Launch

The TUI runs segscan itself; it does not read saved JSON. It has to rescan
after every save, and it needs a second scan for the "show allowed" mode.

The launch screen shows the parameters and lets you edit them:

- paths;
- `-bpc` and `-minlen`, with the values from `.sec/config` by default;
- show allowed findings (a scan with the `path:` lines of the allowlist
  only);
- LLM: on or off, server address, context settings.

The last used parameters are kept in `segscan-tui` in the git directory
(local, never committed; found with `git rev-parse --git-path`, since in a
linked worktree `.git` is a file), together with the display settings:

| Setting | Meaning |
|---|---|
| `preview_lines` | lines shown above and below the finding |
| `preview_width` | how much of a long line is shown; the start of the line is always shown, then the part around the finding |
| `mask` | how many characters of a value the summary shows (0: none) |

**LLM.** Scoring runs in the background, at about 50 findings a minute on
the CPU. The list appears at once with bpc only, and the scores fill in as
they arrive. Scores are cached in `segscan-llm.cache` in the git directory. The cache key
includes the context, so a rescan asks the model only about findings that
are new or whose line changed.

## 3. List

- **Columns:** marker, llm score, bpc, `file:line`, preview.
- **Sort orders:** `[file, bpc, llm]`, `[bpc, llm, file]`, `[llm, bpc, file]`.
  Findings without a score go last when sorting by llm.
- **Filters:** hide marked rows; one file only.
- **Grouping:** a file's findings can be folded into one row, so a series
  (`nvme0n1p3`, `nvme2n1p2`, ...) takes one decision.
- **Allowed findings:** in "show allowed" mode they are shown dimmed, with
  the marker `a`.
- **Status line:** the planned action of the current row (6).

## 4. Preview

- **Context:** `preview_lines` lines above and below, with the finding
  highlighted. A long line (base64) shows its start and the part around
  the finding, up to `preview_width`.
- **Value boundaries.** A finding is the most random stretch of a string,
  which may be only part of a password: `Summer2026Xk9Pq` can be reported as
  `Xk9Pq`. For action K the boundaries therefore default to the whole value
  (the chunk between quotes or spaces, without a `key=` prefix), and start
  and length can be moved with the keys before marking.

## 5. Actions

Actions are only marked. Nothing is written until a save (7). A row has at
most one action.

The allowlist is the one the scan uses: `.sec/allow` in a `.sec/`
repository, `.segscan-allow` otherwise, or the file given with `-allow` on
the launch screen.

| Key | Action | Marker | Notes |
|---|---|---|---|
| `I` | file → `.gitignore` | `I`, colour 1 | the root `.gitignore`, anchored (`/path/file`), glob characters escaped. An ignore rule does not stop git from tracking a file it already tracks, so a tracked file is also removed from the index (`git rm --cached`; the file stays on disk). A file in the index but not in `HEAD`: nothing reaches the history. A file in `HEAD`: a separate confirmation, with the warning that the value is in the history. A file with a `.sec/manifest` entry: warning, `check` will miss the file in a clean clone |
| `F` | file → allowlist (`path:/file`) | `F`, colour 2 | not for `private_key` rows: `check` does not honour `path:` lines for private keys |
| `A` | fingerprint → allowlist | `A`, colour 3 | applies to every finding with that fp in the tree; all of them are coloured, and the status line says how many there are and in how many files. Not for `private_key` rows: their fp is computed from the `BEGIN ... PRIVATE KEY` line, the same for every key with that marker, so one allow would hide them all |
| `M` | `segscan:allow` in a comment on the line | `M`, colour 3 | the comment syntax comes from the file type (`#`, `//`, `--`, `;`, `<!-- -->`). Offered only where the end of the line is certainly outside a string: not in JSON, not inside quoted strings, YAML block scalars, heredocs and the like, not for an unknown type. In doubt, not offered |
| `K` | value → keystore, placeholder in the file | `K`, colour 4 | only with a keystore on this machine; see 5.1 |
| `U` | unmark | | |
| `E` | open in `$EDITOR` at the line | | the file is rescanned on return |

- **Overlaps.** An action on a whole file (`I`, `F`) overrides the row
  actions in that file. Those rows are shown as overridden, and they come
  back if the file action is unmarked.
- **Not only colour.** The marker letter is always shown next to the
  colour, so the marks can be told apart on a monochrome terminal too.

### 5.1 Action K

K is offered only when the keystore of `.sec/config` exists on this machine
(it may be empty). Without a keystore only `I`, `F`, `A` and `M` are left:
no names, no placeholders, no transforms.

- **Name.** The user types it, in the format of `.sec/names` (letters,
  digits, `_`, `.`); the TUI checks that it is free. The uuid is made by
  `key add` as usual. Nothing computed from the value goes into the name:
  `.sec/names` is committed, and a hash of a weak password can be
  brute-forced.
- **Scope.** Suggested from the path (`nodes/n1/etc/nginx/**`).
- **`-base58`.** Suggested if the value looks like one of our generated
  keys.
- **Transform.** Offered if the value stands inside quotes or a URL. The
  resulting placeholder is shown before marking.

| Situation | What K does |
|---|---|
| the value is already in the keystore under name N | only puts N's placeholder in; if N's scope does not cover the file, offers to widen it |
| a new name | `key add` + `key set` + placeholder |
| the name exists with another value | not offered: rotation is not the TUI's job (vault and other tools) |
| the value has characters a key cannot hold (space, quotes, `\`, `#`, several lines) | not offered; it has to be a secret file (stage 3) |

Keystores on different machines may hold different sets of keys; that is
accepted.

## 6. Saving

- **When.** Files are written only on "save" (a menu item or key) or on
  exit after confirmation. "Clear actions" drops every mark.
- **Exit dialog.** Apply all, discard all and exit, or stay.
- **Summary.** Before writing, the list of changes per file. Values are
  shown masked: the first characters and the length.
- **Changed files.** Before writing, each file is compared with its state
  at the scan (a hash of the content). The actions on a file that has
  changed are not applied; the file is rescanned and its rows are marked
  again by hand.
- **Keystore backup.** Before the first write to the keystore in a save,
  the whole keystore directory is copied next to it as
  `<keystore>.<YYYYmmdd-HHMMSS>.backup`, with the same modes (0700 for the
  directory, 0600 for the files). Old backups are removed by hand.
- **Order of writes.**
  1. `.sec/names` (new names: `key set` needs the name there; the file
     holds no values);
  2. keystore (after the backup);
  3. the files themselves: bottom-up within a file and right to left
     within a line, so that earlier replacements do not move later ones;
  4. the allowlist and `.gitignore`;
  5. `git rm --cached`.

  A value leaves its file only after it is in the keystore. Each write
  goes through a temporary file and a rename. Several files cannot be
  written atomically, and the keystore lies outside git, so a commit
  cannot hold everything either. On an error the TUI stops and shows what
  was done and what was not. The actions are idempotent, so applying again
  is safe.
- **After saving.** `segscan check` on the working tree, with its result
  on screen; the changed files are rescanned, and the rows that were dealt
  with disappear.

## 7. What writes the files

`segscan tui` is a command of the segscan binary and uses the same code.

- **Already there:** `key add` (`.sec/names`), `key set` (keystore, with
  journal and lock), writing through a temporary file and a rename, and,
  in `segscan import`, finding the values of keys in a text under every
  transform and replacing them by placeholders.
- **New:** adding to the allowlist and `.gitignore`, the `segscan:allow`
  marker, replacing one stretch of a file by a placeholder.

Every action gets a non-interactive command as well (`segscan allow add`,
`segscan key move FILE:LINE:COL+LEN -name ...`), so it can be tested
without a terminal and used from scripts. The plan of a session exists
only in memory and never holds values.

## Not in scope

- **The git history.** For values already committed there is a warning
  and rotation, nothing more.
- **Copying from `/etc` under sudo.** `sudo segscan import -node n1 FILE...`
  already does this:
  - copies the file into `nodes/n1/...`;
  - records type, mode, owner and group in the manifest;
  - replaces the known values of the keystore by placeholders, with their
    transforms;
  - keeps secret files in the keystore (`-secret`).

  It has to be tested before a new tool is written.
- **Manifest improvements and syncing keystores between machines.**

## Stages

1. The file set of `scan` (1); the TUI with list, preview, actions `I`,
   `F`, `A`, `M`, `U`, `E`, saving and the exit dialog; LLM in the
   background.
2. Testing `key add` / `key set` / `import` / `expand` / `check` by hand
   on a test repository; then action `K` with the keystore backup.
3. Secret files: a whole file → keystore `files/<name>` with a type `s`
   manifest entry, for `private_key` findings and multi-line values.

## Decided

1. The flag for scanning everything is `-scanall`; all of `.sec/` is left
   out of the scan.
2. `K` is not offered without a keystore.
3. Key names are typed by the user, in the format of `.sec/names`; the uuid
   comes from `key add`.
4. The display of values and context is set in `.git/segscan-tui` (2).
5. Rotation is out of scope: it belongs to vault and other tools.
6. The TUI is written on the standard library only, inside segscan, and
   uses its code directly (no running segscan as a command). Every action
   still gets a non-interactive command, for tests and scripts.
7. Keystore backups lie next to the keystore and are removed by hand.

## Open questions

1. The model (`.sec/segscan.model`). Trained on the repository and then
   scanning the same repository, it learns what is "normal" from the very
   files it checks: a key repeated in several node files becomes a
   dictionary word and is no longer reported. The built-in model alone
   gives too many false positives. The approach is under review
   (a universal model, or another way to learn the vocabulary); until then,
   training on a tree that still holds values is unsafe.

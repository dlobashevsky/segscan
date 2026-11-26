# segscan manual

This manual describes what segscan does **today**. The design of the parts
that are not built yet is in [DESIGN.md](DESIGN.md); the statistical
scanner itself is described in [README.md](README.md).

segscan has two jobs:

1. **Statistical scan.** It flags strings that look random (keys, tokens,
   hashes) in files, diffs and staged changes. It warns; it cannot be sure.
2. **Configuration repositories.** A repository with a `.sec/` directory
   keeps no credentials at all. Files hold placeholders such as
   `!SECKEY_ch_sts_<uuid>!`, and `segscan check` blocks every commit and
   push that breaks the rules.

## 1. Install

    go build -o segscan .
    install -m 0755 segscan /usr/local/bin/

The hooks call `segscan` from `$PATH`; every machine that commits to a
configuration repository needs it there.

## 2. Status

| Part | State |
|---|---|
| Statistical scan: `scan`, `diff`, `hook`, `train`, `calib`, `explain` | works |
| `.sec/` repositories: `init`, `key add/rm/list`, `manifest fix`, `check` checks 1-5, hooks | works |
| Keystore, `key set/check`, `import`, `expand`, known-value check (check 6) | not yet (stage 3) |
| `manifest pull/check/apply`, `expand -install` with owners and modes | not yet (stage 4) |
| Binary files in the statistical scan, `drift`, `keys sync` | not yet (stage 5) |

What this means in practice today: the repository can hold placeholders
instead of values, and nothing that violates the rules gets committed or
pushed. Putting the values back for deployment (`expand`) is not there yet;
until it is, deploy the files that hold placeholders by hand, or keep
those files out of the deployment.

`check` says so on every run:

    segscan: known values not checked: keystore support is not implemented yet

## 3. Quick start: a configuration repository

    git init cluster && cd cluster
    segscan init

`init` creates `.sec/` and sets `git config core.hooksPath .sec/hooks`. Run
`segscan init` again in every fresh clone: it creates nothing that exists
already, it only sets the hooks path again (git does not clone that
setting).

Put the configuration of each node under `nodes/<node>/` at its host path:

    nodes/n1/etc/nginx/nginx.conf
    nodes/n1/etc/clickhouse-server/users.xml

For every credential, add a key name and use the printed placeholder in
place of the value:

    $ segscan key add ch_sts -scope 'nodes/*/etc/clickhouse-server/**'
    !SECKEY_ch_sts_bb40c92c-18bf-46cf-96df-5b7d8f9b3749!

    <password_sha256_hex>!SECKEY_ch_sts_bb40c92c-18bf-46cf-96df-5b7d8f9b3749:sha256!</password_sha256_hex>

Record owner, group and mode of the files:

    $ segscan manifest fix
    + nodes/n1/etc/clickhouse-server/users.xml  f 0600 root:root  (default, review)
    + nodes/n1/etc/nginx/nginx.conf             f 0600 root:root  (default, review)

then correct `.sec/manifest` by hand (section 7).

Check and commit:

    segscan check
    git add -A && git commit

Train the statistical model on the repository once it has some content, and
commit the model, so everyone's hook uses the same one:

    segscan train          # writes .sec/segscan.model
    git add .sec/segscan.model && git commit -m 'segscan model'

## 4. The `.sec/` directory

| File | Contents |
|---|---|
| `config` | settings (section 6) |
| `names` | key names and uuids; never values (section 5) |
| `manifest` | type, mode, owner, group of every file under a node root (section 7) |
| `allow` | allowlist of the statistical scan: fingerprints and `path:glob` |
| `segscan.model` | the trained model (optional, from `segscan train`) |
| `hooks/pre-commit`, `hooks/pre-push` | the hooks (section 9) |
| `.gitignore` | ignores `.sec/keys`, an optional link to the keystore |

`.sec/` must be a real directory, and `config`, `names`, `manifest` and
`allow` regular files (no symlinks, no submodules), in the working tree and
in every commit. They are UTF-8 text with LF line ends; a CR or invalid
UTF-8 is an error. segscan writes them through a temporary file and a
rename and never follows a symlink inside `.sec/`.

## 5. Keys and placeholders

### 5.1 Names

    segscan key add <name> [-scope GLOB,...] [-base58]
    segscan key rm <name>
    segscan key list [-no-header]

- A name is letters, digits, `_` and `.`, not starting with `.`
  (`ch_sts`, `nginx.play`).
- `key add` gives the name a fresh uuid and prints its placeholder. The
  uuid ties placeholders to this repository: the same name elsewhere has
  another uuid.
- `-scope` limits where the key may be used (path globs, comma-separated).
  Without it the key may be used anywhere.
- `-base58` marks our own generated keys.
- `key rm` refuses while a placeholder still uses the key, and names one
  such file.
- `key list` prints `name uuid scope flags uses files`.

`.sec/names` lines are `name<TAB>uuid[<TAB>scope[<TAB>flags]]`. You can edit
the file by hand; `check` validates it.

### 5.2 Placeholders

    !SECKEY_<name>_<uuid>!
    !SECKEY_<name>_<uuid>:<transform>[:<transform>...]!

The transforms say in which form the value appears in the file, at most 4
in a chain, applied left to right:

| Transform | Form |
|---|---|
| `sha256` | SHA-256, lowercase hex (ClickHouse `password_sha256_hex`) |
| `dsha1` | SHA-1 of SHA-1, hex (ClickHouse `password_double_sha1_hex`) |
| `b64`, `b64nl`, `b64url` | base64; with a final newline; URL-safe |
| `urlenc` | percent-encoded (a password inside a URL) |
| `dq`, `sq` | inside a double- / single-quoted string |
| `nginxq` | inside an nginx string |
| `xml` | XML-escaped |

Example, a password inside a URL in an nginx config:

    proxy_pass http://play:!SECKEY_web_play_4ffa...:urlenc!@127.0.0.1:8123;

Today the transforms are only checked for spelling; they take effect with
`expand` (stage 3).

## 6. `.sec/config`

    project     = cluster
    keystore    = ~/.secshell/cluster
    roots       = nodes/*
    skip_uuids  = all
    binary      = scan
    hook_scan   = warn
    forbid      = .htpasswd*, *.key, id_rsa*, id_ed25519*, id_ecdsa*

| Key | Meaning |
|---|---|
| `project` | name, default the directory name |
| `keystore` | where the values will live (stage 3). Must be outside the repository and contain no `.` or `..` components; `check` reports a keystore inside the repository and forbids its path |
| `roots` | globs of node roots; `nodes/n1/etc/x` is `/etc/x` on node `n1` |
| `skip_uuids` | `all` (placeholders and bare UUIDs are not scored by the statistical scan), `placeholders`, `off` |
| `binary` | `scan` or `skip`; binary scanning itself comes in stage 5 |
| `hook_scan` | the statistical part of the pre-commit hook: `warn` (print, do not block), `block`, `off` |
| `forbid` | globs of paths that may never be committed |

`#` starts a comment at the beginning of a line or after a space or TAB.
Unknown keys and bad values are errors.

## 7. `.sec/manifest`

    <path> TAB <type> TAB <mode> TAB <owner> TAB <group> [TAB <attr>...]

| Field | Values |
|---|---|
| `path` | repository path, normalized (`nodes/n1/etc/nginx/nginx.conf`) |
| `type` | `f` file, `l` symlink, `d` directory, `s` secret file from the keystore |
| `mode` | octal, 3 or 4 digits (`0640`, `2750`) |
| `owner`, `group` | names, not numbers; they may differ between nodes |
| `attr` | `secret=<name>` (required, once, on `s` only), `acl=...`, `selinux=...`, `xattr.<name>=<base64>`; each at most once |

Rules that `check` enforces:

- every file under a node root has an entry, of the right type (`f` for a
  file, `l` for a symlink);
- every `f`/`l` entry has a file; an `s` path must not exist in the tree;
- no entry lies below an `f` or `s` entry;
- a node root itself (`nodes/n1`) must be a directory, and no submodule may
  sit under a node root.

`segscan manifest fix` adds entries for new files and drops `f`/`l` entries
whose file is gone. A new file gets the owner and group of the nearest
parent `d` entry and that directory's mode without execute and special bits
(`2750` gives `0640`); with no parent entry, `root:root 0600`. Every added
entry is printed for review. `d` and `s` entries are never dropped: git
keeps no empty directory, and a secret file is never in the tree. Declaring
a directory once gives sane defaults to everything added below it:

    nodes/n1/etc/nginx	d	2750	root	www-data

## 8. `segscan check`

    segscan check                 # the working tree
    segscan check -staged         # the index (what the next commit holds)
    segscan check -range 'A..B'   # every commit given by git rev-list arguments
    segscan check -all            # every commit reachable from any ref
    -json, -no-header

Each snapshot (the working tree, the index, a commit) is checked with its
own `.sec/` files. A problem found in many commits is reported once, at the
oldest one. Commits from before `.sec/` existed get only the grammar,
forbidden-path and private-key checks.

Output is TSV `commit file line col check message`, or JSON Lines. Exit
code 0 clean, 1 problems, 2 error.

| `check` | What it means | Fix |
|---|---|---|
| `grammar` | a malformed `!SECKEY_` placeholder, an unknown transform, a placeholder in a binary file | correct the placeholder |
| `names` | unknown key, wrong uuid, key used outside its scope, a bad line in `.sec/names` | `key add`, fix the uuid, widen `-scope` |
| `manifest` | missing or stale entry, wrong type, bad line in `.sec/manifest` (section 7) | `manifest fix`, edit the manifest |
| `forbidden` | a path that matches `forbid`, `.sec/keys`, or lies in the keystore | remove the file |
| `private_key` | a `-----BEGIN ... PRIVATE KEY-----` block, also in binary files and in `.sec/` | remove the key; a deliberate test key goes into `.sec/allow` by fp |
| `config` | an invalid `.sec/config`; a `.sec/` file that is not a regular file; `.sec` not a directory; a keystore inside the repository | fix the file |

Example:

    commit  file                           line col check  message
            nodes/n1/etc/nginx/nginx.conf  3    1   names  key ch_sts used outside its scope
            nodes/n1/etc/nginx/nginx.conf  4    1   names  unknown key nope (segscan key add)

## 9. Hooks

`init` points `core.hooksPath` at `.sec/hooks`:

- **pre-commit**: `segscan check -staged` (blocking), then `segscan hook`,
  the statistical scan of the added lines. With `hook_scan = warn` it only
  prints suspicious fragments:

        segscan: 1 suspicious fragment(s), not blocking.
        False positive? Add its fp to the allowlist or put "segscan:allow" on the line.

  The hook reads `.sec/config`, `.sec/allow` and `.sec/segscan.model` from
  the index, not the working tree, so it judges exactly what is committed.

- **pre-push**: `segscan check -range` over every pushed commit that the
  destination does not have yet (it asks the remote with `git ls-remote`,
  and checks the whole history if that fails). Deleting a remote ref is
  not checked. A pushed ref that is not a commit (a tag on a blob) is
  refused, because it cannot be checked.

`git commit --no-verify` and `git push --no-verify` skip the hooks. Do that
only knowingly; `segscan check -all` finds afterwards what slipped through.

The old `segscan install` (a single `.git/hooks/pre-commit`) still works for
repositories without `.sec/`; with `core.hooksPath` set, git ignores
`.git/hooks`.

## 10. The statistical scan in a `.sec/` repository

`scan`, `diff`, `hook`, `train`, `calib` and `explain` use
`.sec/segscan.model` and `.sec/allow` by default (`-m`, `-allow` and
`$SEGSCAN_MODEL` still win) and follow `skip_uuids`. They do not scan
`.sec/config`, `names`, `manifest`, `allow` and `hooks/`: those are
structured, validated by `check`, and full of paths and uuids.

False positives:

- add the `fp` column of the finding to `.sec/allow`, one per line;
- `path:<glob>` in `.sec/allow` skips files;
- `segscan:allow` on a line skips that line.

Useful one-offs on a repository you take over:

    segscan scan | sort -t$'\t' -k5,5nr | head -50    # most random first
    git log -p --all -U0 | segscan diff                # the whole history
    segscan check -all                                 # rules over the whole history

## 11. Taking over an existing repository

Credentials that are already in the history stay there; placeholders only
protect what comes next. The safe order:

1. Scan the old repository: `git log -p --all -U0 | segscan diff` and the
   statistical findings sorted by bits per char; list every credential
   found.
2. Rotate those credentials. A value that was ever pushed is not secret any
   more.
3. Start a new repository (or rewrite the history, which does not remove
   copies already fetched elsewhere), `segscan init`, and bring the files
   over with placeholders in place of the values.
4. `segscan check -all` before the first push.

## 12. Exit codes

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | findings (`scan`, `diff`, `hook`) or problems (`check`) |
| 2 | error: bad arguments, invalid `.sec/` files where they are needed, a refused `key rm`, git failures |

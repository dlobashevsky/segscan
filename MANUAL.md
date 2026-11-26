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

The keystore and the commands that need it (`key set/check/retire`,
`import`, `expand`, check 6) are Linux only. Elsewhere (macOS, a planning
laptop) everything else works, and `check` runs without check 6.

## 2. Status

| Part | State |
|---|---|
| Statistical scan: `scan`, `diff`, `hook`, `train`, `calib`, `explain` | works |
| `.sec/` repositories: `init`, `key add/rm/list`, `manifest fix`, `check` checks 1-5, hooks | works |
| Keystore, `key set/check/retire`, `import`, `expand -to`, known-value check (check 6), `train` guard | works |
| `check -all` state (incremental runs), `key forget` | not yet: `-all` always checks the whole history |
| `manifest pull/check/apply`, `expand -install` with owners and modes | not yet (stage 4) |
| Binary files in the statistical scan, `drift`, `keys sync` | not yet (stage 5) |

What this means in practice: the repository holds placeholders instead of
values, nothing that breaks the rules gets committed or pushed, and on the
deploy machine (the one with the keystore) `expand -to` writes the real
files into a staging directory, from which your deploy tool copies them.
Owners and modes on the node are still your deploy tool's job; the manifest
records them already.

Without the keystore (a laptop that only plans changes), `check` says once
per run that check 6 was skipped:

    segscan: known values not checked: no keystore at /home/me/.secshell/cluster

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

On the deploy machine, give the keys their values and build the files of a
node:

    segscan key check                      # which values are missing
    segscan key set ch_sts                 # type it, or: key set ch_sts -gen 32
    segscan check -all                     # also searches the known values now
    segscan expand -node n1 -to /srv/stage/n1

Then your deploy tool copies the files from the staging tree and sets
owner, group and mode from `.sec/manifest`. Do not `rsync -a` the staging
tree onto `/` as it is: every file there is `0600` and every directory
`0700`, and `rsync -a` would give `/etc` those modes.

A change made on a node by hand comes back with
`sudo segscan import -node n1 /etc/...` (section 9).

## 4. The `.sec/` directory

| File | Contents |
|---|---|
| `config` | settings (section 6) |
| `names` | key names and uuids; never values (section 5) |
| `manifest` | type, mode, owner, group of every file under a node root (section 7) |
| `allow` | allowlist of the statistical scan: fingerprints and `path:glob` |
| `segscan.model` | the trained model (optional, from `segscan train`) |
| `hooks/pre-commit`, `hooks/pre-push` | the hooks (section 12) |
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

A placeholder of a key that is a `user:password` pair in
`Authorization: Basic`: make the whole `user:password` the key's value and
use `:b64`. segscan cannot see a value inside a base64 of a longer string.

Every form a chain produces is at most 64 KiB.

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
| `keystore` | where the values live (section 8). `$SEGSCAN_KEYSTORE` overrides it. Must be outside the repository and contain no `.` or `..` components; `check` reports a keystore inside the repository and forbids its path |
| `roots` | globs of node roots; `nodes/n1/etc/x` is `/etc/x` on node `n1` |
| `skip_uuids` | `all` (placeholders and bare UUIDs are not scored by the statistical scan), `placeholders`, `off` |
| `binary` | `scan` or `skip`, for the statistical scan (stage 5); check 6 always reads binary files |
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

## 8. The keystore

The values live outside the repository, on the deploy machine only:

    ~/.secshell/<project>/      (keystore in .sec/config, or $SEGSCAN_KEYSTORE)
      keys                      name<TAB>uuid<TAB>value
      retired                   values replaced by key set or key retire, still searched
      files/<name>              secret files: .htpasswd, .env, PEM keys
      retired-files/            replaced secret files, still searched

- The directory must be mode `0700` and owned by you, every file `0600`
  with one link, owned by you or root; segscan refuses anything else, like
  ssh. Under `sudo`, "you" is `$SUDO_UID`, and `~` is that user's home.
  Files segscan writes under sudo are given to that user.
- segscan opens it component by component and never follows a symlink,
  neither to the keystore nor inside it. A link `.sec/keys -> ~/.secshell/x`
  for convenience is fine (`.sec/.gitignore` ignores it), but the keystore
  path in the config must be the real one.
- A value is printable ASCII without spaces, quotes (`" ' \``), backslash
  and `#`. Anything else (a multi-line or binary secret) is a secret file.
- Commands that change it hold an exclusive lock, readers a shared one. A
  rotation goes through a journal (`pending`), so a crash never loses the
  old value; the next command finishes it.

Back it up like ssh keys. Two deploy machines: copy it with the modes kept
(`keys sync` is stage 5).

### 8.1 Values

    segscan key set <name>            # the value from stdin, no echo on a terminal
    segscan key set <name> -gen 32    # 32 random base58 characters (our own keys)
    segscan key check [-weak]
    segscan key retire <name>         # after key rm: the value stays searchable
    segscan key retire -secret <name> # a secret file no type s entry names any more

- `key set` needs the name in `.sec/names` and takes its uuid from there. A
  `-base58` key accepts only base58. Two keys with the same value are
  refused. The value replaced goes to `retired`.
- `key check` compares `.sec/names` with the keystore and lists, as TSV
  `kind name problem`: keys without a value, values without a name, uuid
  mismatches (another project's keystore), secret files without a type `s`
  entry and type `s` entries without a file. Exit 1 if there is any.
- `key check -weak` also lists keys whose value has weak forms (below):
  check 6 does not search those forms, so these values are only partly
  protected. Weak or default passwords as such are not segscan's job; use a
  dictionary or a leak scanner before deployment.
- There is no `key forget` yet: retired values stay searched forever.

Rotation: `key set <name>` (the placeholders in the repository stay the
same), `expand`, deploy, restart the services. The old value keeps being
searched by `check`.

## 9. `segscan import`: from a node into the repository

    sudo segscan import [-n] -node n1 /etc/clickhouse-server/users.xml /etc/nginx/nginx.conf
    sudo segscan import -node n1 -secret htpasswd /etc/nginx/.htpasswd

`import` copies each live file to `nodes/<node>/<path>`, replaces every
value of every key by its placeholder, and records type, mode, owner and
group in the manifest. `-n` prints what it would do. Run it from the
checkout; it does not run git, so it is safe under `sudo`. It reads the
live file without following symlinks on the way; a symlink is imported as
a symlink (type `l`). A new node directory (`nodes/n9`) is created. Directories are not walked: give the files
(`$(find /etc/nginx -type f)`).

It searches each value in its bare form, under every transform and every
pair of transforms (and longer chains the repository uses), and writes the
placeholder with the matching transforms. It stops and writes **nothing**,
for all files given, when:

| Problem | What to do |
|---|---|
| a value outside the key's `-scope` | widen the scope, or it really is a leak |
| the forms of two keys overlap (`abc` and `abcdef`) | write that placeholder by hand |
| one text fits several transforms (an alphanumeric value is the same bare, `urlenc`ed and `xml`-escaped) | `-form FILE:LINE=urlenc` (or `=bare`), or write the placeholder by hand; the next import keeps it |
| a short or common value (`on`, `admin`): it would replace ordinary text too | check the listed places, then `-accept <name>`; or narrow the scope |
| a value left after replacement (a retired value, a line of a secret file) | it is a leak; remove it on the node |
| a binary file with a value in it, or one that cannot be fully read | `-secret <name>`, or `path:<glob>` in `.sec/allow` for a harmless binary |
| the result does not expand back to the live file byte for byte | write the placeholders by hand |

For a `-base58` key the choice of transform is never ambiguous for escapes,
so mark our own keys `-base58`. A short value counts only as a whole token
(no letter, digit, `_` or `-` next to it) and only inside the scope.

`-secret <name>` stores the file in the keystore (`files/<name>`) and adds a
type `s` entry; the file never enters the tree. Use it for `.htpasswd`
(salted hashes cannot be placeholders), `.env` files, PEM keys. A PKCS#12
bundle deployed by hand can live in `files/` too: check 6 keeps searching
for it.

It prints, per file, the keys replaced and how often, and the number of
statistical findings left (`-v` shows them).

## 10. `segscan expand -to`: from the repository to a node

    segscan expand -node n1 -to /srv/stage/n1 [/etc/nginx ...]
    segscan expand -n -node n1 -to /srv/stage/n1

`expand` writes every manifest entry of the node under the staging
directory at its host path, with every placeholder resolved: type `f` with
the values, type `s` from `files/`, type `l` as symlinks, type `d` as
directories. Files are `0600`, directories `0700`; the real owners and modes
are in `.sec/manifest` for your deploy tool (`expand -install`, which sets
them, is stage 4). Paths after the flags select a part of the node.

- Every problem is collected first (missing value, uuid mismatch, malformed
  placeholder, a transform that cannot represent the value, two entries on
  the same target) and reported together; then nothing is written.
- The staging directory must be outside the repository, and no symlink
  under it is followed. Entries below a declared symlink (type `l`) land
  where the link points on the node.
- A file that is already right is not touched. The changed paths are
  printed, never the values. `-n` only lists them.
- It reads the repository without following symlinks and refuses a type `f`
  file with several hard links.

## 11. `segscan check`

    segscan check                 # the working tree
    segscan check -staged         # the index (what the next commit holds)
    segscan check -range 'A..B'   # every commit given by git rev-list arguments
    segscan check -all            # every commit reachable from any ref
    -json, -no-header

Each snapshot (the working tree, the index, a commit) is checked with its
own `.sec/` files. With the keystore available, check 6 runs too; the
pre-commit hook on the deploy machine runs it on every commit, and
`check -all` there finds values committed elsewhere. A problem found in many commits is reported once, at the
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
| `known_value` | check 6, only with the keystore: a value of a key (current or retired) or of a secret file is in the file, in some form; or a binary file could not be read completely | remove the value and rotate it if it was pushed; a harmless binary goes into `.sec/allow` as `path:<glob>` |

Check 6 in detail:

- It searches every **strong** form of every value: bare, under each
  transform and pair of transforms, and longer chains used in the
  repository. A form shorter than 8 bytes or one that looks like ordinary
  text (a word, a version, a path) is weak and not searched: `0` is in every
  `0600`. The strong forms of a weak value, such as its `sha256`, are still
  searched (`key check -weak` lists the weak ones).
- Scopes do not matter here: a strong form is a finding under any path,
  `.sec/` included.
- Secret files: their whole content, each line (trimmed of spaces) and the
  value of each `name=value` line, with and without one pair of quotes,
  each in all its strong forms. So `TOKEN=Zx81...` from `app.env` is found
  under another name too.
- Binary files (not valid UTF-8, or a NUL anywhere): the raw bytes, also in
  UTF-16LE/BE, plus what gzip members (also behind a text prefix, as in a
  self-extracting script) and ZIP archives hold, two levels deep, 64 MiB at
  most. Any other binary (PNG, PDF, tar, ...) is reported as "not fully
  scanned" until `.sec/allow` has `path:<glob>` for it; the raw bytes are
  still searched. `.sec/segscan.model` is read in full.
- The message names the key or secret file and the form, never the value.

Example:

    commit  file                           line col check  message
            nodes/n1/etc/nginx/nginx.conf  3    1   names  key ch_sts used outside its scope
            nodes/n1/etc/nginx/nginx.conf  4    1   names  unknown key nope (segscan key add)

## 12. Hooks

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

## 13. The statistical scan in a `.sec/` repository

`scan`, `diff`, `hook`, `train`, `calib` and `explain` use
`.sec/segscan.model` and `.sec/allow` by default (`-m`, `-allow` and
`$SEGSCAN_MODEL` still win) and follow `skip_uuids`. They do not scan
`.sec/config`, `names`, `manifest`, `allow` and `hooks/`: those are
structured, validated by `check`, and full of paths and uuids.

False positives:

- add the `fp` column of the finding to `.sec/allow`, one per line;
- `path:<glob>` in `.sec/allow` skips files;
- `segscan:allow` on a line skips that line.

`segscan train` with the keystore available first runs check 6 on its
input and stops on any finding, so a value never becomes a dictionary word
of the model.

Useful one-offs on a repository you take over:

    segscan scan | sort -t$'\t' -k5,5nr | head -50    # most random first
    git log -p --all -U0 | segscan diff                # the whole history
    segscan check -all                                 # rules over the whole history

## 14. Taking over an existing repository

Credentials that are already in the history stay there; placeholders only
protect what comes next. The safe order:

1. Scan the old repository: `git log -p --all -U0 | segscan diff` and the
   statistical findings sorted by bits per char; list every credential
   found.
2. Rotate those credentials. A value that was ever pushed is not secret any
   more.
3. Start a new repository (or rewrite the history, which does not remove
   copies already fetched elsewhere), `segscan init`, `key add` every
   credential (`-base58` for our own), `key set` the new values on the
   deploy machine, and bring the files in with `sudo segscan import` from
   the nodes, or by hand with placeholders.
4. Put the old, rotated values into the keystore too, as retired values
   (`key set` the old value first, then the new one), so check 6 keeps
   them out of the new repository.
5. `segscan check -all` before the first push.

## 15. Exit codes

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | findings (`scan`, `diff`, `hook`) or problems (`check`, `key check`, `import`, `expand`); `import` and `expand` wrote nothing |
| 2 | error: bad arguments, invalid `.sec/` files where they are needed, a refused `key rm` or `key set`, a missing or untrusted keystore, git failures |

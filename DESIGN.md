# segscan: secrets out of a configuration repository

Status: draft, for review. Nothing here is implemented yet.

## 1. Goal

A repository holds the configuration of a cluster: large parts of `/etc`
from every node. It is read by people and tools that plan the
infrastructure, including an AI assistant working in a cloud session, and it
lives on GitHub. None of them may see a credential.

The real values exist in one place only: the keystore on the deploy machine.
The repository holds placeholders. segscan turns a placeholder tree into real
files on the way to a node (`expand`), turns real files back into
placeholders on the way into the repository (`import`), and checks every
commit (`check`, `hook`).

Two kinds of leak are handled differently:

| Leak | Detection | Blocks the commit |
|---|---|---|
| A **known** value (it is in the keystore), in any of its encodings | exact match | yes, no false positives |
| An **unknown** value (nobody has put it in the keystore yet) | the statistical scanner (`scan`, `hook`) | no, it warns |

The statistical scanner stays advisory: on a tree of `/etc` it has too many
false positives to block on. Its allowlist and model grow by hand on the
deploy machine and are committed, so the noise goes down over time.

### Non-goals

- Protecting the deploy machine itself, or a node once it is compromised.
- Catching an unknown secret with certainty. The statistical scanner misses
  dictionary passwords, short hex and digits-only secrets (see README).
- Exact-match checks on machines without the keystore. Commits made there
  get grammar and consistency checks only, and are checked again by the
  deploy machine on its next `check --all`.

## 2. Backward compatibility

Every new behaviour switches on only when one of these is true:

- the repository has a `.sec/` directory;
- a new command is used;
- a new flag is given.

Without `.sec/`, `scan`, `diff`, `hook`, `train`, `install`, `calib` and
`explain` behave exactly as they do now, with the same defaults, output and
exit codes.

New flag for the scanner commands: `-skip-uuids` (also `--skip-uuids`, as the
`flag` package accepts both). It is off by default and on by default inside a
`.sec/` repository (`skip_uuids = all` in `.sec/config`). See 5.3 for what it
skips.

## 3. Layout

### 3.1 In the repository (committed, no secret inside)

```
.sec/
  config          settings, see 4.1
  names           the keys: name, uuid, optional scope; no values
  manifest        owner, group, mode and type of every file under a node root
  allow           statistical allowlist (the existing .segscan-allow format)
  segscan.model   the repository model (segscan train)
  hooks/          pre-commit, pre-push; core.hooksPath points here
nodes/<node>/...  files of each node, with placeholders
```

`allow` holds fingerprints, the first 48 bits of sha256 of a finding, never
the finding itself, so a real secret allowlisted by mistake does not end up
in git in clear.

`segscan.model` holds dictionary fragments of the tree it was trained on.
That tree contains placeholders, not values. `train` refuses to run when the
keystore is available and any of its values, in any encoding, occurs in the
input (see 6.6).

### 3.2 Outside the repository (deploy machine only)

```
~/.secshell/<project>/     path from .sec/config, overridden by $SEGSCAN_KEYSTORE
  keys                     name, uuid, value; mode 0600
  retired                  values replaced by key set, kept for check 6; mode 0600
  files/<name>             secrets that are whole files: .htpasswd, PEM keys, .env; mode 0600
```

The directory and every file in it must be mode 0600 or 0700 and owned by
the invoking user, as ssh requires for its keys. Otherwise segscan refuses
to read them. Under sudo the invoking user is the one in `$SUDO_UID`: `~`
in the keystore path is that user's home, and files owned by that user or
by root are accepted. The mode checks stay the same.

The keystore is not kept under `.gitignore` inside the tree: `git add -f`,
`git clean -fdx`, a `tar` or `rsync` of the tree, and IDE indexing all go
around `.gitignore`. A symlink `.sec/keys -> ~/.secshell/<project>` is
allowed for convenience; `.sec/.gitignore` ignores it, and `git clean`
removes the link, not the target. `keys sync <host>` copies the keystore to
another machine over ssh with the modes kept.

## 4. File formats

All files are UTF-8 text with LF line ends, with one exception: the value
field of the keystore's `keys` and `retired` is any bytes except LF (4.3);
their names, uuids and dates are UTF-8 like everything else. `#` at the start of a line begins
a comment and blank lines are ignored, except in `keys` (see 4.3). Fields are
separated by one TAB. In `.sec/config` only, a `#` after a space or TAB also
starts a comment, so a value cannot contain ` #`.

### 4.1 `.sec/config`

`key = value` lines:

```
project     = cluster
keystore    = ~/.secshell/cluster
roots       = nodes/*          # where a node tree starts: nodes/n1/etc/... -> /etc/...
skip_uuids  = all              # all | placeholders | off   (5.3)
binary      = scan             # scan | skip: binary files in check/hook (8)
hook_scan   = warn             # warn | block | off: the statistical part of the hook
forbid      = .htpasswd*, *.key, id_rsa*, id_ed25519*   # paths that may never be committed
```

### 4.2 `.sec/names`

```
<name> TAB <uuid> [TAB <scope> [TAB <flags>]]
```

- `name`: `[A-Za-z0-9_][A-Za-z0-9_.]*`, unique. A name cannot start with
  `.`, so `.` and `..` are never names.
- `uuid`: random (v4), lower-case canonical form, generated by `key add`,
  unique. It binds a placeholder to this key in this project. A key of the
  same name in another project has another uuid, so the wrong keystore is
  detected instead of silently used.
- `scope`: optional comma-separated path globs relative to the repository
  root (`nodes/*/etc/nginx/**`). If given, a placeholder of this key outside
  the scope is an error, and `import` replaces the value only inside it.
  Empty when there is no scope but there are flags.
- `flags`: optional, comma-separated. The only flag is `base58`: the value
  is always base58 (our own keys, `key add -base58`). `key set` refuses any
  other value for such a key. Every transform that only escapes characters
  (`urlenc`, `dq`, `nginxq`, `sq`, `xml`) leaves base58 unchanged, so for
  these keys `import` treats those forms as the bare value (6.3).

The file is kept sorted by name; `key add` and `key rm` rewrite it.

### 4.3 keystore `keys`

```
<name> TAB <uuid> TAB <value>
```

The value is everything after the second TAB up to the end of the line,
byte for byte: it may contain spaces, `#` and TABs and is not trimmed. It
cannot contain LF; a multi-line value is a file in `files/`. It cannot be
empty either: an empty value would match at every byte. A line with an empty
value is an error, and `key set` refuses one (`-gen N` needs N >= 1). Comment lines
start with `#` in the first column. There are no requirements on the length
or strength of a value, because values are often set by other tools or other
teams. Weak values are reported by `key check -weak`, using the scanner's
cost model.

`retired` has the same format plus a fourth field, the date it was retired.
`key set` does not drop the value it replaces: it appends it to `retired`.
An old value can still be live (the rotation is not deployed yet) and can
still sit in commits made elsewhere that no `check --all` has seen. Check 6
searches every form of every retired value like a current one, and reports
it as "retired value of <name>". A retired value leaves the file only with
`key forget <name>`, which refuses while `check --all` has not run since the
value was retired.

Secret files are kept the same way. When `import -secret <name>` replaces
`files/<name>`, the old content moves to `retired-files/<name>.<date>`
(mode 0600). Check 6 searches it like a current secret file, and
`key forget <name>` drops it under the same condition.

### 4.4 `.sec/manifest`

```
<path> TAB <type> TAB <mode> TAB <owner> TAB <group> [TAB <attr>...]
```

- `path`: repository path (`nodes/n1/etc/nginx/nginx.conf`), normalized:
  relative, no empty, `.` or `..` component, no trailing `/`. Anything else,
  such as `nodes/n1/../../etc/shadow`, is a manifest error, also for type
  `s` and `d` entries that have no file in the tree. The target path
  is the path minus the node root, with no other mapping. Files of containers
  on a node are kept under the host path where they live
  (`nodes/n1/srv/app/conf/...`), like any other file of the node.
  Because the path includes the node, every entry is per node. Users and
  groups differ between nodes, and the manifest of each node names its own.
- `type`: `f` file, `d` directory, `l` symlink (the target is in git itself),
  `s` secret file taken from the keystore's `files/` (the repository holds no
  file at this path; see 7.2).
- `mode`: octal, with setuid/setgid/sticky (`0640`, `2775`).
- `owner`, `group`: names, not numbers, because ids differ between nodes.
  `expand -install` and `manifest apply` resolve every name on the target
  before writing anything. A name the target does not know is an error, and
  nothing is changed.
- `attr`: zero or more `k=v`:
  - `secret=<name>` for type `s`. The name follows the key name grammar
    (4.2), so it is one path component and never `.` or `..`. Before
    opening `files/<name>`, segscan also checks that the resolved path,
    symlinks followed, is still inside `files/`. A name that fails either
    check is an error, because under sudo the repository must not choose
    which file of the deploy machine to copy;
  - `acl=<text>` (getfacl short form, `,`-separated);
  - `xattr.<name>=<base64>`;
  - `selinux=<context>`.

## 5. Placeholders

### 5.1 Grammar

```
!SECKEY_<name>_<uuid>[:<transform>]...!

name       [A-Za-z0-9_][A-Za-z0-9_.]*
uuid       [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
transform  [a-z0-9]+
```

The name cannot contain `-` and the uuid always does, so the last `_` before
the uuid ends the name and parsing is unambiguous. A text that starts with
`!SECKEY_` but does not match the grammar is an error in `check` and
`expand`. It is never passed through.

Placeholders are recognised in text files only. In a binary file a
placeholder is an error.

### 5.2 Transforms

Transforms are applied left to right to the value. All of them are
deterministic: the same value always gives the same text, so `expand` is
idempotent and `drift` (7.4) shows only real changes.

| Transform | Result | Typical use |
|---|---|---|
| (none) | the value | most places |
| `sha256` | lower-case hex sha256 | ClickHouse `password_sha256_hex` |
| `dsha1` | lower-case hex sha1(sha1(value)) | ClickHouse `password_double_sha1_hex`, MySQL |
| `b64` | base64, standard alphabet, padded | `Authorization: Basic` |
| `b64nl` | base64 of value + LF | what `echo value \| base64` produces |
| `b64url` | base64url, unpadded | tokens in URLs |
| `urlenc` | percent-encoding, RFC 3986 unreserved kept, upper-case hex | query strings, nginx proxying to play |
| `dq` | JSON string escaping: `\\`, `\"`, `\t`, `\r`, `\n`, other bytes below 0x20 and 0x7f as `\u00XX` | inside "..." in JSON, TOML basic strings, YAML double-quoted |
| `nginxq` | `\\`, `\"`, `\t`, `\r`, `\n`; any other control byte is an error | inside "..." in nginx |
| `sq` | `'` replaced with `'\''`; NUL is an error | inside '...' in sh |
| `xml` | `& < > " '` as entities | XML text and attributes |

Example: `Basic !SECKEY_ch_sts_<uuid>:b64!`. Salted hashes (bcrypt, apr1,
crypt) cannot be transforms, because each run would produce new text. Files
that hold them (`.htpasswd`) are secret files (type `s`).

A transform must produce text that is valid in its context for every value
the keystore allows (any byte except LF). When it cannot, for example
`nginxq` with a control byte other than TAB and CR, or `xml` with a byte that
XML 1.0 forbids, `expand` fails and names the key. It never writes the raw
byte. `dq` and `xml` also need the value to be valid UTF-8, because JSON,
TOML, YAML and XML text is UTF-8; any other value is an error for them.
`nginxq`, `sq`, `urlenc` and the `b64` family pass bytes of 0x80 and above
through (urlenc as `%XX`), because their contexts are bytes.

New transforms can be added later; an unknown one is an error.

### 5.3 What `-skip-uuids` skips

The statistical scanner would report every placeholder, because 32 hex
digits cost about 4.5-5 bits per char. `-skip-uuids` blanks a span before
the line is scored, so the text around it is still scanned. Which spans:

- `all` (the flag on the command line, and the default inside `.sec/`):
  every well-formed `!SECKEY_..!` span and every bare canonical UUID.
- `placeholders`: only the `!SECKEY_..!` spans.

`all` misses UUID-shaped secrets (Sensu and Proxmox API tokens, some client
secrets are UUIDs) in the statistical scan. A known value of that shape is
still caught by the exact match (check 6). Only an unknown one goes
unreported.

## 6. Commands

The existing commands stay. New ones are listed below. Commands that need
the keystore say so; without it they exit 2 with a message naming the path
they tried.

### 6.1 `init`

Creates `.sec/` with `config`, an empty `names`, `manifest`, `allow`,
`.gitignore` and `hooks/`, and runs `git config core.hooksPath .sec/hooks`.
Run it again in every new clone (it only sets the hooks path when `.sec/`
exists). The existing `install` command is unchanged and writes
`.git/hooks/pre-commit` as before.

### 6.2 `key`

```
key add <name> [-scope GLOB,...] [-base58]
                                    new name + uuid in names; prints the placeholder   (no keystore)
key set <name> [-gen N]             value from stdin (no echo on a tty), or -gen: N chars of base58
                                    from crypto/rand (the house standard for our own keys)   (keystore)
key rm  <name>                      from names; refuses while a placeholder still uses it
key forget <name>                   drop the retired values of a key (4.3)   (keystore)
key list                            names, scopes, where each is used, and how often
key check [-weak]                   names <-> keystore: missing values, unknown keys, uuid mismatches;
                                    -weak: values the cost model finds guessable   (keystore)
keys sync <host>:<path>             copy the keystore with modes kept (ssh)   (keystore)
```

`key add` works without the keystore. This is the normal flow for someone
who plans changes without access to the values: they add the name, use the
placeholder, and the deploy machine fills in the value with `key set` when
`expand` reports it as missing.

### 6.3 `import` (node -> repository)

```
sudo segscan import [-n] -node <node> <abs-path>...
```

Copies `/<abs-path>` from the running system into `nodes/<node>/<abs-path>`
and rewrites it (needs the keystore).

The destination must stay inside the repository. Every existing component of
`nodes/<node>/<abs-path>` below the repository top, the file itself included,
must be a plain directory or a plain file, never a symlink. Before writing,
the resolved destination is checked to be under the repository top. A
symlink there is an error, because under sudo it could point back into the
live system and the write would replace a real configuration with
placeholders. A symlink that is part of the configuration is recorded as type
`l` and recreated, not followed.

The check and the write must be the same walk, or a directory renamed and
replaced by a symlink between them would still be followed. So the
destination is opened component by component from a descriptor of the
repository top. On Linux 5.6 and later this is `openat2` with
`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`. Elsewhere every directory is opened
with `openat(O_DIRECTORY | O_NOFOLLOW)` relative to the previous one, and the
file with `O_NOFOLLOW` relative to the last. Directories that have to be
created are made with `mkdirat` on the same descriptors. `expand -install`
walks `<root>` the same way (6.4).

The steps:

1. For every key, it builds the set of forms to search for: the value under
   no transform, under each single transform in 5.2, and under every
   transform chain used for that key in the tree being imported into and,
   for check 6, in any of: the commits the check covers, `HEAD`, the
   commits a range excludes (its base), and the chains recorded in
   `check.state`. The state keeps every chain it has seen, so a chain
   removed in the very commit being checked (the staged change, or the
   first commit of a range) is still searched. A
   transform that cannot represent the value (5.2) gives no form and is
   left out of the set, here and in check 6; it is an error only where a
   placeholder asks for it (`expand`, the round trip). Forms are searched
   longest first. Inside the key's scope, if it has one, each occurrence is
   replaced with the placeholder for that form. An occurrence outside the
   scope is an error: `import` stops, writes no file, and lists the places,
   because leaving it would put the value into the tree in clear.
2. If two keys produce the same form, that is an error naming both keys,
   because the placeholder cannot be chosen.
3. Forms of one key can be equal too: an alphanumeric value is unchanged by
   `urlenc`, `xml`, `sq`, `dq` and `nginxq`. The text then does not say
   which transform the place needs, and a wrong choice would only show
   after a rotation to a value with reserved characters. For an occurrence
   that matches several forms of one key, `import` takes, in order:
   - the placeholder the repository already has at that place: the same
     file, the same line once the placeholder is expanded, and the same
     position on the line;
   - for a `base58` key (4.2), the bare value;
   - otherwise nothing. It stops, writes no file, and lists each such
     place with the candidate transforms. The user then writes the
     placeholder into the tree by hand, or gives `-form <file>:<line>=<transform>`,
     and runs `import` again.
4. Round trip: the rewritten file is expanded in memory and must equal the
   original byte for byte. If it does not, nothing is written.
5. It reports per key: number of occurrences and files. A short value
   matches ordinary text as well, and a rotation would then change unrelated
   lines. A key whose value is short or cheap under the cost model, or that
   is replaced in an unexpected file, is listed as a warning.
6. It records the file's type, mode, owner, group, ACL, xattrs and SELinux
   context in the manifest.
7. It runs the statistical scanner on the result and prints the number of
   findings, with details under `-v`.
8. The files written into the tree belong to `$SUDO_UID:$SUDO_GID`, not root.

A file that holds no placeholders after import is still listed in the
manifest. A path given with `-secret <name>` is not copied into the tree:
its content goes to `files/<name>` in the keystore and the manifest gets a
type `s` entry. `-n` prints what would change without writing.

Binary files are copied as they are, without replacement, and scanned (8).

### 6.4 `expand` (repository -> node)

```
segscan expand [-n] -node <node> (-to <dir> | -install <root>) [path...]
```

Needs the keystore.

- It resolves every placeholder in the selected files. Missing keys, uuid
  mismatches, malformed placeholders and unknown transforms are collected
  first and reported together. If there is any, nothing is written.
- `-to <dir>`: writes the files under `dir` mode 0600, directories 0700.
  `dir` must be outside the repository. This is for review and for deploy
  tools that copy files themselves.
- `-install <root>` (usually `/`, under sudo) never writes through a symlink
  it was not told about. Every existing component below `<root>` on the way
  to a target must be a plain directory, or a symlink that the manifest of
  the node declares as type `l` and whose resolved target is still under
  `<root>`. Anything else is an error before the first write, so a staging
  root with `etc -> /etc` cannot overwrite the live host. The check and the
  write are the same walk over directory descriptors, as for `import`
  (6.3): with `openat2(RESOLVE_BENEATH)`, a declared symlink is resolved by
  hand and checked to stay under `<root>`. A symlink swapped in during the
  run is therefore not followed either. The final target of every entry,
  type `s` and `d` included, must be under `<root>` once resolved, whatever
  the manifest says. Type `l` entries are created as symlinks, never written
  through.

  It first handles the type `d`
  entries, parents before children. A missing directory is created with the
  mode, owner, group and other attributes of its entry, and an existing one
  gets them applied. A directory with no entry that has to be created gets
  `0700 root:root` and a warning. Then, for every file:
  1. writes a temporary file in the target directory, mode 0600;
  2. applies owner, group, mode, ACL, xattrs and SELinux context. They come
     from the manifest. If the path is missing from the manifest, they are
     copied from the existing target. A new file with no manifest entry gets
     `0600 root:root` and a warning;
  3. `fsync`s it, then `rename`s it over the target, so a service never
     reads a half-written file.

  Type `s` entries are copied from `files/<name>` the same way, and type `l`
  entries create the symlink. A file whose content and attributes are
  already right is not touched. The command prints the list of changed
  files, never the values.
- `-n` lists the files that would change and, for attributes, the old and
  new values.

### 6.5 `check`

```
segscan check [-staged | -range REVS | -all] [-json] [-no-header]
```

Without a flag it checks the working tree: tracked files and untracked files
that are not ignored.

Blocking checks (exit 1). The `check` column of the output names them as
given in brackets:

1. **Grammar** (`grammar`). Every `!SECKEY_` is a well-formed placeholder (5.1) with
   known transforms.
2. **Names** (`names`). Every placeholder's name and uuid are in `names`, and are used
   inside its scope.
3. **Manifest** (`manifest`). Every file under a node root has a manifest entry, and every
   type `f`/`l` entry has a file. Type `s` paths must not exist in the tree.
   Owner and group must not be empty. Whether they exist on the node is
   checked on install (4.4).
4. **Forbidden paths** (`forbidden`). No path in the checked snapshot
   (working tree, index, or each commit of the range or history) matches
   `forbid`, the keystore path or `.sec/keys`.
5. **Private keys** (`private_key`). No `PRIVATE KEY` block (the existing
   detector; an allowlisted fp is respected).
6. **Known values** (`known_value`; only when the keystore is available).
   No value of any key occurs, in any form from 6.3 step 1, in a text file
   or anywhere in the bytes of a binary file (8). No secret file from
   `files/` is in the repository, under any path:
   - a file whose content equals a secret file is a finding;
   - so is a file that contains a line of one. Every line of a secret file
     whose text, trimmed of spaces, is at least 8 bytes counts. Shorter lines
     are too common (`}`, `[main]`) to tell anything;
   - so is a file that contains the value part of a `name=value` line. When
     the name looks like a credential (it contains `pass`, `pwd`, `secret`,
     `token`, `key`, `auth` or `cred`, the scanner's keyword list), the
     value counts at any length, like a keystore value, so `TOKEN=abc123`
     is found under another name. Other values count from 8 bytes, because
     `PORT=8080` or `DEBUG=true` would match everywhere. An empty value
     (`TOKEN=`) is never searched.

   The report names the key or secret file, the file and the line, never
   the value.

All checks run and all findings are reported, as TSV
`commit file line col check message` or, with `-json`, JSON Lines. Errors in
`.sec/config`, `names` and `manifest` themselves are findings too (check
`config`, `names`, `manifest`). Files under `.sec/` are checked for private
keys only, not for placeholders.

Each commit is checked with the `.sec/config`, `names`, `manifest` and
`allow` of that commit, and the index with those of the index, so an
unstaged allowlist entry cannot hide a staged key. A commit without `.sec/`
gets the grammar, forbidden-path and private-key checks only.

Without the keystore, check 6 is skipped with a single line saying so.

`-staged` checks the index (the pre-commit case). `-range` takes
`git rev-list` arguments (`A..B`, `B --not --remotes`) and checks every
commit they list (pre-push). `-all` checks every commit reachable from any
ref. In both, a problem that many commits share is reported once, with the
oldest commit that has it. Run `-all` run it on the deploy machine from time to time, because commits
made elsewhere skipped check 6.

`--all` keeps its state in the keystore directory (`check.state`, mode 0600),
because only the deploy machine runs check 6. The state holds:

- the ref tips already checked;
- for every key, a digest of its name, its uuid and the complete sorted set
  of forms that check 6 searches for it (6.3 step 1). The set changes with
  the value, with a new transform chain in the repository, and with a
  segscan release that adds or changes a transform, and any of these counts
  as a change. For every secret file in `files/`, a digest of its name and
  of every form searched for it. All digests are HMAC-SHA256
  with a random per-keystore salt kept in the same file, so the state does
  not help to guess a value.

On the next run:

- commits not reachable from the stored tips are checked with every key;
- a key or secret file that is new, or whose digest changed, is checked
  against the whole history.

`--all -full` ignores the state.

### 6.6 Statistical scanner in a `.sec/` repository

`scan`, `diff`, `hook` and `train` read `.sec/config`:

- `-m` defaults to `.sec/segscan.model`, and `-allow` to `.sec/allow`;
- `-skip-uuids` follows `skip_uuids`;
- binary files are scanned via their strings when `binary = scan` (8).

New flag for `hook`: `-warn`. It prints the findings in the added lines and
exits 0. Inside `.sec/`, when `-warn` is not given, `hook_scan` decides:
`warn` (the default) prints and exits 0, `block` blocks as before, `off`
does nothing. An explicit `-warn` or `-warn=false` wins.

`train` with the keystore available first runs check 6 on its input. If any
value is present it stops, so a value never becomes a dictionary word.

### 6.7 `drift`

```
segscan drift -node <node> [path...]
```

Shows what changed on a running node since the last import: runs `import -n`
in memory and prints a unified diff between the tree and the result. The diff
is already in placeholder form, so it can be pasted anywhere. It also
compares the manifest with the live attributes. Needs the keystore.

The name is `drift` and not `diff`, because `diff` already exists (scan a
unified diff on stdin).

### 6.8 `manifest`

```
manifest pull  -node <node> [path...]   record live attributes for files already in the tree   (sudo)
manifest check -node <node> [path...]   compare manifest and live attributes
manifest apply -node <node> [path...]   set live attributes from the manifest, content untouched   (sudo)
manifest fix                            add entries for new files, drop entries of deleted ones
```

`manifest fix` gives a new file the owner and group of the nearest parent
directory entry (type `d`) of the same node, and that directory's mode
without execute, setuid, setgid and sticky bits (`0750` -> `0640`). A
symlink gets `0777`. With no parent entry it uses `root:root 0600`. Every
added entry is printed for review. Paths that match `forbid` are not added.
A type `d` entry stays while its directory exists, and type `s` entries are
never dropped.

## 7. Flows

### 7.1 Planning without the keys (no keystore)

1. Edit files under `nodes/`.
2. A new credential: `segscan key add ch_reports -scope 'nodes/*/etc/clickhouse-server/**'`,
   then use the printed placeholder.
3. A new file: `segscan manifest fix`, then correct owner, group and mode in
   `.sec/manifest` by hand.
4. Commit. The pre-commit hook runs `check --staged` (blocking, without
   check 6) and `hook -warn`.

### 7.2 Deploy (deploy machine)

1. `git pull`.
2. `segscan check --all`: also runs check 6 on commits made elsewhere.
3. `segscan key check`, then `segscan key set <name>` for every missing value.
4. `segscan expand -n -node n1 -install /`, review the list, then run it
   without `-n` on the node, or with `-to` and the usual deploy tool.

### 7.3 A change made on a node by hand

1. `segscan drift -node n1`.
2. `sudo segscan import -node n1 <paths>`.
3. A new credential in the result: `key add`, `key set`, `import` again.
4. Commit.

### 7.4 Rotation

1. `segscan key set <name>`. Name and uuid stay, so no file in the repository
   changes. The old value goes to `retired` (4.3).
2. `segscan expand -install` on every node that uses the key
   (`key list` shows them).
3. Restart the services. segscan does not do it.
4. `segscan check --all`, then `segscan key forget <name>` when the old
   value is dead on every node.

## 8. Binary files

A file with a NUL in its first 8000 bytes is binary.

- `scan` and `hook` without `.sec/`: skipped, as now.
- `check`, and `scan`/`hook` inside `.sec/` with `binary = scan`: the file is
  scanned as its strings:
  - runs of at least 8 printable ASCII bytes;
  - runs of at least 8 UTF-16LE characters;
  - gzip, brotli, zip and the Flate streams of a PDF are unpacked first, up to
    64 MiB unpacked and two levels deep.

  The statistical scanner reports findings in the strings with the byte
  offset in the `col` field. The length limits apply to it only.

  Check 6 does not use the strings. It searches the raw bytes, and the
  unpacked bytes, for every form of every value: as is, and in UTF-16LE.
  Values of any length are searched, so a short one is not lost between two
  NUL bytes.

  Unpacking that fails, or that hits a limit, leaves part of the file
  unread. For the statistical scanner that is a warning. For check 6 it is
  a blocking finding (`known_value`: "not fully scanned"), because a known
  value could sit past the limit. A file that must stay in the repository
  anyway goes into `.sec/allow` as `path:<glob>`, which is a visible
  decision.
- Binary files never get placeholders and are never rewritten.

## 9. Hooks

`.sec/hooks/pre-commit`:

```sh
#!/bin/sh
segscan check -staged || exit 1
exec segscan hook          # warn, block or off: hook_scan
```

`.sec/hooks/pre-push` runs `segscan check -range` for every pushed ref.
`-range` takes one string that is split at whitespace into `git rev-list`
arguments, so `-range "A ^B ^C"` works. The range is the pushed commit minus
the tips the destination advertises right now (`git ls-remote`), for those
tips that exist here. Local remote-tracking refs are not trusted: they can
be stale after a branch was deleted or rewritten on the server, or belong to
another remote. When `ls-remote` fails, nothing is excluded and the whole
ancestry is checked. A deleted ref (an all-zero local id) has nothing to
check and is skipped.

Both expect `segscan` in `$PATH`. If it is missing they fail with a message
rather than pass silently.

## 10. Exit codes

| Code | Meaning |
|---|---|
| 0 | clean / done |
| 1 | findings (scan, diff, hook), failed checks (check), missing keys (expand, key check) |
| 2 | usage or I/O error, keystore unreadable or with wrong modes |

## 11. Implementation stages

Each stage is one pull request with tests, and keeps the existing behaviour
and tests intact.

1. **This document.**
2. **Without the keystore:**
   - `.sec/config`, the placeholder parser and `-skip-uuids`;
   - `init`, `key add|rm|list`, `manifest fix` (a new file takes owner,
     group and mode from the nearest parent directory entry of the same
     node, or `root:root 0600` if there is none, and is listed for review);
   - `check` checks 1-5, `hook -warn`, the pre-commit and pre-push hooks;
   - `.sec/` defaults for `scan`/`hook`/`train`.
3. **Keystore and transforms:**
   - the keystore reader with mode checks, `key set|check`;
   - `expand -to`, `import -n` and `import` with the round trip;
   - `check` check 6, the `train` guard.
4. **Attributes:** `manifest pull|check|apply`, `expand -install` with atomic
   writes and attributes, type `s`.
5. **Rest:** `drift`, binary scanning (8), `keys sync`.

## 12. Decisions

1. `skip_uuids` defaults to `all` inside `.sec/` (5.3).
2. No path mapping besides removing the node root. Container files are
   kept under their host paths (4.4).
3. Users and groups differ between nodes. Manifest entries are per node, and
   names are resolved on the target (4.4).
4. Our own keys are always base58 from a random source (`key set -gen`).
   Values set by external tools may be anything (4.3).
5. `check --all` keeps incremental state in the keystore (6.5).

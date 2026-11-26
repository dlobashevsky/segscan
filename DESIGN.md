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
  retired-files/           replaced or retired secret files; mode 0700
  pending                  journal of a rotation in progress (4.3); mode 0600, absent normally
```

The directory and every file in it must be mode 0600 or 0700 and owned by
the invoking user, as ssh requires for its keys. Otherwise segscan refuses
to read them. Under sudo the invoking user is the one in `$SUDO_UID`: `~`
in the keystore path is that user's home, and files owned by that user or
by root are accepted. The mode checks stay the same.

That user can change everything in the keystore while segscan runs as
root, so no keystore file is ever opened by path, for reading or writing:
- the keystore directory is opened once, component by component from a
  descriptor of `/`, with `O_DIRECTORY | O_NOFOLLOW` on every component
  (`openat2` with `RESOLVE_NO_SYMLINKS` where available), so a symlink
  swapped in for an ancestor such as `~/.secshell` is never followed; a
  missing component is created with `mkdirat` relative to its parent's
  descriptor and then opened the same way. `fstat` on the final descriptor
  must show a directory of mode 0700 owned by the invoking user. Root is not accepted for the
  directory itself, so `~/.secshell/<project> -> /root` is refused;
- every file in it (`keys`, `retired`, `pending`, `check.state`,
  `check.key`) and `files/` and `retired-files/` are opened from that
  descriptor with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`
  (otherwise `openat(O_NOFOLLOW)`), and checked with `fstat` on the opened
  descriptor: a regular file (or directory), owner and mode as above, and,
  for a regular file, one link, so neither a symlink nor a hard link to a
  file of root's is followed (a directory always has two or more links and
  gets the other checks only). Only then is it read, or written;
- a file that is replaced is written to a new temporary name created with
  `O_EXCL` in the same directory descriptor and moved with `renameat`,
  which replaces the directory entry and never writes through it. No
  keystore file is ever written in place, `retired` included (4.3).

The keystore is not kept under `.gitignore` inside the tree: `git add -f`,
`git clean -fdx`, a `tar` or `rsync` of the tree, and IDE indexing all go
around `.gitignore`. A symlink `.sec/keys -> ~/.secshell/<project>` is
allowed for convenience; `.sec/.gitignore` ignores it, and `git clean`
removes the link, not the target. `keys sync <host>` copies the keystore to
another machine over ssh with the modes kept. It is not a file copy: it
runs `segscan keys receive` on the destination, which takes the
destination's own exclusive lock (4.3, on its keystore directory, which
the sync never replaces) and receives the files into
a staging directory inside the keystore. Under the lock it merges
`retired` and `retired-files/` first, as a union by rotation id (nothing
retired on either side is ever lost). A destination value that would be
displaced, a current key value or a current secret file that differs from
the source's (rotated or set up locally), is first retired on the
destination with a fresh rotation id, even when the same bytes are
already among the retired records under an older id: that old id may be
covered by a clean run from before this value's latest life, and only a
new id makes `key forget` wait for a run after it. The value thus stays
searchable there and is never silently dropped; `keys receive` lists each
such value by name. Then it updates `files/`,
and replaces `keys` last with an atomic rename, each step `fsync`ed and journalled like a
rotation. An interrupted sync therefore leaves the old current value
searchable on the destination, and the next run finishes or redoes it.

## 4. File formats

The files segscan defines (everything in `.sec/` and in the keystore) are
UTF-8 text with LF line ends; the configuration files of the nodes in the
tree are whatever their programs expect, binary included (8). The one exception
among segscan's own files: the secret files in `files/` and
`retired-files/` are opaque bytes, binary included (a PKCS#12 bundle), with
no format at all. `#` at the start of a line begins
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

The keystore must be outside the repository (3.2). Every command that opens
or creates it resolves its path first and refuses one that is the
repository or lies inside it, before reading or writing anything there;
`check` reports such a configuration as a `config` finding. The keystore
path (from `keystore` or `$SEGSCAN_KEYSTORE`) may not contain `.` or `..`
components either: a path that climbs out of the repository and back
in could land, in a commit, somewhere the working tree's symlinks hide,
and `check` could not tell that the keystore is inside the repository.

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

The value is everything after the second TAB up to the end of the line.
It is printable ASCII (`0x21`-`0x7e`) without `"`, `'`, `` ` ``, `\` and
`#`: no spaces, TABs, quotes, backslashes, comment signs, control bytes or
non-ASCII. Our values are base58 and never come near this; a value from
another tool that does is refused by `key set` and reported by `key check`,
rather than handled by quoting and escaping rules in every place it is
written and searched (12.9). A multi-line or binary secret is a file in
`files/`. The value cannot be empty either: an empty value would match at
every byte (`-gen N` needs N >= 1). Comment lines start with `#` in the
first column. Within that alphabet there are no requirements on the length
or strength of a value, because values are often set by other tools or
other teams.

segscan does not look for weak or default values (`admin`, `guest`,
`password12345`). It exists to stop real keys from being committed, and a
weak value cannot be told from ordinary text: `0` is in every `0600`,
`admin` in every `admin_user`. Finding default and guessable credentials
is a separate deploy-time task for other tools (dictionaries, existing
leak scanners), not a commit or push blocker. What segscan does with weak
values is only this:
- check 6 searches the strong forms of every value and leaves out its
  weak forms (6.5);
- `import` never replaces a weak value blindly (6.3 step 5);
- `key check -weak` lists the keys whose value has weak forms, so it is
  visible which values check 6 cannot fully protect.

`retired` has the same fields plus a rotation id and the time it was
retired, before the value:
`<name> TAB <uuid> TAB <rotation> TAB <time> TAB <value>`.
The rotation id is 128 random bits in hex, new for every retirement. The
same value can be retired more than once (A, then B, then A again, then C);
each retirement is its own record, with its own time.
`key set` does not drop the value it replaces: it adds it to `retired`.
The order makes this survive a crash or power loss at any point:
1. a journal, `pending` (mode 0600), is written with `O_EXCL` and `fsync`ed:
   the new rotation id, the old record and the new `keys` line;
2. `retired` with the old record (and its rotation id) added is written
   to a temporary file in the same directory, `fsync`ed and renamed over
   `retired`. It is never appended in place: an append cut off by a crash
   could leave a torn last record, which would make the file unreadable or
   look like a finished retirement. A rename leaves either the old file or
   the new one;
3. the new `keys` is written to a temporary file in the same directory,
   `fsync`ed and renamed over `keys`;
4. `pending` is removed; the directory is `fsync`ed after each step.

Every command that changes the keystore holds an exclusive `flock` for its
whole run, recovery included; commands that only read it (`check`,
`expand`, `key check`) hold a shared one. The lock is taken on the
keystore directory descriptor itself (3.2), the one every other file is
opened from, not on a file inside it: the invoking user owns that
directory and could rename a lock file and create another while a command
under sudo holds the first. They can rename the whole directory too, but
then the running command works on the renamed one through its descriptor,
and a second command opens a different keystore; neither can be made to
interleave with the other on the same files. A second `key set` therefore waits for the first instead of
finishing its live journal, and a `pending` seen under the exclusive lock
can only be left over from a process that died. Under that lock, a command
first finishes a `pending` it finds:
it adds the record (by the same rename) unless `retired` already holds
that rotation id, then
writes `keys` from the journal, then removes `pending`. The rotation id,
not the value, is what tells a retry from a new retirement, so a value that
comes back (A, B, A) is recorded again with its later time. While
`pending` exists, `key set` refuses to start another rotation. `import
-secret` (below), `key retire` and `key retire -secret` use the same journal:
the retired copy is durable before the current one changes.
An old value can still be live (the rotation is not deployed yet) and can
still sit in commits made elsewhere that no `check --all` has seen. Check 6
searches every form of every retired value like a current one, and reports
it as "retired value of <name>". A retired value leaves the file only with
`key forget <name>`. It refuses unless a complete `check --all` has run since
the value was retired, and that run found no form of it in any reachable
commit. A run that merely happened is not enough: if it reported the value,
the leak is still there and the retired value is what keeps finding it.
Refs can also move after that run (a fetch brings a commit with the old
value). So `key forget` itself checks the retired forms against every
commit reachable now that the qualifying run did not cover, and drops the
value only if that comes out clean too. Commits that exist only on a
remote are not reachable here and would never be searched, so before
anything else `key forget` lists every ref of every configured remote
(`git ls-remote`) and refuses, naming them, while any advertised object is
missing locally; the user fetches, and the fetched commits are then
covered like any other. That listing cannot be atomic with the deletion: a
push to the remote between the two is not seen. `key forget` therefore
also asks for the value to be dead, not just unseen: it refuses unless the
rotation that retired it is deployed (`drift` shows no node still using the
value, 6.7), and it prints that the last remote listing was taken at a given
time. A value forgotten under this rule can still turn up in such a
late-pushed commit, but it is then a dead credential, not a live one; that
residual is accepted, and the only way to avoid it entirely is never to
forget (`key forget` is optional housekeeping). If any ref moved backwards or was
rewritten, it runs the whole history again for those forms. So it does when
the forms of the retired value differ from those the qualifying run
searched: the digest of 6.5 changes on an ordinary forward update too,
for instance when a new commit uses a transform chain no earlier commit
did, and the commits that run covered were never searched for the new
form. `key forget` compares the digest the run recorded with the current
one, and on any difference searches the whole history for the value.
The "since the value was retired" condition is decided by rotation id, not
by comparing digests or clocks: a clean run records in `check.state` the
rotation ids of every retired record it searched (6.5), and `key forget`
requires that the qualifying run covered every rotation id the value has in
`retired`. A value that was retired again after that run (A, B, A) has a
new id the run never saw, so the old run does not count, however equal its
forms look.

Secret files are kept the same way. When `import -secret <name>` replaces
`files/<name>`, the old content moves to
`retired-files/<name>.<UTC timestamp>.<rotation>`, created with `O_EXCL`
(mode 0600). `<rotation>` is a new random rotation id, as for a retired
key (above): a second retirement in the same second, a clock set back, or
the same content retired again after `key forget -secret` always gets a
name, and an id, that no earlier version had, so an old clean run in
`check.state` never stands for a new retirement. Check 6 searches it like a current secret file, and
`key forget -secret <name>` drops it under the same condition. A secret
file that no type `s` entry names any more is retired with
`key retire -secret <name>` (6.2); until then `key check` reports it, like
an unknown key, and check 6 still searches it. A file that is never
deployed by segscan but must never enter the repository either (a
PKCS#12 bundle deployed by hand) can be kept there on purpose (12.8). From `retired-files/` it
leaves only through `key forget -secret` with its clean-history gate.

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
  - `secret=<name>`: required, exactly once, on every type `s` entry, and
    allowed on no other type (check 3 reports a missing, repeated or
    misplaced one, so `expand` never meets an `s` entry without a source).
    The name follows the key name grammar
    (4.2), so it is one path component and never `.` or `..`. The file is
    opened through a descriptor of the keystore directory, never by path:
    `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` on Linux 5.6 and
    later, otherwise `openat(O_DIRECTORY | O_NOFOLLOW)` on `files/` and then
    `openat(O_NOFOLLOW)` on the name. Under sudo the user who owns the
    keystore cannot swap in a symlink between a check and the open, and the
    descriptor is the one that is read. A name that fails is an error,
    because under sudo the repository must not choose which file of the
    deploy machine to copy;
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

A placeholder has at most 4 transforms. Every form that a chain produces,
including the intermediate ones, is at most 64 KiB. Longer chains are an
error in the grammar check, and a form over the limit is an error for
`expand`, `import` and check 6. The limit is for forms derived from a
placeholder chain. The whole content of a secret file (6.5 check 6) is not
capped: it and its transforms are searched with a streaming matcher, so a
large file in `files/` (a PKCS#12 bundle, 12.8) neither fails the check nor
is held in memory more than once per form. Without these limits, `:b64` repeated many
times in a small file would grow the result exponentially and exhaust the
memory of every hook and of the deploy machine.

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
| `nginxq` | `\\`, `\"`, `\t`, `\r`, `\n`; `$` and any other control byte are errors (nginx has no escape for `$`, which starts a variable) | inside "..." in nginx |
| `sq` | `'` replaced with `'\''`; NUL is an error | inside '...' in sh |
| `xml` | `& < > " '` as entities; TAB, LF and CR as `&#9;` `&#10;` `&#13;`, which XML would otherwise normalize | XML text and attributes |

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
                                    from crypto/rand (the house standard for our own keys); a value
                                    outside the alphabet of 4.3 is refused   (keystore)
key rm  <name>                      from names; refuses while a placeholder still uses it
key retire <name>                   move the current value of a key that is no longer in names
                                    to retired (4.3), so it is still searched; key check reports
                                    such keys until then   (keystore)
key retire -secret <name>           the same for a file in files/ that no type s entry names:
                                    it moves to retired-files/, durably before files/<name> is
                                    removed   (keystore)
key forget <name>                   drop the retired values of a key (4.3)   (keystore)
key forget -secret <name>           drop the retired versions of a secret file (4.3). Keys and
                                    secret files are separate namespaces (a key and a file may
                                    both be called htpasswd), so every command that can act on
                                    either takes -secret for the file   (keystore)
key list                            names, scopes, where each is used, and how often
key check [-weak]                   names <-> keystore: missing values, unknown keys, uuid mismatches,
                                    values outside the alphabet of 4.3;
                                    -weak: keys whose value has weak forms, which check 6 does
                                    not search (4.3)   (keystore)
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

`<node>` must be one path component (no `/`, not `.` or `..`) that names
an existing node root under `roots` (4.1); `-node ../.git` is an error. The
destination must stay inside that node root, not merely inside the
repository. Every existing ancestor of `nodes/<node>/<abs-path>` below the
node root must be a plain directory, never a symlink. Before writing, the
resolved destination is checked to be under the node root. A symlink there
is an error, because under sudo it could point back into the live system and
the write would replace a real configuration with placeholders.

The source is read the same way. Under sudo the live path may lie below a
directory the invoking user can write, who could swap the source file, or
one of its ancestors, for a symlink to a root-only file while `import`
runs. So `/<abs-path>` is opened component by component from a descriptor
of `/`, with `O_NOFOLLOW` on every component (`openat2` with
`RESOLVE_NO_SYMLINKS` where available): a symlink among the ancestors is
an error, a symlink as the last component is read with `readlinkat` and
imported as type `l`, never followed. The type and attributes are taken
with `fstat` on the descriptor that is then read, so the bytes imported
are those of the file that was checked.

On the repository side, the final component may already be a symlink only
when the manifest declares it as type `l`: a configuration symlink
imported earlier. A live symlink at a path the repository does not have yet
is new and is simply created, as a type `l` entry with its attributes. It is never followed;
it is read with `readlinkat`, and replaced, if the live link changed, by
creating the new link under a temporary name with `symlinkat` and
`renameat` over the old one, both relative to the parent descriptor. A
symlink that is part of the configuration is recorded as type `l` and
recreated, not followed.

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
   chain of two transforms (every ordered pair from 5.2, generated whether
   or not a placeholder uses it), and under every longer chain used for that
   key in the tree being imported into and, for check 6, in any of: the
   snapshot being checked (the index for `--staged`, the working tree), the
   commits the check covers, `HEAD`, the
   commits a range excludes (its base), and the chains recorded in
   `check.state`. The state keeps every chain it has seen, so a chain
   removed in the very commit being checked (the staged change, or the
   first commit of a range) is still searched. On a machine with the
   keystore but without `check.state` yet (a new deploy machine, a lost
   state), the chain set is first seeded from every commit reachable from
   any ref, as `--all` would collect it, and stored; a chain used only deep
   in history is then searched by the first `--staged` or pre-push check
   too. Chains of three or four
   are allowed by the grammar for configurations of our own tools, but
   ordinary configurations need at most two (a sha256 passed through a
   URL), so three and four are searched only when the repository uses
   them; generating them all would multiply the search set for forms
   nobody writes. A
   transform that cannot represent the value (5.2) gives no form and is
   left out of the set, here and in check 6; it is an error only where a
   placeholder asks for it (`expand`, the round trip). Forms are searched
   longest first. Inside the key's scope, if it has one, each occurrence is
   replaced with the placeholder for that form. An occurrence outside the
   scope is an error: `import` stops, writes no file, and lists the places,
   because leaving it would put the value into the tree in clear. A weak
   form (shorter than 8 bytes, or cheap under the cost model; 4.3) counts
   only as a whole token, with no letter, digit, `_` or `-` on either side,
   and only inside the key's scope. Outside the scope it is not an
   occurrence at all, since `0` in `0600` or `listen 0` says nothing about
   the key, so an unrelated file is imported as it is. Where it does count,
   step 5 applies. The strong forms of the same value (`sha256("0")`) are
   still errors anywhere outside the scope.
2. If two keys produce the same form, or a form of one key occurs inside
   a form of another (`abc` and `abcdef`), that is an error naming both
   keys, because the placeholder cannot be chosen: longest first would
   take `abcdef` even where the live file has key `abc` followed by the
   literal `def`, the round trip would still pass, and the next rotation
   would expand the wrong key and change the bytes after it. Weak forms
   take part only where they match as tokens (step 1); a form that is
   contained in another only as a token-internal substring is not an
   overlap.
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
   matches ordinary text as well (`on`, `0`, `true`), and the round trip
   cannot tell: the placeholders expand back to the same bytes until a
   rotation turns unrelated text into the new credential. So for a key whose
   value is shorter than 8 bytes or cheap under the cost model, `import`
   stops, writes nothing, and lists every place it would replace. The user
   either narrows the key's scope, writes the placeholders by hand, or
   confirms the list with `-accept <name>` for this run. This is not a
   requirement on the value, which stays whatever it is; it only keeps a
   short one from being replaced blindly. A key replaced in a file where it
   never was before is listed as a warning.
6. It records the file's type, mode, owner, group, ACL, xattrs and SELinux
   context in the manifest.
7. It runs the statistical scanner on the result and prints the number of
   findings, with details under `-v`.
8. The files written into the tree belong to `$SUDO_UID:$SUDO_GID`, not root.
   So do the files `import -secret` writes into the keystore (`files/` and
   `retired-files/`): they are created with mode 0600 and `fchown`ed to the
   keystore owner, so the next run without sudo accepts them.

A file that holds no placeholders after import is still listed in the
manifest. A path given with `-secret <name>` is not copied into the tree:
its content goes to `files/<name>` in the keystore (an empty file is an
error: as a substring it would match everywhere) and the manifest gets a
type `s` entry. `-n` prints what would change without writing.

Binary files are copied as they are, without replacement, and scanned (8).
Before any file is written into the tree, text or binary, `import` runs
check 6 on the bytes it is about to write: for a text file the rewritten
content, after the placeholders are in, so what is left is what replacement
could not take (a retired value, a secret-file pattern, a form outside its
scope). A finding stops the import and nothing is written: the raw value
must never reach the working tree. A binary file with a finding belongs in
the keystore, with `-secret <name>`.

### 6.4 `expand` (repository -> node)

```
segscan expand [-n] -node <node> (-to <dir> | -install <root>) [path...]
```

Needs the keystore.

- It reads the repository side the way it writes the target side. Under
  sudo the checkout belongs to the invoking user, who could replace a type
  `f` file or one of its directories with a symlink to a root-only file
  (`/etc/shadow`) after it was checked. So every input is opened from a
  descriptor of the repository root with `openat2(RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS)` (otherwise one `openat(O_NOFOLLOW)` per component),
  and the check is made with `fstat` on that descriptor: a type `f` entry
  must be a regular file with one link (a hard link to another file is
  refused), and a type `l` entry is read with `readlinkat` from its
  directory's descriptor. The bytes that are expanded are the bytes read
  from that descriptor. Every input is read this way into memory before the
  first write, so nothing the user changes afterwards reaches the target.
  `.sec/config`, `.sec/names` and `.sec/manifest` are read the same way,
  here and by `manifest pull|apply`.
  `expand` does not run `git` as root in a checkout owned by someone else:
  its configuration (hooks, `core.fsmonitor`, filters) would run code as
  root.
- It resolves every placeholder in the selected files. Missing keys, uuid
  mismatches, malformed placeholders and unknown transforms are collected
  first and reported together. If there is any, nothing is written.
- `-to <dir>`: writes the files under `dir` mode 0600, directories 0700.
  `dir` must be outside the repository. This is for review and for deploy
  tools that copy files themselves. The writes use the same descriptor walk
  as `import` (6.3), beneath `dir`, so an existing `dir/etc -> ~/.ssh`
  cannot redirect them. Symlinks of the configuration (type `l`) are
  created as symlinks, and a declared link that entries lie beneath is
  followed by the same rule as for `-install` below, with `dir` as the
  root: the link must be the one `-to` created, or an existing one with
  exactly the declared target, and it must resolve beneath `dir`. A
  declared target that leaves `dir` (an absolute `/etc/...` link, as on the
  host) cannot be followed inside the staging tree, so its descendants are
  written at the path the link resolves to on the node, mapped under `dir`
  (`dir/etc/nginx/...` for a link to `/etc/nginx`), and the link itself is
  still created. The staging tree then holds every entry, and nothing is
  ever written outside `dir`.
- `-install <root>` (usually `/`, under sudo) never writes through a symlink
  it was not told about. `<root>` itself is opened component by component
  from a descriptor of `/`, with `O_NOFOLLOW` on every component, and that
  descriptor is the one every preflight check and every write is relative
  to; a `<root>` below a user-writable directory cannot be swapped for a
  link to `/` between the check and the write. `-to <dir>` pins `dir` the
  same way. Every existing component below `<root>` on the way
  to a target must be a plain directory, or a symlink that the manifest of
  the node declares as type `l` whose target, as `readlinkat` returns it,
  is byte for byte the target in the repository, and which resolves under
  `<root>`. A declared link that has drifted to another target is an error
  even when the new target is under `<root>`: with root `/` almost every
  target is, and following it would put a descendant type `s` or `d` entry
  at an unrelated privileged path. `-install` does not repair it on its own;
  `manifest apply -links` (6.8) replaces drifted declared links with the
  declared target, after printing old and new, and only then can `-install`
  go on. A declared link that is missing is created with the declared
  target before any entry beneath it. A declared link whose target goes
  through another symlink is accepted only if that one is declared and
  intact too, by the same rule. Anything else is an error before the first
  write, so a staging root with `etc -> /etc` cannot overwrite the live
  host. The check and the
  write are the same walk over directory descriptors, as for `import`
  (6.3): with `openat2(RESOLVE_BENEATH)`, a declared symlink is resolved by
  hand and checked to stay under `<root>`. A symlink swapped in during the
  run is therefore not followed either. The final target of every entry,
  type `s` and `d` included, must be under `<root>` once resolved, whatever
  the manifest says. Before the first write, every entry's target is
  resolved (through declared links, as above) and the resolved targets are
  compared: two entries that land on the same file, such as `link/token`
  and `real/token` with `link -> real`, are an error naming both, so the
  order of the manifest never decides what is deployed. The same holds for
  `-to`. Type `l` entries are created as symlinks, never written
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
   type `f`/`l` entry has a file of that type: a symlink declared as `f`, a
   regular file declared as `l`, or a tracked file at a path declared as
   `d` is a finding, so a commit that `expand` would refuse is refused here
   first. Type `s` paths must not exist in the tree.
   No entry lies below an entry of type `f` or `s` (`etc/credential` and
   `etc/credential/token`): an ancestor must be a directory (`d`, or a
   directory the tree implies) or a declared link (`l`). `expand` repeats
   this on the resolved targets before the first write, so an install never
   stops halfway on a path that cannot be both a file and a directory.
   Owner and group must not be empty. Whether they exist on the node is
   checked on install (4.4).
4. **Forbidden paths** (`forbidden`). No path in the checked snapshot
   (working tree, index, or each commit of the range or history) matches
   `forbid`, the keystore path or `.sec/keys`.
5. **Private keys** (`private_key`). No `PRIVATE KEY` block (the existing
   detector; an allowlisted fp is respected).
6. **Known values** (`known_value`; only when the keystore is available).
   No value of any key occurs, in any form from 6.3 step 1, in a text file
   or anywhere in the bytes of a binary file (8). Only strong forms are
   searched: a form shorter than 8 bytes or cheap under the cost model (as
   in 6.3 step 5) would match ordinary text everywhere (`0` in every
   `0600`) and is left out (4.3: weak and default values are not segscan's
   task). Weakness is judged per form, not per key, so the distinctive
   forms of a weak value, such as `sha256("admin")`, are still searched
   everywhere. Scopes play no part here: a strong form is a finding under
   any path. No secret file from `files/` is in the repository, under any
   path:
   - a file that contains the whole content of a (non-empty) secret file anywhere, as
     a substring of its raw or unpacked bytes, is a finding. Equality alone
     would miss a secret file with only short lines (`abc123\nxyz789`)
     that was embedded in another file or had a byte appended. This also
     covers binary secret files such as a PKCS#12 bundle;
   - so is a file that contains a line of one (trimmed of spaces);
   - so is a file that contains the value part of a `name=value` line of
     one, so `TOKEN=Zx81...` is found under another name. The value is
     taken as written, and also without one pair of surrounding `"..."` or
     `'...'`. Shell and dotenv escaping and inline comments are not
     interpreted (12.9): our secrets never need them, and a line that uses
     them (`JAVA_OPTS="-Xmx1g -Xms1g"`) holds no secret to miss.

   An empty pattern (an empty or blank line, `OPTIONAL=`, `X=""`) is dropped
   before any transform: it holds no secret, and its forms (`sha256("")`)
   are well-known constants that would match unrelated files.

   Each of these patterns is searched only in its strong forms (below), so
   `}`, `[main]`, `PORT=8080` or `DEBUG=true` match nothing by themselves.

   Like a keystore value, every such pattern (the whole content, each
   line, each value) is turned into its forms first, under each single
   transform of 5.2 and the chains used in the repository (6.3 step 1),
   and the strength rule is applied to each form, not to the pattern: a
   secret file that holds only `0` is not searched as `0`, but its
   `sha256("0")` form is, and so a base64 or sha256 form of a line from
   `app.env` is found too. A secret file whose every form of its whole
   content is weak is reported by `key check -weak` like a weak key.

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

- the ref tips already checked, and the time the run completed;
- the rotation ids of every retired record and every retired secret-file
  version it searched (4.3), so `key forget` can tell whether a run came
  after a retirement;
- for every key, a digest of its name, its uuid and the complete sorted set
  of forms that check 6 searches for it (6.3 step 1), for the current value
  and every retired one. The set changes with the value, with a rotation,
  with a new transform chain in the repository, and with a segscan release
  that adds or changes a transform or the cost model, and any of these
  counts as a change. The state also records the segscan version that
  wrote it; when another version reads it, the next `--all` checks the
  whole history and no earlier run counts for `key forget`, since how
  check 6 reads files (encodings, containers) may have changed.
  For every secret file, a digest of its name and of every form searched
  for it, again for the current version in `files/` and every retired one
  in `retired-files/`. A version that was current and retired again
  between two clean runs (A, then B, then C) is still part of the set, so
  it is checked against the whole history like C. All digests are HMAC-SHA256 under a random
  256-bit key kept in its own file, `check.key` (mode 0600), not in
  `check.state`. The state alone does not help to guess a value: without the
  key, a candidate cannot be tested against a digest offline.

The state only advances after a complete run with no findings: tips and
digests are written then and only then. A run with findings, or one that
stopped early, leaves the state as it was, so the next run checks the same
history again and reports the same findings until they are fixed.

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
manifest apply -node <node> [path...]   set live attributes from the manifest, content untouched   (sudo);
                                        same descriptor walk as -install (6.4): an undeclared
                                        symlink on the way is an error, and every change is made
                                        on the opened descriptor (fchmod, fchown, fsetxattr), never
                                        by path
manifest apply -links -node <node>      replace declared type l links whose target has drifted
                                        with the target in the repository, printing old and new;
                                        a link only, never what it points to   (sudo)
manifest fix                            add entries for new files, drop f and l entries of
                                        deleted ones
```

`manifest fix` gives a new file the owner and group of the nearest parent
directory entry (type `d`) of the same node, and that directory's mode
without execute, setuid, setgid and sticky bits (`0750` -> `0640`). A
symlink gets `0777`. With no parent entry it uses `root:root 0600`. Every
added entry is printed for review. Paths that match `forbid` are not added.
Only type `f` and `l` entries, which need a file in the tree, are dropped
when their file is gone. Type `d` and `s` entries describe the target and
have no file of their own (git keeps no empty directory, and a secret file
is never in the tree), so `manifest fix` never drops them; they are removed
by hand.

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

A file with a NUL in its first 8000 bytes is binary for the statistical
scanner. For check 6 the test is stricter and covers the whole file: any
file that is not valid UTF-8 text, or holds a NUL anywhere, is binary, so a
compressed payload behind a long text prefix (a self-extracting shell
script) is treated as binary too. A configuration repository holds few
such files, so segscan does not try to understand every binary format;
what it cannot read fully is refused, and keeping such a file is a visible
decision in `.sec/allow` (12.9).

- `scan` and `hook` without `.sec/`: skipped, as now.
- `check`, and `scan`/`hook` inside `.sec/` with `binary = scan`: the
  statistical scanner reads the file's strings (runs of at least 8
  printable ASCII bytes, or of at least 8 UTF-16LE characters) and reports
  findings with the byte offset in the `col` field.
- Check 6 searches the raw bytes for every strong form of every value
  (6.5), as is, in UTF-16LE and in UTF-16BE. It unpacks two containers,
  wherever they start in the file (so also behind a self-extracting
  prefix): gzip members (`1f 8b 08`) and ZIP archives (by their
  end-of-central-directory record), up to 64 MiB unpacked and two levels
  deep, and searches what they hold the same way.
- Every other binary file (PDF, images, other compressed or archive
  formats, anything encrypted) and every unpack that fails or hits a limit
  is a blocking `known_value` finding, "not fully scanned". A file that
  must stay goes into `.sec/allow` as `path:<glob>` (`path:**/*.png`).
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

Excluding what the destination already has is right for checks 1-5, which
every machine runs the same way. It is not enough for check 6: a commit a
collaborator without the keystore pushed to a feature branch is advertised
by the destination, yet no one has searched it for known values. So on a
machine with the keystore, pre-push excludes only the tips that
`check.state` records as checked by a complete `check --all` (6.5), and
every other pushed commit, advertised or not, gets check 6. That is fast
feedback only; the guarantee stays with `check --all`, which searches every
commit reachable from any local ref, the pushed ones included.

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
   - the keystore reader with mode checks, `key set|check|retire`;
   - `expand -to`, `import -n` and `import` with the round trip;
   - `check` check 6, the `train` guard.
   - Left for later: `check.state` (so `-all` always checks the whole
     history, and check 6 takes chains of three or four from the checked
     snapshots and `HEAD` only) and `key forget`, which needs that state.
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
   Values set by external tools may be anything within the alphabet of
   4.3.
5. `check --all` keeps incremental state in the keystore (6.5).
6. Transform chains: configurations need at most two (a sha256 passed
   through a URL); three and four exist only for our own tools. Single
   transforms and pairs are always searched, longer chains only when the
   repository uses them (6.3 step 1).
7. Weak and default values (`admin`, `password12345`) are not segscan's
   task. segscan blocks commits of real keys; finding default credentials
   is a deploy-time job for other tools. Check 6 searches strong forms
   only, and `import` only refuses to replace a weak value blindly (4.3).
8. Long secret files that are deployed by hand (a PKCS#12 bundle for
   S/MIME) never enter the repository. Putting one into `files/` without a
   type `s` entry makes check 6 search for it; `key check` lists it as
   unnamed, which is expected for such a file.
9. Edge cases are refused, not parsed. The nodes run Linux, the files use
   LF, and our values have no spaces, quotes or escapes. So instead of
   handling CRLF, shell and dotenv quoting, or every binary format, segscan
   rejects what falls outside: `.sec/` files with CR or invalid UTF-8,
   key values outside the alphabet of 4.3, and binary files it cannot fully
   read (8), each of which is either fixed or allowlisted on purpose.
   Secret-file values are searched as written and unquoted, without
   escaping rules.
10. Details fixed while building stage 3:
    - "Cheap under the cost model" (4.3, 6.3, 6.5) means: fewer than 4
      distinct bytes, or the statistical scanner with the built-in model
      and default thresholds finds nothing random in the form. The
      built-in model, not the repository's, so the set of searched forms
      changes only with a segscan release.
    - `import` drops, for the choice of transform (6.3 step 3), chains with
      a step that cannot change any input it can get: an escape of hex,
      base58 or base64url, and `dq`, `sq`, `nginxq` of a keystore value,
      which has no quote, backslash or control byte. Of the chains left it
      takes the shortest, counting the bare value as one step, so bare,
      `urlenc` and `xml` of an alphanumeric value stay an ambiguity, while
      `sha256` and `sha256:urlenc` do not. `-form FILE:LINE=T` takes the
      live path or the repository path; it applies to every ambiguous
      occurrence on that line.
    - `import` takes files and symlinks, not directories; `-secret` takes
      exactly one path. It finds the repository by walking up to `.git`
      instead of running git, which under sudo would refuse a checkout
      owned by someone else or run its configuration as root.
    - A reader that finds `pending` under its shared lock uses the
      journal's contents, which hold the replaced value in `retired`; the
      journal holds `keys` and `retired` whole, so applying it twice is
      harmless.
    - Check 6 still runs on commits from before `.sec/` (6.5 lists only
      grammar, forbidden paths and private keys for them): the known values
      are exactly what a repository taken over carries in its old history.
      Only the "not fully scanned" finding is left out there, since no
      `.sec/allow` can be added to such a commit.
    - Patterns of a binary secret file are its whole content only, no lines
      or values; a whole content over 64 KiB gets the bare form and single
      transforms only, so a large PKCS#12 bundle stays cheap for every hook
      (5.1 asks for this without a streaming matcher). A binary form of 64
      bytes or more and any form of 4 KiB or more is strong without asking
      the scanner.
    - Symlink targets are searched like file content. A `keys` line whose
      value is outside the alphabet is reported by `key check`, searched by
      check 6, unusable for `expand`, and retired by the next `key set`.

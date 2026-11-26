//go:build linux

package main

// The keystore (DESIGN.md 3.2, 4.3): keys, retired, files/, retired-files/
// in a directory outside the repository, read and written only through
// descriptors (fsx_linux.go), under a flock on the directory itself.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func keystorePath(cfg *secConfig) (string, error) {
	p := cfg.keystoreDir()
	if err := checkKeystorePath(p); err != nil {
		return "", err
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("keystore %q: must be an absolute path or start with ~/", p)
	}
	return p, nil
}

// openKeystore opens and locks the keystore: exclusive for commands that
// change it (they also finish an interrupted rotation), shared for readers.
// Without create, a missing keystore is errNoKeystore.
func openKeystore(cfg *secConfig, top string, exclusive, create bool) (*keystore, error) {
	p, err := keystorePath(cfg)
	if err != nil {
		return nil, badKeystorePath{err}
	}
	if rel, ok := relBelowTop(canonical(top), p); ok {
		return nil, badKeystorePath{fmt.Errorf("keystore %s is inside the repository (%s)", p, rel)}
	}
	if rel, err := filepath.Rel(canonical(top), canonical(p)); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
		return nil, badKeystorePath{fmt.Errorf("keystore %s is inside the repository (%s)", p, rel)}
	}
	fd, err := openDirPinned(p, create)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errNoKeystore
		}
		return nil, err
	}
	ks := &keystore{path: p, fd: fd, keys: map[string]ksKey{}}
	fail := func(err error) (*keystore, error) { syscall.Close(fd); return nil, err }
	if err := checkOwned(p, fd, true); err != nil {
		return fail(err)
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(fd, how); err != nil {
		return fail(fmt.Errorf("lock %s: %v", p, err))
	}
	// A pending journal under the lock is left over from a process that
	// died. A writer finishes it; a reader takes its contents, which hold
	// the replaced value in retired, so nothing is missed meanwhile.
	var j *journal
	if _, _, err := readAt(fd, "pending"); err == nil {
		if exclusive {
			err = ks.recover()
		} else {
			j, err = ks.journal()
		}
		if err != nil {
			return fail(err)
		}
	}
	if err := ks.load(j); err != nil {
		return fail(err)
	}
	return ks, nil
}

func (ks *keystore) close() { syscall.Close(ks.fd) }

// checkOwned checks the directory (0700, the invoker's) or a file (0600, the
// invoker's or root's, one link) behind fd.
func checkOwned(name string, fd int, dir bool) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	return checkStat(name, &st, dir)
}

func checkStat(name string, st *syscall.Stat_t, dir bool) error {
	uid, _ := invoker()
	perm := st.Mode & 0o7777
	switch {
	case dir && perm != 0o700:
		return fmt.Errorf("%s: mode %04o, must be 0700", name, perm)
	case dir && int(st.Uid) != uid:
		return fmt.Errorf("%s: owned by uid %d, must be %d", name, st.Uid, uid)
	case !dir && perm != 0o600:
		return fmt.Errorf("%s: mode %04o, must be 0600", name, perm)
	case !dir && int(st.Uid) != uid && st.Uid != 0:
		return fmt.Errorf("%s: owned by uid %d, must be %d or root", name, st.Uid, uid)
	case !dir && st.Nlink != 1:
		return fmt.Errorf("%s: has %d links, must have one", name, st.Nlink)
	}
	return nil
}

func (ks *keystore) readFile(dfd int, name string) ([]byte, error) {
	data, st, err := readAt(dfd, name)
	if err != nil {
		return nil, err
	}
	if err := checkStat(ks.path+"/"+name, st, false); err != nil {
		return nil, err
	}
	return data, nil
}

func (ks *keystore) load(j *journal) error {
	data, err := ks.readFile(ks.fd, "keys")
	if j != nil {
		data, err = []byte(j.Keys), nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for no, l := range strings.Split(string(data), "\n") {
		if l == "" || l[0] == '#' {
			continue
		}
		f := strings.SplitN(l, "\t", 3)
		if len(f) != 3 || !validName(f[0]) || !isUUID([]byte(f[1]), false) || f[2] == "" {
			return fmt.Errorf("%s/keys:%d: expected name<TAB>uuid<TAB>value", ks.path, no+1)
		}
		if _, dup := ks.keys[f[0]]; dup {
			return fmt.Errorf("%s/keys:%d: duplicate key %s", ks.path, no+1, f[0])
		}
		if !validValue(f[2]) {
			// Not usable, but still searched; key check reports it.
			ks.invalid = append(ks.invalid, ksKey{f[0], f[1], f[2]})
			continue
		}
		ks.keys[f[0]] = ksKey{f[0], f[1], f[2]}
	}
	data, err = ks.readFile(ks.fd, "retired")
	if j != nil {
		data, err = []byte(j.Retired), nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for no, l := range strings.Split(string(data), "\n") {
		if l == "" || l[0] == '#' {
			continue
		}
		// A retired value may be one that was outside the alphabet: it is
		// only searched, never written anywhere.
		f := strings.SplitN(l, "\t", 5)
		if len(f) != 5 || !validName(f[0]) || f[4] == "" {
			return fmt.Errorf("%s/retired:%d: expected name<TAB>uuid<TAB>rotation<TAB>time<TAB>value", ks.path, no+1)
		}
		ks.retired = append(ks.retired, ksRetired{f[0], f[1], f[2], f[3], f[4]})
	}
	for _, dir := range []string{"files", "retired-files"} {
		dfd, err := openSubdir(ks.fd, dir, false)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if err := checkOwned(ks.path+"/"+dir, dfd, true); err != nil {
			syscall.Close(dfd)
			return err
		}
		names, err := listDir(dfd)
		if err != nil {
			syscall.Close(dfd)
			return err
		}
		sort.Strings(names)
		for _, n := range names {
			if strings.HasPrefix(n, ".") { // a temporary of an interrupted write
				continue
			}
			data, err := ks.readFile(dfd, n)
			if err != nil {
				syscall.Close(dfd)
				return fmt.Errorf("%s/%s/%s: %v", ks.path, dir, n, err)
			}
			f := ksFile{Name: n, Data: data}
			if dir == "retired-files" {
				// <name>.<time>.<rotation>: the name is everything before the last two parts.
				parts := strings.Split(n, ".")
				if len(parts) < 3 || !validName(strings.Join(parts[:len(parts)-2], ".")) {
					syscall.Close(dfd)
					return fmt.Errorf("%s/retired-files/%s: expected <name>.<time>.<rotation>", ks.path, n)
				}
				f.Name, f.Version = strings.Join(parts[:len(parts)-2], "."), n
			} else if !validName(n) {
				syscall.Close(dfd)
				return fmt.Errorf("%s/files/%s: not a valid secret name", ks.path, n)
			}
			ks.files = append(ks.files, f)
		}
		syscall.Close(dfd)
	}
	return nil
}

func (ks *keystore) keysText() []byte {
	var names []string
	for n := range ks.keys {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# segscan keystore: name<TAB>uuid<TAB>value\n")
	for _, n := range names {
		k := ks.keys[n]
		b.WriteString(k.Name + "\t" + k.UUID + "\t" + k.Value + "\n")
	}
	for _, k := range ks.invalid { // kept until key set replaces them
		if _, ok := ks.keys[k.Name]; !ok {
			b.WriteString(k.Name + "\t" + k.UUID + "\t" + k.Value + "\n")
		}
	}
	return []byte(b.String())
}

func (ks *keystore) retiredText() []byte {
	var b strings.Builder
	b.WriteString("# segscan retired values: name<TAB>uuid<TAB>rotation<TAB>time<TAB>value\n")
	for _, r := range ks.retired {
		b.WriteString(strings.Join([]string{r.Name, r.UUID, r.Rotation, r.Time, r.Value}, "\t") + "\n")
	}
	return []byte(b.String())
}

func newRotation() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		die(err)
	}
	return hex.EncodeToString(b[:])
}

type journal struct {
	Rotation string `json:"rotation"`
	Keys     string `json:"keys"`
	Retired  string `json:"retired"`
}

// set gives name a new value. The replaced value goes to retired first,
// through the pending journal, so a crash at any point leaves it searchable.
func (ks *keystore) set(name, uuid, value string) (retiredOld bool, err error) {
	old, had := ks.keys[name]
	if !had {
		old, had = ks.takeInvalid(name) // an unusable value is still retired, not dropped
	}
	if had && old.Value == value && old.UUID == uuid {
		return false, nil
	}
	ks.keys[name] = ksKey{name, uuid, value}
	rot := newRotation()
	if had {
		ks.retired = append(ks.retired, ksRetired{old.Name, old.UUID, rot, time.Now().UTC().Format(time.RFC3339), old.Value})
	}
	return had, ks.commit(rot)
}

// retire moves the current value of name to retired.
// takeInvalid removes and returns the invalid line of name.
func (ks *keystore) takeInvalid(name string) (ksKey, bool) {
	for i, k := range ks.invalid {
		if k.Name == name {
			ks.invalid = append(ks.invalid[:i:i], ks.invalid[i+1:]...)
			return k, true
		}
	}
	return ksKey{}, false
}

func (ks *keystore) retire(name string) error {
	old, had := ks.keys[name]
	if !had {
		old, had = ks.takeInvalid(name)
	}
	if !had {
		return fmt.Errorf("no value of %s in the keystore", name)
	}
	delete(ks.keys, name)
	rot := newRotation()
	ks.retired = append(ks.retired, ksRetired{old.Name, old.UUID, rot, time.Now().UTC().Format(time.RFC3339), old.Value})
	return ks.commit(rot)
}

// commit writes keys and retired through the journal.
func (ks *keystore) commit(rot string) error {
	j, _ := json.Marshal(journal{rot, string(ks.keysText()), string(ks.retiredText())})
	if err := writeAt(ks.fd, "pending", j, 0o600); err != nil {
		return err
	}
	return ks.recover()
}

func (ks *keystore) journal() (*journal, error) {
	data, err := ks.readFile(ks.fd, "pending")
	if err != nil {
		return nil, err
	}
	var j journal
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("%s/pending: %v", ks.path, err)
	}
	return &j, nil
}

// recover applies the pending journal: retired first, then keys. The
// journal holds both files whole, so applying it twice is harmless.
func (ks *keystore) recover() error {
	j, err := ks.journal()
	if err != nil {
		return err
	}
	if err := writeAt(ks.fd, "retired", []byte(j.Retired), 0o600); err != nil {
		return err
	}
	if err := writeAt(ks.fd, "keys", []byte(j.Keys), 0o600); err != nil {
		return err
	}
	if err := syscall.Unlinkat(ks.fd, "pending"); err != nil {
		return err
	}
	return syscall.Fsync(ks.fd)
}

// retireFile moves files/<name> to retired-files/ (a rename: it is never
// absent from both).
func (ks *keystore) retireFile(name string) error {
	dfd, err := openSubdir(ks.fd, "files", false)
	if err != nil {
		return fmt.Errorf("no secret file %s in the keystore", name)
	}
	defer syscall.Close(dfd)
	if _, _, err := readAt(dfd, name); err != nil {
		return fmt.Errorf("no secret file %s in the keystore", name)
	}
	return ks.moveToRetired(dfd, name)
}

func (ks *keystore) moveToRetired(dfd int, name string) error {
	rfd, err := openSubdir(ks.fd, "retired-files", true)
	if err != nil {
		return err
	}
	defer syscall.Close(rfd)
	ver := name + "." + time.Now().UTC().Format("20060102T150405Z") + "." + newRotation()
	if err := syscall.Renameat(dfd, name, rfd, ver); err != nil {
		return err
	}
	if err := syscall.Fsync(rfd); err != nil {
		return err
	}
	return syscall.Fsync(dfd)
}

// setFile stores a secret file. A different current version is moved to
// retired-files/ first (a rename, durable before the new one is written).
func (ks *keystore) setFile(name string, data []byte) error {
	dfd, err := openSubdir(ks.fd, "files", true)
	if err != nil {
		return err
	}
	defer syscall.Close(dfd)
	old, _, err := readAt(dfd, name)
	if err == nil {
		if string(old) == string(data) {
			return nil
		}
		if err := ks.moveToRetired(dfd, name); err != nil {
			return err
		}
	}
	return writeAt(dfd, name, data, 0o600)
}

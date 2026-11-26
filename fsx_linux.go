//go:build linux

package main

// Descriptor-based file access for the keystore and for writes outside the
// repository (DESIGN.md 3.2, 6.3, 6.4): no path is opened in one call, every
// component is opened with O_NOFOLLOW from the descriptor of its parent, so
// a symlink swapped in anywhere on the way is never followed.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const dirFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// invoker is the uid that owns the keystore and the files segscan writes for
// the user: the sudo caller under sudo, the real uid otherwise.
func invoker() (uid, gid int) {
	if os.Geteuid() == 0 {
		var u, g int
		if _, err := fmt.Sscan(os.Getenv("SUDO_UID"), &u); err == nil {
			if _, err := fmt.Sscan(os.Getenv("SUDO_GID"), &g); err != nil {
				g = -1
			}
			return u, g
		}
	}
	return os.Getuid(), os.Getgid()
}

// openDirPinned opens the absolute directory p one component at a time from
// /, with O_NOFOLLOW on each. With create, missing components are made with
// mode 0700 and, when running as root, given to the invoker.
func openDirPinned(p string, create bool) (int, error) {
	if !filepath.IsAbs(p) {
		return -1, fmt.Errorf("%s: not an absolute path", p)
	}
	for _, c := range strings.Split(p, "/") {
		if c == "." || c == ".." {
			return -1, fmt.Errorf("%s: no . or .. components allowed", p)
		}
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	uid, gid := invoker()
	for _, c := range strings.Split(strings.Trim(p, "/"), "/") {
		if c == "" {
			continue
		}
		nfd, err := syscall.Openat(fd, c, dirFlags, 0)
		if err == syscall.ENOENT && create {
			if err = syscall.Mkdirat(fd, c, 0o700); err == nil {
				nfd, err = syscall.Openat(fd, c, dirFlags, 0)
				if err == nil && os.Geteuid() == 0 {
					syscall.Fchown(nfd, uid, gid)
				}
			} else if err == syscall.EEXIST {
				nfd, err = syscall.Openat(fd, c, dirFlags, 0)
			}
		}
		if err != nil {
			err = describeAt(fd, p, c, err)
			syscall.Close(fd)
			return -1, err
		}
		syscall.Close(fd)
		fd = nfd
	}
	return fd, nil
}

// describeAt explains why the component c in dfd could not be opened as a
// directory: what is there instead.
func describeAt(dfd int, p, c string, err error) error {
	if err != syscall.ELOOP && err != syscall.ENOTDIR {
		return pathErr(p, c, err)
	}
	st, serr := lstatAt(dfd, c)
	if serr != nil {
		return pathErr(p, c, err)
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFLNK:
		return &notDirError{p, c, "a symlink; segscan does not follow symlinks here"}
	case syscall.S_IFREG:
		if st.Size == 0 {
			return &notDirError{p, c, "an empty regular file, not a directory"}
		}
		return &notDirError{p, c, "a regular file, not a directory"}
	}
	return &notDirError{p, c, "not a directory"}
}

type notDirError struct{ path, comp, what string }

func (e *notDirError) Error() string {
	if strings.HasSuffix(strings.TrimRight(e.path, "/"), "/"+e.comp) {
		return fmt.Sprintf("%s is %s", e.path, e.what)
	}
	return fmt.Sprintf("%s: %s is %s", e.path, e.comp, e.what)
}

func pathErr(p, c string, err error) error {
	switch err {
	case syscall.ELOOP, syscall.ENOTDIR:
		return fmt.Errorf("%s: %s is a symlink or not a directory; refusing to follow it", p, c)
	case syscall.ENOENT:
		return &os.PathError{Op: "open", Path: p, Err: os.ErrNotExist}
	}
	return &os.PathError{Op: "open", Path: p, Err: err}
}

// openSubdir opens name in the directory dfd, never through a symlink.
func openSubdir(dfd int, name string, create bool) (int, error) {
	fd, err := syscall.Openat(dfd, name, dirFlags, 0)
	if err == syscall.ENOENT && create {
		if err = syscall.Mkdirat(dfd, name, 0o700); err == nil || err == syscall.EEXIST {
			fd, err = syscall.Openat(dfd, name, dirFlags, 0)
			if err == nil && os.Geteuid() == 0 {
				uid, gid := invoker()
				syscall.Fchown(fd, uid, gid)
			}
		}
	}
	if err != nil {
		return -1, pathErr(name, name, err)
	}
	return fd, nil
}

// readAt reads the regular file name in dfd, never through a symlink, and
// returns it with its stat.
func readAt(dfd int, name string) ([]byte, *syscall.Stat_t, error) {
	fd, err := syscall.Openat(dfd, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if err == syscall.ELOOP {
			return nil, nil, fmt.Errorf("%s is a symlink; refusing to follow it", name)
		}
		return nil, nil, pathErr(name, name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, nil, fmt.Errorf("%s is not a regular file", name)
	}
	data, err := io.ReadAll(f)
	return data, &st, err
}

// writeAt replaces name in dfd: a new temporary file created with O_EXCL,
// fsynced, given to the invoker when running as root, renamed over name, and
// the directory fsynced. Nothing is ever written through an existing entry.
func writeAt(dfd int, name string, data []byte, mode uint32) error {
	var r [8]byte
	rand.Read(r[:])
	tmp := "." + name + ".tmp." + hex.EncodeToString(r[:])
	fd, err := syscall.Openat(dfd, tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = syscall.Fchmod(fd, mode)
	}
	if err == nil && os.Geteuid() == 0 {
		uid, gid := invoker()
		err = syscall.Fchown(fd, uid, gid)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = syscall.Renameat(dfd, tmp, dfd, name)
	}
	if err != nil {
		syscall.Unlinkat(dfd, tmp)
		return fmt.Errorf("%s: %v", name, err)
	}
	return syscall.Fsync(dfd)
}

// listDir returns the names in the directory dfd.
func listDir(dfd int) ([]string, error) {
	nfd, err := syscall.Openat(dfd, ".", dirFlags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(nfd), ".")
	defer f.Close()
	return f.Readdirnames(-1)
}

// readlinkAt reads the symlink name in dfd.
func readlinkAt(dfd int, name string) (string, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 4096)
	n, _, e := syscall.Syscall6(syscall.SYS_READLINKAT, uintptr(dfd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if e != 0 {
		return "", &os.PathError{Op: "readlink", Path: name, Err: e}
	}
	return string(buf[:n]), nil
}

// symlinkAt replaces name in dfd with a symlink to target: a new link under
// a temporary name, renamed over name.
func symlinkAt(dfd int, target, name string) error {
	var r [8]byte
	rand.Read(r[:])
	tmp := "." + name + ".tmp." + hex.EncodeToString(r[:])
	t, err := syscall.BytePtrFromString(target)
	if err != nil {
		return err
	}
	tp, err := syscall.BytePtrFromString(tmp)
	if err != nil {
		return err
	}
	if _, _, e := syscall.Syscall(syscall.SYS_SYMLINKAT, uintptr(unsafe.Pointer(t)), uintptr(dfd), uintptr(unsafe.Pointer(tp))); e != 0 {
		return fmt.Errorf("%s: %v", name, e)
	}
	if os.Geteuid() == 0 {
		uid, gid := invoker()
		fchownatNoFollow(dfd, tmp, uid, gid)
	}
	if err := syscall.Renameat(dfd, tmp, dfd, name); err != nil {
		syscall.Unlinkat(dfd, tmp)
		return fmt.Errorf("%s: %v", name, err)
	}
	return syscall.Fsync(dfd)
}

func fchownatNoFollow(dfd int, name string, uid, gid int) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	const atSymlinkNoFollow = 0x100
	if _, _, e := syscall.Syscall6(syscall.SYS_FCHOWNAT, uintptr(dfd), uintptr(unsafe.Pointer(p)), uintptr(uid), uintptr(gid), atSymlinkNoFollow, 0); e != 0 {
		return e
	}
	return nil
}

// lstatAt stats name in dfd without following a symlink: an O_PATH
// descriptor of the entry itself, then fstat.
func lstatAt(dfd int, name string) (*syscall.Stat_t, error) {
	const oPath = 0x200000
	fd, err := syscall.Openat(dfd, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// walkDirs opens the directory rel (slash-separated, relative) below dfd,
// one component at a time, never through a symlink. With create, missing
// directories are made with mode 0700. The caller closes the result, which
// is a new descriptor even for rel "" or ".".
func walkDirs(dfd int, rel string, create bool) (int, error) {
	fd, err := syscall.Openat(dfd, ".", dirFlags, 0)
	if err != nil {
		return -1, err
	}
	for _, c := range strings.Split(rel, "/") {
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			syscall.Close(fd)
			return -1, fmt.Errorf("%s: no .. components allowed", rel)
		}
		nfd, err := openSubdir(fd, c, create)
		syscall.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("%s: %w", rel, err)
		}
		fd = nfd
	}
	return fd, nil
}

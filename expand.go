//go:build linux

package main

// segscan expand -to (DESIGN.md 6.4): the files of one node with every
// placeholder resolved, written into a staging directory outside the
// repository. Inputs are read through descriptors of the repository top,
// never through a symlink, and all of them are read and resolved before
// the first write.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// ---------- the repository, read through descriptors ----------

type repoView struct {
	top   string
	fd    int
	cfg   *secConfig
	names *nameList
	man   []*mEntry
}

// findTop walks up from the current directory to the first one with .git,
// without running git: under sudo, git would refuse a checkout owned by
// someone else, or run its configuration (hooks, fsmonitor) as root.
func findTop() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			if st, err := os.Lstat(filepath.Join(dir, secDir)); err == nil && st.IsDir() {
				return dir
			}
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func openRepo() *repoView {
	top := findTop()
	if top == "" {
		die(fmt.Errorf("no %s/ in this repository: run segscan init", secDir))
	}
	fd, err := openDirPinned(top, false)
	if err != nil {
		die(err)
	}
	r := &repoView{top: top, fd: fd}
	read := func(name string) []byte {
		data, link, err := r.read(secDir + "/" + name)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			die(err)
		}
		if link {
			die(fmt.Errorf("%s/%s is a symlink; refusing to follow it", secDir, name))
		}
		return data
	}
	if r.cfg, err = parseSecConfig(read("config"), filepath.Base(top)); err != nil {
		die(fmt.Errorf("%s/config: %v", secDir, err))
	}
	var probs []lineProblem
	if r.names, probs = parseNames(read("names")); len(probs) > 0 {
		die(fmt.Errorf("%s/names:%d: %s", secDir, probs[0].Line, probs[0].Msg))
	}
	if r.man, probs = parseManifest(read("manifest")); len(probs) > 0 {
		die(fmt.Errorf("%s/manifest:%d: %s", secDir, probs[0].Line, probs[0].Msg))
	}
	return r
}

// read returns a regular file with one link, or the target of a symlink
// (link true), at the repository path rel; no symlink on the way is followed.
func (r *repoView) read(rel string) (data []byte, link bool, err error) {
	dfd, err := walkDirs(r.fd, path.Dir(rel), false)
	if err != nil {
		return nil, false, err
	}
	defer syscall.Close(dfd)
	base := path.Base(rel)
	st, err := lstatAt(dfd, base)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, false, os.ErrNotExist
		}
		return nil, false, fmt.Errorf("%s: %v", rel, err)
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFLNK:
		t, err := readlinkAt(dfd, base)
		return []byte(t), true, err
	case syscall.S_IFREG:
		data, st, err := readAt(dfd, base)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %v", rel, err)
		}
		if st.Nlink != 1 {
			return nil, false, fmt.Errorf("%s: has %d hard links; refusing to read it", rel, st.Nlink)
		}
		return data, false, nil
	}
	return nil, false, fmt.Errorf("%s: not a regular file or symlink", rel)
}

// nodeRootFor finds the node root of -node: one path component that names
// an existing directory matching roots.
func nodeRootFor(r *repoView, node string) string { return nodeRootMaybe(r, node, false) }

// nodeRootMaybe: with create (import), a node directory that does not exist
// yet is accepted when exactly one root glob gives it.
func nodeRootMaybe(r *repoView, node string, create bool) string {
	if node == "" || node == "." || node == ".." || strings.ContainsAny(node, "/\x00") {
		die(fmt.Errorf("-node %q: must be one path component naming a node", node))
	}
	var found, missing []string
	for _, root := range r.cfg.Roots {
		root = strings.Trim(root, "/")
		cand := root
		if strings.ContainsAny(path.Base(root), "*?[") {
			cand = path.Join(path.Dir(root), node)
		} else if path.Base(root) != node {
			continue
		}
		if !r.cfg.isNodeRoot(cand) {
			continue
		}
		if fd, err := walkDirs(r.fd, cand, false); err == nil {
			syscall.Close(fd)
			found = append(found, cand)
		} else if create && errorsIsNotExist(err) {
			missing = append(missing, cand)
		}
	}
	if len(found) == 0 && len(missing) == 1 {
		return missing[0]
	}
	switch len(found) {
	case 0:
		die(fmt.Errorf("-node %s: no such node directory under roots = %s", node, strings.Join(r.cfg.Roots, ", ")))
	case 1:
		return found[0]
	}
	die(fmt.Errorf("-node %s: matches several node roots: %s", node, strings.Join(found, ", ")))
	return ""
}

func errorsIsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

// treeDirsOK checks that every existing component of the repository
// directory dir is a plain directory, so a write planned there cannot fail
// halfway through an import.
func treeDirsOK(r *repoView, dir string) error {
	cur := ""
	for _, c := range strings.Split(dir, "/") {
		next := path.Join(cur, c)
		fd, err := walkDirs(r.fd, next, false)
		if err != nil {
			if errorsIsNotExist(err) {
				return nil
			}
			return err
		}
		syscall.Close(fd)
		cur = next
	}
	return nil
}

// ---------- placeholders -> values ----------

// expandText resolves every placeholder in data. Every problem is
// returned, with its line; the result is only valid when there is none.
func expandText(data []byte, file string, names *nameList, vals map[string]ksKey) ([]byte, []string) {
	return expandTextAt(data, file, names, vals, nil)
}

// expandTextAt is expandText that also reports where each placeholder's
// value lands in the result: its line and byte column (1-based).
func expandTextAt(data []byte, file string, names *nameList, vals map[string]ksKey, onPH func(line, col int, name, chain string)) ([]byte, []string) {
	var errs []string
	if !bytes.Contains(data, phPrefix) {
		return data, nil
	}
	if !isTextFile(data) {
		return nil, []string{file + ": placeholder in a binary file"}
	}
	var out bytes.Buffer
	for no, line := range bytes.SplitAfter(data, []byte("\n")) {
		lineStart := out.Len()
		good, bad := parsePlaceholders(line)
		for _, b := range bad {
			errs = append(errs, fmt.Sprintf("%s:%d:%d: malformed placeholder: %s", file, no+1, b.Col+1, b.Why))
		}
		last := 0
		for _, p := range good {
			at := fmt.Sprintf("%s:%d:%d", file, no+1, p.Col+1)
			k := names.ByName[p.Name]
			v, ok := vals[p.Name]
			switch {
			case k == nil:
				errs = append(errs, at+": unknown key "+p.Name)
				continue
			case k.UUID != p.UUID:
				errs = append(errs, at+": uuid of "+p.Name+" does not match .sec/names")
				continue
			case !ok:
				errs = append(errs, at+": no value for "+p.Name+" (segscan key set "+p.Name+")")
				continue
			case v.UUID != p.UUID:
				errs = append(errs, at+": the keystore has another uuid for "+p.Name+" (another project's keystore?)")
				continue
			}
			res, err := applyChain(p.Transforms, []byte(v.Value), true)
			if err != nil {
				errs = append(errs, at+": "+p.Name+": "+err.Error())
				continue
			}
			out.Write(line[last:p.Col])
			if onPH != nil {
				onPH(no+1, out.Len()-lineStart+1, p.Name, strings.Join(p.Transforms, ":"))
			}
			out.Write(res)
			last = p.End
		}
		out.Write(line[last:])
	}
	return out.Bytes(), errs
}

// ---------- the plan: every target resolved before the first write ----------

type expandItem struct {
	entry  *mEntry
	node   string // the path on the node: /etc/nginx/nginx.conf
	target string // where it lands, resolved through declared links
	data   []byte // content (f, s) or link target (l)
}

// resolveDir resolves the declared links among the components of the node
// path p (all of them: p is a directory on the way to a target).
func resolveDir(p string, links map[string]string, depth int) (string, error) {
	if depth > 40 {
		return "", fmt.Errorf("%s: too many levels of declared links", p)
	}
	cur := "/"
	for _, c := range strings.Split(strings.Trim(p, "/"), "/") {
		if c == "" {
			continue
		}
		next := path.Join(cur, c)
		if t, ok := links[next]; ok {
			if !path.IsAbs(t) {
				t = path.Join(cur, t)
			}
			r, err := resolveDir(path.Clean(t), links, depth+1)
			if err != nil {
				return "", err
			}
			next = r
		}
		cur = next
	}
	return cur, nil
}

func planNode(r *repoView, ks *keystore, root string, filter []string) ([]*expandItem, []string) {
	var errs []string
	vals := ks.keys
	files := map[string][]byte{}
	for _, f := range ks.files {
		if f.Version == "" {
			files[f.Name] = f.Data
		}
	}
	var entries []*mEntry
	links := map[string]string{}
	for _, e := range r.man {
		if !strings.HasPrefix(e.Path, root+"/") {
			continue
		}
		entries = append(entries, e)
		if e.Type == "l" {
			t, link, err := r.read(e.Path)
			switch {
			case err != nil:
				errs = append(errs, e.Path+": "+err.Error())
			case !link:
				errs = append(errs, e.Path+": manifest type l, but it is not a symlink")
			default:
				links[strings.TrimPrefix(e.Path, root)] = string(t)
			}
		}
	}
	selected := func(n string) bool {
		if len(filter) == 0 {
			return true
		}
		for _, f := range filter {
			f = "/" + strings.Trim(f, "/")
			if n == f || strings.HasPrefix(n, f+"/") {
				return true
			}
		}
		return false
	}
	var items []*expandItem
	for _, e := range entries {
		n := strings.TrimPrefix(e.Path, root)
		if !selected(n) {
			continue
		}
		dir, err := resolveDir(path.Dir(n), links, 0)
		if err != nil {
			errs = append(errs, e.Path+": "+err.Error())
			continue
		}
		it := &expandItem{entry: e, node: n, target: path.Join(dir, path.Base(n))}
		switch e.Type {
		case "f":
			data, link, err := r.read(e.Path)
			switch {
			case err != nil:
				errs = append(errs, e.Path+": "+err.Error())
				continue
			case link:
				errs = append(errs, e.Path+": manifest type f, but it is a symlink")
				continue
			}
			out, perrs := expandText(data, e.Path, r.names, vals)
			errs = append(errs, perrs...)
			it.data = out
		case "s":
			name := ""
			for _, a := range e.Attrs {
				if v, ok := strings.CutPrefix(a, "secret="); ok {
					name = v
				}
			}
			data, ok := files[name]
			if !ok {
				errs = append(errs, e.Path+": no secret file "+name+" in the keystore (segscan import -secret "+name+")")
				continue
			}
			it.data = data
		case "l":
			it.data = []byte(links[n])
		}
		items = append(items, it)
	}
	// Two entries that land on the same place, or a file that would have to
	// be a directory too: the manifest order must never decide.
	sort.Slice(items, func(i, j int) bool { return items[i].target < items[j].target })
	by := map[string]*expandItem{}
	for _, it := range items {
		if o := by[it.target]; o != nil {
			errs = append(errs, fmt.Sprintf("%s and %s land on the same path %s", o.entry.Path, it.entry.Path, it.target))
			continue
		}
		by[it.target] = it
		for d := path.Dir(it.target); d != "/"; d = path.Dir(d) {
			if o := by[d]; o != nil && o.entry.Type != "d" {
				errs = append(errs, fmt.Sprintf("%s lands below %s, which is type %s", it.entry.Path, o.entry.Path, o.entry.Type))
				break
			}
		}
	}
	return items, errs
}

// ---------- the command ----------

func cmdExpand(args []string) {
	fs := flag.NewFlagSet("expand", flag.ExitOnError)
	dry := fs.Bool("n", false, "list what would change, write nothing")
	node := fs.String("node", "", "the node to expand (a directory under roots)")
	to := fs.String("to", "", "write the files under this directory, outside the repository (mode 0600, directories 0700)")
	install := fs.String("install", "", "install onto this root (not implemented yet)")
	fs.Parse(args)
	if *install != "" {
		die(fmt.Errorf("expand -install is not implemented yet; use -to and your deploy tool"))
	}
	if *to == "" || *node == "" {
		die(fmt.Errorf("usage: segscan expand [-n] -node <node> -to <dir> [path...]"))
	}
	r := openRepo()
	defer syscall.Close(r.fd)
	root := nodeRootFor(r, *node)
	dir, err := filepath.Abs(*to)
	if err != nil {
		die(err)
	}
	if rel, ok := relBelowTop(canonical(r.top), dir); ok {
		die(fmt.Errorf("-to %s is inside the repository (%s)", dir, rel))
	}
	if rel, err := filepath.Rel(canonical(r.top), canonical(dir)); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
		die(fmt.Errorf("-to %s is inside the repository (%s)", dir, rel))
	}
	ks := mustKeystore(r.top, r.cfg, false, false)
	defer ks.close()
	items, errs := planNode(r, ks, root, fs.Args())
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "segscan:", e)
		}
		fmt.Fprintf(os.Stderr, "segscan: %d problem(s); nothing written\n", len(errs))
		os.Exit(1)
	}
	var dfd int
	if !*dry {
		if dfd, err = openDirPinned(dir, true); err != nil {
			die(err)
		}
		defer syscall.Close(dfd)
	} else if dfd, err = openDirPinned(dir, false); err != nil {
		dfd = -1 // nothing there yet: everything would be new
	}
	changed := 0
	for _, it := range items {
		ch, err := stageItem(dfd, it, *dry)
		if err != nil {
			die(fmt.Errorf("%s: %v", it.node, err))
		}
		if ch {
			changed++
			fmt.Println(it.node)
		}
	}
	verb := "written"
	if *dry {
		verb = "would change"
	}
	fmt.Fprintf(os.Stderr, "segscan: %d of %d entries %s under %s\n", changed, len(items), verb, dir)
}

// stageItem writes one entry under the staging directory dfd and says
// whether anything changed. With dry, it only compares (dfd may be -1).
func stageItem(dfd int, it *expandItem, dry bool) (bool, error) {
	rel := strings.TrimPrefix(it.target, "/")
	if dfd < 0 {
		return true, nil
	}
	if it.entry.Type == "d" {
		fd, err := walkDirs(dfd, rel, false)
		if err == nil {
			syscall.Close(fd)
			return false, nil
		}
		if dry {
			return true, nil
		}
		fd, err = walkDirs(dfd, rel, true)
		if err == nil {
			syscall.Close(fd)
		}
		return true, err
	}
	pfd, err := walkDirs(dfd, path.Dir(rel), !dry)
	if err != nil {
		if dry {
			return true, nil
		}
		return false, err
	}
	defer syscall.Close(pfd)
	base := path.Base(rel)
	st, err := lstatAt(pfd, base)
	if err == nil {
		isLink := st.Mode&syscall.S_IFMT == syscall.S_IFLNK
		switch {
		case it.entry.Type == "l" && isLink:
			if t, err := readlinkAt(pfd, base); err == nil && t == string(it.data) {
				return false, nil
			}
		case it.entry.Type != "l" && st.Mode&syscall.S_IFMT == syscall.S_IFREG:
			if old, _, err := readAt(pfd, base); err == nil && bytes.Equal(old, it.data) && st.Mode&0o7777 == 0o600 {
				return false, nil
			}
		case st.Mode&syscall.S_IFMT == syscall.S_IFDIR:
			return false, fmt.Errorf("a directory is in the way")
		}
	}
	if dry {
		return true, nil
	}
	if it.entry.Type == "l" {
		return true, symlinkAt(pfd, string(it.data), base)
	}
	return true, writeAt(pfd, base, it.data, 0o600)
}

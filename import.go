//go:build linux

package main

// segscan import (DESIGN.md 6.3): live files of a node into the tree, every
// known value replaced by its placeholder, checked by a round trip and by
// check 6 before anything is written. All files or none.

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// liveFile is one source path, read through descriptors from /.
type liveFile struct {
	abs   string
	link  bool
	data  []byte // content, or the link target
	mode  uint32
	owner string
	group string
}

func readLive(abs string) (*liveFile, error) {
	if !path.IsAbs(abs) || path.Clean(abs) != abs || abs == "/" {
		return nil, fmt.Errorf("%s: give a clean absolute path of a file", abs)
	}
	dfd, err := openDirPinned(path.Dir(abs), false)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dfd)
	base := path.Base(abs)
	st, err := lstatAt(dfd, base)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", abs, err)
	}
	lf := &liveFile{abs: abs}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFLNK:
		t, err := readlinkAt(dfd, base)
		if err != nil {
			return nil, err
		}
		lf.link, lf.data, lf.mode = true, []byte(t), 0o777
	case syscall.S_IFREG:
		data, fst, err := readAt(dfd, base)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", abs, err)
		}
		st = fst // the attributes of the descriptor that was read
		lf.data, lf.mode = data, st.Mode&0o7777
	case syscall.S_IFDIR:
		return nil, fmt.Errorf("%s is a directory: give its files (find %s -type f)", abs, abs)
	default:
		return nil, fmt.Errorf("%s: not a regular file or symlink", abs)
	}
	lf.owner = strconv.Itoa(int(st.Uid))
	if u, err := user.LookupId(lf.owner); err == nil {
		lf.owner = u.Username
	}
	lf.group = strconv.Itoa(int(st.Gid))
	if g, err := user.LookupGroupId(lf.group); err == nil {
		lf.group = g.Name
	}
	return lf, nil
}

// ---------- replacement ----------

type keyForms struct {
	key    *keyName
	value  string
	weak   bool                // the value itself is weak: replacements need -accept
	chains map[string][]string // form -> every chain that gives it
	weakF  map[string]bool     // form -> weak
}

func buildKeyForms(names *nameList, ks *keystore, chains [][]string) []*keyForms {
	var out []*keyForms
	for _, k := range names.Keys {
		v, ok := ks.keys[k.Name]
		if !ok || v.UUID != k.UUID {
			continue // key check reports these; check 6 still finds the value
		}
		kf := &keyForms{key: k, value: v.Value, weak: weakForm([]byte(v.Value)), chains: map[string][]string{}, weakF: map[string]bool{}}
		// A chain with a step that can never change its input (an escape
		// of hex, of base58, dq of a keystore value) gives the same text as
		// the chain without it, for every value the key can ever have: it
		// is no candidate of its own unless nothing else gives that form.
		for _, pass := range []bool{false, true} {
			for _, c := range chains {
				if redundantChain(c, k.Base58) != pass {
					continue
				}
				d, err := applyChain(c, []byte(v.Value), true)
				if err != nil || len(d) == 0 {
					continue
				}
				if pass && kf.chains[string(d)] != nil {
					continue
				}
				kf.chains[string(d)] = append(kf.chains[string(d)], strings.Join(c, ":"))
				kf.weakF[string(d)] = weakForm(d)
			}
		}
		out = append(out, kf)
	}
	return out
}

// redundantChain: some step of c leaves every possible input unchanged.
// The input of the first step is a keystore value (4.3: no quotes,
// backslash or control bytes), or base58 for a base58 key.
func redundantChain(c []string, base58 bool) bool {
	class := "value"
	if base58 {
		class = "safe"
	}
	for _, t := range c {
		if escaping[t] {
			switch {
			case class == "safe", // hex, base58, base64url: nothing to escape
				t == "dq" || t == "sq" || t == "nginxq": // no quote, backslash, control byte or $ to escape that can stay
				return true
			case t == "xml" && (class == "b64" || class == "urlenc"):
				return true
			}
		}
		switch t {
		case "sha256", "dsha1", "b64url":
			class = "safe"
		case "b64", "b64nl":
			class = "b64"
		case "urlenc":
			class = "urlenc"
		}
	}
	return false
}

type occ struct {
	start, end int
	kf         *keyForms
	chains     []string
}

func isTokenByte(b byte) bool { return isAlnum(b) || b == '_' || b == '-' }

type importOpts struct {
	accept map[string]bool
	forms  map[string]string // "<file>:<line>" -> chain ("" for the bare value)
}

type replaced struct {
	out      []byte
	perKey   map[string]int
	problems []string
}

// replaceValues rewrites data (the live file going to repository path rp).
// existing is the current repository file, used to keep the transform of a
// placeholder that is already there.
func replaceValues(data []byte, abs, rp string, kfs []*keyForms, existing []byte, r *repoView, ks *keystore, o importOpts) replaced {
	res := replaced{perKey: map[string]int{}}
	prob := func(format string, a ...any) { res.problems = append(res.problems, fmt.Sprintf(format, a...)) }
	lineCol := func(off int) (int, int) {
		return bytes.Count(data[:off], []byte("\n")) + 1, off - bytes.LastIndexByte(data[:off], '\n')
	}
	var occs []occ
	for _, kf := range kfs {
		inScope := true
		if len(kf.key.Scope) > 0 {
			_, inScope = matchAny(kf.key.Scope, rp)
		}
		for f, chains := range kf.chains {
			weak := kf.weakF[f]
			for off := 0; ; {
				i := bytes.Index(data[off:], []byte(f))
				if i < 0 {
					break
				}
				s, e := off+i, off+i+len(f)
				off = s + 1
				if weak {
					// A weak form counts only as a whole token inside the scope.
					if !inScope || s > 0 && isTokenByte(data[s-1]) || e < len(data) && isTokenByte(data[e]) {
						continue
					}
				}
				if !inScope {
					l, c := lineCol(s)
					prob("%s:%d:%d: value of %s outside its scope (%s)", abs, l, c, kf.key.Name, strings.Join(kf.key.Scope, ","))
					continue
				}
				occs = append(occs, occ{s, e, kf, chains})
			}
		}
	}
	// Longest first; an overlap of two keys cannot be decided.
	sort.Slice(occs, func(i, j int) bool {
		if li, lj := occs[i].end-occs[i].start, occs[j].end-occs[j].start; li != lj {
			return li > lj
		}
		return occs[i].start < occs[j].start
	})
	var sel []occ
next:
	for _, x := range occs {
		for _, y := range sel {
			if x.start < y.end && y.start < x.end {
				if x.kf != y.kf {
					l, c := lineCol(x.start)
					prob("%s:%d:%d: forms of %s and %s overlap; write the placeholder by hand", abs, l, c, y.kf.key.Name, x.kf.key.Name)
				}
				continue next
			}
		}
		sel = append(sel, x)
	}
	sort.Slice(sel, func(i, j int) bool { return sel[i].start < sel[j].start })

	// Placeholders the repository already has, by where their value lands.
	have := map[[2]int]string{} // line, col -> name + "\x00" + chain
	haveKey := map[string]bool{}
	if existing != nil {
		expandTextAt(existing, rp, r.names, ks.keys, func(line, col int, name, chain string) {
			have[[2]int{line, col}] = name + "\x00" + chain
			haveKey[name] = true
		})
	}
	var out bytes.Buffer
	last := 0
	weakPlaces := map[string][]string{}
	for _, x := range sel {
		l, c := lineCol(x.start)
		chain, ok := "", false
		// Of the chains that give this text, only the shortest are
		// candidates: nobody writes urlenc:urlenc where urlenc fits.
		// The bare value counts as one step (chainLen).
		x.chains = shortest(x.chains)
		if len(x.chains) == 1 {
			chain, ok = x.chains[0], true
		}
		if !ok {
			if f, given := o.forms[abs+":"+strconv.Itoa(l)]; given && contains(x.chains, f) {
				chain, ok = f, true
			} else if f, given := o.forms[rp+":"+strconv.Itoa(l)]; given && contains(x.chains, f) {
				chain, ok = f, true
			}
		}
		if !ok {
			if h, there := have[[2]int{l, c}]; there {
				name, ch, _ := strings.Cut(h, "\x00")
				if name == x.kf.key.Name && contains(x.chains, ch) {
					chain, ok = ch, true
				}
			}
		}
		if !ok && x.kf.key.Base58 && contains(x.chains, "") {
			chain, ok = "", true
		}
		if !ok {
			var cs []string
			for _, ch := range x.chains {
				if ch == "" {
					ch = "bare"
				}
				cs = append(cs, ch)
			}
			prob("%s:%d:%d: %s could be any of %s; write the placeholder by hand or give -form %s:%d=<transform>",
				abs, l, c, x.kf.key.Name, strings.Join(cs, ", "), abs, l)
			continue
		}
		if x.kf.weak && !o.accept[x.kf.key.Name] {
			weakPlaces[x.kf.key.Name] = append(weakPlaces[x.kf.key.Name], fmt.Sprintf("%s:%d:%d", abs, l, c))
		}
		var ts []string
		if chain != "" {
			ts = strings.Split(chain, ":")
		}
		out.Write(data[last:x.start])
		out.WriteString(placeholderText(x.kf.key.Name, x.kf.key.UUID, ts...))
		last = x.end
		res.perKey[x.kf.key.Name]++
	}
	out.Write(data[last:])
	for _, name := range sortedKeys(weakPlaces) {
		prob("%s has a short or common value, which matches ordinary text too: check these places, then give -accept %s (or narrow its scope, or write the placeholders by hand): %s",
			name, name, strings.Join(weakPlaces[name], " "))
	}
	for name := range res.perKey {
		if existing != nil && !haveKey[name] {
			fmt.Fprintf(os.Stderr, "segscan: warning: %s: %s is new in this file\n", rp, name)
		}
	}
	res.out = out.Bytes()
	return res
}

func shortest(chains []string) []string {
	n := -1
	for _, c := range chains {
		if l := chainLen(c); n < 0 || l < n {
			n = l
		}
	}
	var out []string
	for _, c := range chains {
		if chainLen(c) == n {
			out = append(out, c)
		}
	}
	return out
}

// chainLen counts the bare value as one step: bare, urlenc and xml stay
// candidates together, since a rotation can give them different texts.
func chainLen(c string) int {
	return strings.Count(c, ":") + 1
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// ---------- the command ----------

type importItem struct {
	live   *liveFile
	rp     string // repository path
	out    []byte // what goes into the tree (f), or the link target (l)
	secret string
	entry  *mEntry
	note   string
}

func cmdImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	dry := fs.Bool("n", false, "print what would change, write nothing")
	node := fs.String("node", "", "the node the files come from (a directory under roots)")
	secret := fs.String("secret", "", "store the one file given in the keystore as this secret file (type s), not in the tree")
	verbose := fs.Bool("v", false, "print the statistical scanner's findings in the result")
	var accept, forms multiFlag
	fs.Var(&accept, "accept", "replace this key although its value is short or common (repeatable, or comma-separated)")
	fs.Var(&forms, "form", "FILE:LINE=TRANSFORM: the transform for an occurrence that fits several (bare for none; repeatable)")
	fs.Parse(args)
	paths := fs.Args()
	if *node == "" || len(paths) == 0 {
		die(fmt.Errorf("usage: segscan import [-n] -node <node> [-secret NAME] [-accept NAME] [-form FILE:LINE=T] /abs/path..."))
	}
	if *secret != "" && (len(paths) != 1 || !validName(*secret)) {
		die(fmt.Errorf("import -secret: give a valid name and exactly one path"))
	}
	o := importOpts{accept: map[string]bool{}, forms: map[string]string{}}
	for _, a := range accept {
		for _, n := range splitList(a) {
			o.accept[n] = true
		}
	}
	for _, f := range forms {
		left, chain, ok := strings.Cut(f, "=")
		i := strings.LastIndexByte(left, ':')
		if !ok || i <= 0 {
			die(fmt.Errorf("-form %q: expected FILE:LINE=TRANSFORM", f))
		}
		if _, err := strconv.Atoi(left[i+1:]); err != nil {
			die(fmt.Errorf("-form %q: bad line number", f))
		}
		if chain == "bare" {
			chain = ""
		}
		for _, t := range strings.Split(chain, ":") {
			if chain != "" && !knownTransforms[t] {
				die(fmt.Errorf("-form %q: unknown transform %s", f, t))
			}
		}
		o.forms[left] = chain
	}

	r := openRepo()
	defer syscall.Close(r.fd)
	root := nodeRootMaybe(r, *node, true)
	write := *secret != "" && !*dry
	ks := mustKeystore(r.top, r.cfg, write, write)
	defer ks.close()

	// The chains in use anywhere under the node roots, for forms of three
	// or four transforms.
	extra := map[string]bool{}
	man := map[string]*mEntry{}
	for _, e := range r.man {
		man[e.Path] = e
		if e.Type == "f" {
			if data, link, err := r.read(e.Path); err == nil && !link {
				chainsUsed(data, extra)
			}
		}
	}
	chains := searchChains(extra)
	kfs := buildKeyForms(r.names, ks, chains)
	matcher := buildMatcher(ks, extra)
	allow := &allowList{fp: map[string]bool{}}
	if data, link, err := r.read(secDir + "/allow"); err == nil && !link {
		allow.add(data)
	}

	var items []*importItem
	var problems []string
	for _, p := range paths {
		lf, err := readLive(p)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		rp := root + lf.abs
		it := &importItem{live: lf, rp: rp, secret: *secret}
		if err := treeDirsOK(r, path.Dir(rp)); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		old := man[rp]
		it.entry = &mEntry{Path: rp, Mode: fmt.Sprintf("%04o", lf.mode), Owner: lf.owner, Group: lf.group}
		if old != nil {
			for _, a := range old.Attrs {
				if !strings.HasPrefix(a, "secret=") {
					it.entry.Attrs = append(it.entry.Attrs, a)
				}
			}
		}
		if fd, err := walkDirs(r.fd, rp, false); err == nil {
			syscall.Close(fd)
			problems = append(problems, rp+" is a directory in the tree")
			continue
		}
		existing, exLink, exErr := r.read(rp)
		switch {
		case *secret != "":
			if lf.link || len(lf.data) == 0 {
				problems = append(problems, p+": a secret file must be a non-empty regular file")
				continue
			}
			if exErr == nil {
				problems = append(problems, rp+" is in the tree; a secret file must not be (git rm it first)")
				continue
			}
			it.entry.Type = "s"
			it.entry.Attrs = append(it.entry.Attrs, "secret="+*secret)
			it.note = "secret file " + *secret + " in the keystore"
		case lf.link:
			it.entry.Type, it.out = "l", lf.data
			it.note = "symlink -> " + string(lf.data)
			found, _ := matcher.knownFindings(rp, lf.data)
			for _, f := range found {
				problems = append(problems, fmt.Sprintf("%s: the symlink target holds a %s", p, f.Msg))
			}
		default:
			it.entry.Type = "f"
			if exErr != nil || exLink {
				existing = nil
			}
			if !isTextFile(lf.data) {
				it.out = lf.data
				found, why := matcher.knownFindings(rp, lf.data)
				for _, f := range found {
					problems = append(problems, fmt.Sprintf("%s: binary file holds a %s; keep it in the keystore with -secret", p, f.Msg))
				}
				if why != "" && !allowedBinary(allow, rp) {
					problems = append(problems, fmt.Sprintf("%s: binary file cannot be fully scanned (%s); add path:%s to .sec/allow first, or keep it in the keystore with -secret", p, why, rp))
				}
				it.note = "binary, copied as is"
				break
			}
			rep := replaceValues(lf.data, p, rp, kfs, existing, r, ks, o)
			problems = append(problems, rep.problems...)
			if len(rep.problems) > 0 {
				continue
			}
			back, errs := expandText(rep.out, rp, r.names, ks.keys)
			if len(errs) > 0 || !bytes.Equal(back, lf.data) {
				problems = append(problems, p+": the result does not expand back to the live file (round trip); nothing written")
				continue
			}
			found, _ := matcher.knownFindings(rp, rep.out)
			for _, f := range found {
				problems = append(problems, fmt.Sprintf("%s:%d:%d: %s is left after replacement", p, f.Line, f.Col, f.Msg))
			}
			it.out = rep.out
			var parts []string
			for _, n := range sortedKeys(rep.perKey) {
				parts = append(parts, fmt.Sprintf("%s x%d", n, rep.perKey[n]))
			}
			it.note = "no placeholders"
			if len(parts) > 0 {
				it.note = strings.Join(parts, ", ")
			}
			if n := statFindings(r, rp, rep.out, *verbose); n > 0 {
				it.note += fmt.Sprintf("; %d statistical finding(s) (-v)", n)
			}
		}
		items = append(items, it)
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "segscan:", p)
		}
		fmt.Fprintf(os.Stderr, "segscan: %d problem(s); nothing written\n", len(problems))
		os.Exit(1)
	}
	for _, it := range items {
		verb := "import"
		if *dry {
			verb = "would import"
		}
		fmt.Printf("%s %s -> %s (%s %s %s:%s)\t%s\n", verb, it.live.abs, it.rp, it.entry.Type, it.entry.Mode, it.entry.Owner, it.entry.Group, it.note)
	}
	if *dry {
		return
	}
	for _, it := range items {
		var err error
		switch {
		case it.secret != "":
			err = ks.setFile(it.secret, it.live.data)
		default:
			err = writeTree(r, it)
		}
		if err != nil {
			die(fmt.Errorf("%s: %v", it.rp, err))
		}
		man[it.rp] = it.entry
	}
	var es []*mEntry
	for _, e := range man {
		es = append(es, e)
	}
	mfd, err := walkDirs(r.fd, secDir, false)
	if err != nil {
		die(err)
	}
	defer syscall.Close(mfd)
	if err := writeAt(mfd, "manifest", formatManifest(es), 0o644); err != nil {
		die(err)
	}
}

// writeTree writes one imported file into the tree, below the node root,
// through directory descriptors only.
func writeTree(r *repoView, it *importItem) error {
	pfd, err := walkDirs(r.fd, path.Dir(it.rp), true)
	if err != nil {
		return err
	}
	defer syscall.Close(pfd)
	base := path.Base(it.rp)
	if st, err := lstatAt(pfd, base); err == nil && st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		return fmt.Errorf("a directory is in the way")
	}
	if it.entry.Type == "l" {
		return symlinkAt(pfd, string(it.out), base)
	}
	mode := uint32(0o644)
	if it.live.mode&0o111 != 0 {
		mode = 0o755
	}
	return writeAt(pfd, base, it.out, mode)
}

// statFindings runs the statistical scanner on the result, with the
// repository model when there is one.
func statFindings(r *repoView, rp string, data []byte, verbose bool) int {
	var m *Model
	if raw, link, err := r.read(secDir + "/segscan.model"); err == nil && !link {
		m, _ = decodeModel(bytes.NewReader(raw), secDir+"/segscan.model")
	}
	m = combine(m, baseModel)
	if m == nil {
		return 0
	}
	o := defaultOpts
	o.Skip = r.cfg.SkipUUIDs
	sc := NewScanner(m, o)
	n := 0
	for no, line := range bytes.Split(data, []byte("\n")) {
		sc.Line(line, func(col int, text []byte, bits, _ float64) {
			n++
			if verbose {
				fmt.Fprintf(os.Stderr, "segscan: %s:%d:%d: %.1f bits/char, %d chars\n", rp, no+1, col+1, bits, len(text))
			}
		})
	}
	return n
}

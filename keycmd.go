//go:build linux

package main

// key set, key check, key retire: the key commands that need the keystore
// (DESIGN.md 6.2).

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func isBase58(v string) bool {
	for i := 0; i < len(v); i++ {
		if strings.IndexByte(base58Alphabet, v[i]) < 0 {
			return false
		}
	}
	return v != ""
}

func genBase58(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(base58Alphabet)))
	for i := range b {
		x, err := rand.Int(rand.Reader, max)
		if err != nil {
			die(err)
		}
		b[i] = base58Alphabet[x.Int64()]
	}
	return string(b)
}

// mustKeystore opens the keystore of the repository, or exits 2 naming the
// path it tried.
func mustKeystore(top string, cfg *secConfig, exclusive, create bool) *keystore {
	ks, err := openKeystore(cfg, top, exclusive, create)
	if err == errNoKeystore {
		fmt.Fprintf(os.Stderr, "segscan: no keystore at %s (this command needs it)\n", cfg.keystoreDir())
		os.Exit(2)
	}
	if err != nil {
		die(err)
	}
	return ks
}

// readSecret reads one line from stdin, without echo when it is a terminal.
func readSecret(prompt string) string {
	fd := int(os.Stdin.Fd())
	var old syscall.Termios
	tty := ioctl(fd, syscall.TCGETS, &old) == nil
	if tty {
		fmt.Fprint(os.Stderr, prompt)
		noEcho := old
		noEcho.Lflag &^= syscall.ECHO
		ioctl(fd, syscall.TCSETS, &noEcho)
		defer func() {
			ioctl(fd, syscall.TCSETS, &old)
			fmt.Fprintln(os.Stderr)
		}()
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		die(err)
	}
	return strings.TrimSuffix(line, "\n")
}

func ioctl(fd int, req uintptr, t *syscall.Termios) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(t))); e != 0 {
		return e
	}
	return nil
}

func keySet(args []string) {
	fs := flag.NewFlagSet("key set", flag.ExitOnError)
	gen := fs.Int("gen", 0, "generate N characters of base58 from crypto/rand instead of reading stdin")
	name := oneArg(fs, args)
	top, cfg := mustSec()
	k := loadNamesOrDie(top).ByName[name]
	if k == nil {
		die(fmt.Errorf("no key %s in %s/names (segscan key add %s)", name, secDir, name))
	}
	var v string
	switch {
	case *gen < 0:
		die(fmt.Errorf("key set: -gen needs N >= 1"))
	case *gen > 0:
		v = genBase58(*gen)
	default:
		v = readSecret("value of " + name + ": ")
	}
	if !validValue(v) {
		die(fmt.Errorf("key set %s: the value must be non-empty printable ASCII without spaces, quotes, backslash or #", name))
	}
	if k.Base58 && !isBase58(v) {
		die(fmt.Errorf("key set %s: the key is base58 (.sec/names), and the value is not", name))
	}
	ks := mustKeystore(top, cfg, true, true)
	defer ks.close()
	old, had := ks.keys[name]
	if had && old.Value == v && old.UUID == k.UUID {
		fmt.Fprintf(os.Stderr, "segscan: %s unchanged\n", name)
		return
	}
	for n, other := range ks.keys {
		if n != name && other.Value == v {
			die(fmt.Errorf("key set %s: key %s has the same value; import could not tell them apart", name, n))
		}
	}
	retired, err := ks.set(name, k.UUID, v)
	if err != nil {
		die(err)
	}
	if retired {
		fmt.Fprintf(os.Stderr, "segscan: %s set; the old value is in retired and is still searched by check\n", name)
	} else {
		fmt.Fprintf(os.Stderr, "segscan: %s set\n", name)
	}
}

// secretNames returns the secret= names of the type s entries in the
// working tree's manifest.
func secretNames(top string) map[string]bool {
	data, err := os.ReadFile(secPath(top, "manifest"))
	if err != nil && !os.IsNotExist(err) {
		die(err)
	}
	es, probs := parseManifest(data)
	if len(probs) > 0 {
		die(fmt.Errorf("%s/manifest:%d: %s", secDir, probs[0].Line, probs[0].Msg))
	}
	out := map[string]bool{}
	for _, e := range es {
		if e.Type != "s" {
			continue
		}
		for _, a := range e.Attrs {
			if v, ok := strings.CutPrefix(a, "secret="); ok {
				out[v] = true
			}
		}
	}
	return out
}

func keyCheck(args []string) {
	fs := flag.NewFlagSet("key check", flag.ExitOnError)
	weak := fs.Bool("weak", false, "also list the keys and secret files that have weak forms, which check does not search")
	noHeader := fs.Bool("no-header", false, "omit the TSV header line")
	fs.Parse(args)
	if fs.NArg() > 0 {
		die(fmt.Errorf("key check: unexpected %q", fs.Arg(0)))
	}
	top, cfg := mustSec()
	names := loadNamesOrDie(top)
	secrets := secretNames(top)
	ks := mustKeystore(top, cfg, false, false)
	defer ks.close()
	type row struct{ kind, name, msg string }
	var rows []row
	problems := 0
	add := func(kind, name, msg string, problem bool) {
		rows = append(rows, row{kind, name, msg})
		if problem {
			problems++
		}
	}
	for _, k := range names.Keys {
		v, ok := ks.keys[k.Name]
		switch {
		case !ok:
			add("key", k.Name, "no value (segscan key set "+k.Name+")", true)
		case v.UUID != k.UUID:
			add("key", k.Name, "uuid differs from .sec/names: the keystore belongs to another project, or the key was added again", true)
		case k.Base58 && !isBase58(v.Value):
			add("key", k.Name, "the key is base58 (.sec/names), and the value is not", true)
		}
	}
	for _, n := range sortedKeys(ks.keys) {
		if names.ByName[n] == nil {
			add("key", n, "not in .sec/names (segscan key retire "+n+")", true)
		}
	}
	current := map[string]*ksFile{}
	for i, f := range ks.files {
		if f.Version == "" {
			current[f.Name] = &ks.files[i]
		}
	}
	for _, n := range sortedKeys(secrets) {
		if current[n] == nil {
			add("secret", n, "no file in the keystore (segscan import -secret "+n+")", true)
		}
	}
	for _, n := range sortedKeys(current) {
		if !secrets[n] {
			add("secret", n, "no type s entry names it (segscan key retire -secret "+n+"); check still searches it", true)
		}
	}
	if *weak {
		chains := searchChains(nil)
		for _, n := range sortedKeys(ks.keys) {
			if w := weakChains([]byte(ks.keys[n].Value), chains); w != "" {
				add("key", n, "weak forms, not searched by check: "+w, false)
			}
		}
		for _, n := range sortedKeys(current) {
			whole, _, _ := secretPatterns(current[n].Data)
			strong := false
			for _, f := range formsOf(whole, chains) {
				strong = strong || !f.Weak
			}
			if !strong {
				add("secret", n, "every form of its content is weak; check cannot find it", false)
			}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].kind != rows[j].kind {
			return rows[i].kind < rows[j].kind
		}
		return rows[i].name < rows[j].name
	})
	if len(rows) > 0 && !*noHeader {
		fmt.Println("kind\tname\tproblem")
	}
	for _, r := range rows {
		fmt.Printf("%s\t%s\t%s\n", r.kind, r.name, r.msg)
	}
	if problems > 0 {
		os.Exit(1)
	}
}

// weakChains lists the chains whose form of v is weak ("bare" for none).
func weakChains(v []byte, chains [][]string) string {
	var w []string
	for _, f := range formsOf(v, chains) {
		if f.Weak {
			c := f.Chain
			if c == "" {
				c = "bare"
			}
			w = append(w, c)
		}
	}
	return strings.Join(w, ",")
}

// keyRetire moves the current value of a key that is no longer in names,
// or a secret file no type s entry names, to retired (4.3).
func keyRetire(args []string) {
	fs := flag.NewFlagSet("key retire", flag.ExitOnError)
	secret := fs.Bool("secret", false, "retire the secret file of this name instead of a key")
	name := oneArg(fs, args)
	top, cfg := mustSec()
	if *secret {
		if secretNames(top)[name] {
			die(fmt.Errorf("key retire -secret %s: a type s entry in .sec/manifest still names it", name))
		}
	} else if loadNamesOrDie(top).ByName[name] != nil {
		die(fmt.Errorf("key retire %s: the key is still in .sec/names (segscan key rm %s first)", name, name))
	}
	ks := mustKeystore(top, cfg, true, false)
	defer ks.close()
	var err error
	if *secret {
		err = ks.retireFile(name)
	} else {
		err = ks.retire(name)
	}
	if err != nil {
		die(err)
	}
	fmt.Fprintf(os.Stderr, "segscan: %s retired; check still searches it\n", name)
}

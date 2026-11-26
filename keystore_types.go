package main

// Keystore types shared by every platform; reading and writing the keystore
// is Linux only (keystore.go, fsx_linux.go).

import (
	"errors"
	"strings"
)

var errNoKeystore = errors.New("no keystore")

// badKeystorePath: the configured path is refused before anything is opened
// (inside the repository, . or .. components); check reports it as a config
// finding.
type badKeystorePath struct{ error }

type ksKey struct {
	Name, UUID, Value string
}

type ksRetired struct {
	Name, UUID, Rotation, Time, Value string
}

type ksFile struct {
	Name    string // secret name
	Version string // "" for the current file, else the retired-files entry
	Data    []byte
}

type keystore struct {
	path    string
	fd      int
	keys    map[string]ksKey
	retired []ksRetired
	files   []ksFile // current and retired secret files
}

// validValue: printable ASCII without quotes, backslash and '#' (4.3).
func validValue(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b < 0x21 || b > 0x7e || strings.IndexByte("\"'`\\#", b) >= 0 {
			return false
		}
	}
	return true
}

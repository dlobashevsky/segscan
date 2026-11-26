//go:build !linux

package main

// The keystore and the commands that need it are Linux only: they rely on
// openat, flock and descriptor-relative renames to stay safe under sudo.
// Elsewhere check runs without check 6, as on a machine without a keystore.

import (
	"errors"
	"fmt"
)

var errLinuxOnly = errors.New("keystore support needs Linux")

func openKeystore(cfg *secConfig, top string, exclusive, create bool) (*keystore, error) {
	return nil, badKeystorePath{errLinuxOnly}
}

func (ks *keystore) close() {}

func linuxOnly(what string) { die(fmt.Errorf("%s: %v", what, errLinuxOnly)) }

func keySet([]string)    { linuxOnly("key set") }
func keyCheck([]string)  { linuxOnly("key check") }
func keyRetire([]string) { linuxOnly("key retire") }
func cmdExpand([]string) { linuxOnly("expand") }
func cmdImport([]string) { linuxOnly("import") }

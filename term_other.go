//go:build !linux

package main

import (
	"errors"
	"os"
)

// The TUI is Linux only for now, like the keystore.

type termState struct{}

var errNoTerm = errors.New("segscan tui needs Linux")

func makeRaw(int) (*termState, error)   { return nil, errNoTerm }
func restoreTerm(int, *termState) error { return nil }
func termSize(int) (int, int, error)    { return 0, 0, errNoTerm }
func isTerminal(int) bool               { return false }
func winchSignal() os.Signal            { return nil }

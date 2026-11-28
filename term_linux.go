//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// The TUI's terminal: raw mode and size, through ioctl on the tty.

type termState struct{ t syscall.Termios }

func ttyIoctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// makeRaw puts the terminal into raw mode: no echo, no line editing, no
// signals from ^C (the TUI asks before quitting). It returns the old state.
func makeRaw(fd int) (*termState, error) {
	var old termState
	if err := ttyIoctl(fd, syscall.TCGETS, unsafe.Pointer(&old.t)); err != nil {
		return nil, err
	}
	t := old.t
	t.Iflag &^= syscall.BRKINT | syscall.ICRNL | syscall.INPCK | syscall.ISTRIP | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Cflag |= syscall.CS8
	t.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	// A read returns after 0.1 s without input: the reader can stop for
	// the editor, and tell a lone ESC from the start of a sequence.
	t.Cc[syscall.VMIN] = 0
	t.Cc[syscall.VTIME] = 1
	if err := ttyIoctl(fd, syscall.TCSETS, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	return &old, nil
}

func restoreTerm(fd int, s *termState) error {
	return ttyIoctl(fd, syscall.TCSETS, unsafe.Pointer(&s.t))
}

func termSize(fd int) (w, h int, err error) {
	var ws struct{ Row, Col, X, Y uint16 }
	if err := ttyIoctl(fd, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return 0, 0, err
	}
	return int(ws.Col), int(ws.Row), nil
}

func isTerminal(fd int) bool {
	var t syscall.Termios
	return ttyIoctl(fd, syscall.TCGETS, unsafe.Pointer(&t)) == nil
}

func winchSignal() os.Signal { return syscall.SIGWINCH }

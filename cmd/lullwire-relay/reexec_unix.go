// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"os"
	"strings"
	"syscall"
)

// reexec replaces this process with a fresh copy of the relay program, same
// arguments and environment. The process id stays the same, so systemd, cron
// scripts and pid files keep tracking it; a binary replaced on disk (an update)
// is what starts.
func reexec() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(strings.TrimSuffix(exe, " (deleted)"), os.Args, os.Environ())
}

const canReexec = true

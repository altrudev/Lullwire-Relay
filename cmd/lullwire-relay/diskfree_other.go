// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !(linux || android || darwin || freebsd || openbsd || netbsd)

package main

// diskFree is not measured on this platform; the free-space floor is skipped.
func diskFree(string) (uint64, bool) { return 0, false }

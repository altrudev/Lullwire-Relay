// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

import "errors"

func reexec() error { return errors.New("restarting itself is not supported on this system") }

const canReexec = false

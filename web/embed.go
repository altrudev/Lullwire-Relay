// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web embeds the Lullwire Relay app so the Go relay is a single file.
// Only the files listed here are served; relay.php and server config are not.
package web

import "embed"

//go:embed index.html style.css app.js call.js worklet.js sw.js config.js manifest.json icon.svg icon-192.png icon-512.png icon-maskable.png apple-touch-icon.png vendor/*.js vendor/*.txt
var Files embed.FS

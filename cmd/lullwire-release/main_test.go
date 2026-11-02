// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	dir, key, other := t.TempDir(), filepath.Join(t.TempDir(), "k.pem"), filepath.Join(t.TempDir(), "o.pem")
	files := map[string]string{"sw.js": "const RELEASE_KEY = '';\n", "app.js": "app", "vendor/q.js": "q",
		"relay.php": "<?php", ".htaccess": "x", "data/box/1.m": "mail", "embed.go": "package web"}
	for n, c := range files {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(dir, n)), 0o755)
		_ = os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644)
	}
	if err := keygen(key, dir); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Fatal("key file readable by others")
	}
	if err := sign(key, dir, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	m, err := verify(dir)
	if err != nil || m.Version != "1.2.3" || len(m.Files) != 2 || m.Files["vendor/q.js"] == "" {
		t.Fatalf("%v %+v", err, m)
	}
	// Server-side files, data and the verifier itself are not part of the release.
	for _, n := range []string{"sw.js", "relay.php", ".htaccess", "data/box/1.m", "embed.go"} {
		if _, ok := m.Files[n]; ok {
			t.Errorf("%s should not be listed", n)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "app.js"), []byte("changed"), 0o644)
	if _, err := verify(dir); err == nil || !strings.Contains(err.Error(), "app.js") {
		t.Fatal("changed file not detected:", err)
	}
	_ = os.WriteFile(filepath.Join(dir, "new.js"), []byte("x"), 0o644)
	_ = sign(key, dir, "1.2.4")
	_ = os.WriteFile(filepath.Join(dir, "extra.js"), []byte("x"), 0o644)
	if _, err := verify(dir); err == nil || !strings.Contains(err.Error(), "extra.js") {
		t.Fatal("unsigned extra file not detected:", err)
	}
	// Another key can't sign for this app (sw.js pins ours).
	k2dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(k2dir, "sw.js"), []byte("const RELEASE_KEY = '';\n"), 0o644)
	_ = keygen(other, k2dir)
	if err := sign(other, dir, "9.9.9"); err == nil {
		t.Fatal("signed with a key sw.js doesn't pin")
	}
	// keygen never replaces an existing key.
	before, _ := os.ReadFile(key)
	_ = keygen(key, dir)
	if after, _ := os.ReadFile(key); string(after) != string(before) {
		t.Fatal("keygen replaced the key")
	}
}

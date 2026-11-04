// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPHPBundle(t *testing.T) {
	dir, key, out := t.TempDir(), filepath.Join(t.TempDir(), "k.pem"), t.TempDir()
	png := []byte{0x89, 'P', 'N', 'G', 0, '\n', '\r', 0xff} // binary, with a newline inside
	files := map[string][]byte{"sw.js": []byte("const RELEASE_KEY = '';\n"), "index.html": []byte("<p>app</p>"),
		"vendor/q.js": []byte("q"), "icon.png": png, ".htaccess": []byte("x"), "embed.go": []byte("package web"),
		"relay.php": []byte("<?php\n// relay\necho 'relay';\n"), "data/box/1.m": []byte("mail")}
	for n, c := range files {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(dir, n)), 0o755)
		_ = os.WriteFile(filepath.Join(dir, n), c, 0o644)
	}
	if _, err := phpBundle(dir, out); err == nil {
		t.Fatal("bundled an app without a signed release.json")
	}
	_ = keygen(key, dir)
	if err := sign(key, dir, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	path, err := phpBundle(dir, out)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "lullwire-relay.php" {
		t.Fatal("the name must not change between versions (it is part of every invite):", path)
	}
	b, _ := os.ReadFile(path)
	head, data, ok := bytes.Cut(b, []byte("__halt_compiler();"))
	if !ok || !bytes.HasPrefix(head, []byte("<?php")) || !bytes.Contains(head, []byte("Lullwire Relay 1.2.3")) ||
		!bytes.Contains(head, []byte("echo 'relay';")) || bytes.Count(head, []byte("<?php")) != 1 {
		t.Fatal("router + relay.php code not laid out as expected")
	}
	idx, rest, _ := bytes.Cut(data, []byte("\n"))
	var index map[string][3]any
	if err := json.Unmarshal(idx, &index); err != nil {
		t.Fatal(err)
	}
	// Exactly the signed app files plus release.json and sw.js, byte for byte.
	want := []string{"index.html", "vendor/q.js", "icon.png", "release.json", "sw.js"}
	if len(index) != len(want) {
		t.Fatalf("bundled %v", index)
	}
	for _, n := range want {
		e, ok := index[n]
		orig, _ := os.ReadFile(filepath.Join(dir, n))
		if !ok || !bytes.Equal(rest[int(e[0].(float64)):int(e[0].(float64))+int(e[1].(float64))], orig) {
			t.Errorf("%s missing or changed", n)
		}
	}
	for _, n := range []string{"relay.php", ".htaccess", "embed.go", "data/box/1.m"} {
		if _, ok := index[n]; ok {
			t.Errorf("%s must not be served", n)
		}
	}
	if php, err := exec.LookPath("php"); err == nil {
		if o, err := exec.Command(php, "-l", path).CombinedOutput(); err != nil {
			t.Fatalf("php -l: %v %s", err, o)
		}
	}
	// A relay.php that closes its PHP tag would put the stored files outside PHP.
	_ = os.WriteFile(filepath.Join(dir, "relay.php"), []byte("<?php echo 1; ?>\n"), 0o644)
	if _, err := phpBundle(dir, out); err == nil {
		t.Fatal("accepted a relay.php with a closing tag")
	}
}

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

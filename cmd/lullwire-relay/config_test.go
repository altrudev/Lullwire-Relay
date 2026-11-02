// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitWritesSettings(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "relay.conf")
	var out bytes.Buffer
	// proxy mode, a domain, default data folder, port 9123, private
	in := strings.NewReader("1\nchat.example.org\n" + filepath.Join(dir, "data") + "\n9123\n\n")
	if err := runInit(in, &out, []string{"-config", conf}); err != nil {
		t.Fatal(err, out.String())
	}
	cfg, path, err := loadConfig([]string{"-config", conf})
	if err != nil || path != conf {
		t.Fatal(err, path)
	}
	if cfg["addr"] != "127.0.0.1:9123" || cfg["data"] != filepath.Join(dir, "data") || len(cfg["join-code"]) != 16 ||
		!strings.HasPrefix(cfg["path"], "/") || len(cfg["path"]) != 12 {
		t.Fatalf("settings: %v", cfg)
	}
	if fi, _ := os.Stat(conf); fi.Mode().Perm() != 0o600 {
		t.Fatalf("settings file mode %v", fi.Mode())
	}
	o := out.String()
	for _, want := range []string{"reverse_proxy 127.0.0.1:9123", "proxy_set_header Upgrade", "https://chat.example.org" + cfg["path"], "ExecStart="} {
		if !strings.Contains(o, want) {
			t.Errorf("next steps miss %q:\n%s", want, o)
		}
	}
	// An existing file is kept unless you say so.
	if err := runInit(strings.NewReader("4\n\n\n\n"), &out, []string{"-config", conf}); err == nil {
		t.Fatal("replaced an existing settings file without asking")
	}
	// Tor and tunnel modes set what they need; running out of answers takes defaults.
	for mode, want := range map[string]string{"3": "onion = true", "2": "forwarded-header = CF-Connecting-IP"} {
		c := filepath.Join(dir, "m"+mode+".conf")
		if err := runInit(strings.NewReader(mode+"\n"), &out, []string{"-config=" + c}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(c)
		if !strings.Contains(string(b), want) || !strings.Contains(string(b), "join-code = ") {
			t.Errorf("mode %s: %s", mode, b)
		}
	}
}

func TestSettingPriority(t *testing.T) {
	cfg, err := parseConfig(strings.NewReader("# comment\naddr = 127.0.0.1:7000\ndata = \"/srv/with space\"\n"))
	if err != nil || cfg["data"] != "/srv/with space" {
		t.Fatal(err, cfg)
	}
	if setting(cfg, "addr", "x") != "127.0.0.1:7000" || setting(cfg, "path", "/") != "/" {
		t.Fatal("file or default not used")
	}
	t.Setenv("HUSH_ADDR", "127.0.0.1:7001") // Hush Relay names still work...
	if setting(cfg, "addr", "x") != "127.0.0.1:7001" {
		t.Fatal("HUSH_ADDR ignored")
	}
	t.Setenv("LULLWIRE_ADDR", "127.0.0.1:7002") // ...but the new name wins
	t.Setenv("LULLWIRE_JOIN_CODE", "abc")
	if setting(cfg, "addr", "x") != "127.0.0.1:7002" || setting(cfg, "join-code", "") != "abc" {
		t.Fatal("LULLWIRE_* not preferred")
	}
	if _, err := parseConfig(strings.NewReader("nonsense = 1\n")); err == nil {
		t.Fatal("unknown setting accepted")
	}
	if _, _, err := loadConfig([]string{"--config", filepath.Join(t.TempDir(), "missing.conf")}); err == nil {
		t.Fatal("a missing settings file that was asked for by name must be an error")
	}
	if !isTrue("1") || !isTrue("true") || isTrue("") || isTrue("no") {
		t.Fatal("isTrue")
	}
}

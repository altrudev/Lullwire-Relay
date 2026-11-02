// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Settings come from, in order of priority: command-line flags, LULLWIRE_*
// environment variables (HUSH_* from Hush Relay still work), the settings file,
// then built-in defaults. "lullwire-relay init" writes the settings file.
//
// The file is plain "name = value" lines using the flag names:
//
//	# written by lullwire-relay init
//	addr = 127.0.0.1:8080
//	data = /home/me/.lullwire-relay-data
//	path = /k7q4mxp2ab/
//	join-code = 3f9c1e7a5b2d8c40

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// settingNames are the flags a settings file may set.
var settingNames = map[string]bool{"addr": true, "data": true, "web": true, "trusted-proxies": true, "onion": true,
	"forwarded-header": true, "path": true, "cover": true, "join-code": true}

func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "lullwire-relay", "relay.conf")
}

// defaultDataDir keeps using a Hush Relay data folder if that's the one that exists.
func defaultDataDir() string {
	home, _ := os.UserHomeDir()
	cur, old := filepath.Join(home, ".lullwire-relay-data"), filepath.Join(home, ".hush-relay-data")
	if _, err := os.Stat(cur); os.IsNotExist(err) {
		if _, err := os.Stat(old); err == nil {
			log.Printf("note: using the Hush Relay data folder %s (rename it to %s, or set -data)", old, cur)
			return old
		}
	}
	return cur
}

// configArg finds -config/--config on the command line (before flag parsing, so the
// file can supply the other flags' defaults).
func configArg(args []string) (string, bool) {
	for i, a := range args {
		for _, p := range []string{"-config", "--config"} {
			if a == p && i+1 < len(args) {
				return args[i+1], true
			}
			if strings.HasPrefix(a, p+"=") {
				return strings.TrimPrefix(a, p+"="), true
			}
		}
	}
	return "", false
}

// loadConfig reads the settings file named by -config or LULLWIRE_CONFIG, or the
// default one if it exists. A file that was asked for by name must exist.
func loadConfig(args []string) (map[string]string, string, error) {
	path, named := configArg(args)
	if !named {
		if path = envSetting("CONFIG"); path != "" {
			named = true
		} else if path = defaultConfigPath(); path == "" {
			return map[string]string{}, "", nil
		}
	}
	f, err := os.Open(path)
	if err != nil {
		if !named && os.IsNotExist(err) {
			return map[string]string{}, "", nil
		}
		return nil, "", fmt.Errorf("settings file: %w", err)
	}
	defer f.Close()
	cfg, err := parseConfig(f)
	if err != nil {
		return nil, "", fmt.Errorf("settings file %s: %w", path, err)
	}
	return cfg, path, nil
}

func parseConfig(r io.Reader) (map[string]string, error) {
	cfg := map[string]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || !settingNames[k] {
			return nil, fmt.Errorf("line %d: expected one of the setting names, like \"addr = 127.0.0.1:8080\"", n)
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		}
		cfg[k] = v
	}
	return cfg, sc.Err()
}

// envSetting reads LULLWIRE_<NAME>, or HUSH_<NAME> from Hush Relay.
func envSetting(name string) string {
	if v := os.Getenv("LULLWIRE_" + name); v != "" {
		return v
	}
	return os.Getenv("HUSH_" + name)
}

// setting resolves one flag's default: environment, then settings file, then def.
func setting(cfg map[string]string, name, def string) string {
	if v := envSetting(strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); v != "" {
		return v
	}
	if v, ok := cfg[name]; ok && v != "" {
		return v
	}
	return def
}

func isTrue(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
}

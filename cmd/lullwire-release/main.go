// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command lullwire-release signs the web app, so browsers that already have it only
// switch to new code signed with your release key. It uses only the Go standard library.
//
//	go run ./cmd/lullwire-release keygen            # once: makes the key, pins it in web/sw.js
//	go run ./cmd/lullwire-release sign 0.6.0        # each release: writes web/release.json
//	go run ./cmd/lullwire-release verify            # checks web/ against web/release.json
//	go run ./cmd/lullwire-release php               # dist/lullwire-relay-<version>.php: app + relay, one file
//
// The key (ECDSA P-256) lives in ~/.lullwire-relay/web-signing.pem; keep it offline
// and backed up. release.json = {"m": manifest JSON, "s": signature over m}, where the
// manifest lists the SHA-256 of every app file except sw.js (the verifier itself).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type manifest struct {
	V       int               `json:"v"`
	Version string            `json:"version"`
	Key     string            `json:"key"`
	Files   map[string]string `json:"files"`
}

type release struct {
	M string `json:"m"`
	S string `json:"s"`
}

var b64 = base64.RawURLEncoding

func main() {
	home, _ := os.UserHomeDir()
	fsFlags := flag.NewFlagSet("lullwire-release", flag.ExitOnError)
	keyPath := fsFlags.String("key", envOr("LULLWIRE_WEB_KEY", filepath.Join(home, ".lullwire-relay", "web-signing.pem")), "signing key file")
	dir := fsFlags.String("dir", "web", "the app folder")
	outDir := fsFlags.String("out", "dist", "where php writes the single-file relay")
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	// Flags may come before or after the version: "sign 0.6.0 -key k.pem" or "sign -key k.pem 0.6.0".
	_ = fsFlags.Parse(os.Args[2:])
	var pos []string
	for fsFlags.NArg() > 0 {
		pos = append(pos, fsFlags.Arg(0))
		_ = fsFlags.Parse(fsFlags.Args()[1:])
	}
	var err error
	switch cmd {
	case "keygen":
		err = keygen(*keyPath, *dir)
	case "sign":
		if len(pos) != 1 || !regexp.MustCompile(`^\d+(\.\d+)*$`).MatchString(pos[0]) {
			usage()
		}
		err = sign(*keyPath, *dir, pos[0])
	case "verify":
		var m manifest
		if m, err = verify(*dir); err == nil {
			fmt.Printf("ok: %s, %d files, key %s\n", m.Version, len(m.Files), fingerprint(m.Key))
		}
	case "php":
		_, err = phpBundle(*dir, *outDir)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lullwire-release keygen | sign <version> | verify | php   [-key file] [-dir web] [-out dist]")
	os.Exit(2)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var pinLine = regexp.MustCompile(`(?m)^const RELEASE_KEY = '[A-Za-z0-9_-]*';`)

// keygen makes a key (refusing to overwrite one) and pins its public half in sw.js.
func keygen(keyPath, dir string) error {
	if _, err := os.Stat(keyPath); err == nil {
		k, err := loadKey(keyPath)
		if err != nil {
			return err
		}
		fmt.Printf("using the existing key %s\n", keyPath)
		return pin(dir, pubRaw(&k.PublicKey))
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	fmt.Printf("new signing key: %s (keep it offline and backed up)\n", keyPath)
	return pin(dir, pubRaw(&k.PublicKey))
}

func pin(dir, pub string) error {
	p := filepath.Join(dir, "sw.js")
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if !pinLine.Match(b) {
		return errors.New("sw.js has no RELEASE_KEY line")
	}
	b = pinLine.ReplaceAll(b, []byte("const RELEASE_KEY = '"+pub+"';"))
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("pinned in %s: %s (fingerprint %s)\n", p, pub, fingerprint(pub))
	return nil
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New(path + ": not a PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New(path + ": not a P-256 key")
	}
	return ek, nil
}

func pubRaw(p *ecdsa.PublicKey) string {
	b := make([]byte, 65)
	b[0] = 4
	p.X.FillBytes(b[1:33])
	p.Y.FillBytes(b[33:])
	return b64.EncodeToString(b)
}

func fingerprint(pub string) string {
	raw, _ := b64.DecodeString(pub)
	h := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(h[:8]))
}

// appFiles lists what the browser runs: everything in the app folder except the
// verifier itself, the manifest, and server-side files that are never served.
func appFiles(dir string) (map[string]string, error) {
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		name := d.Name()
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(name, ".") || name == "data") {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasPrefix(name, "."), rel == "sw.js", rel == "release.json",
			strings.HasSuffix(name, ".php"), strings.HasSuffix(name, ".go"):
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		files[rel] = hex.EncodeToString(h[:])
		return nil
	})
	return files, err
}

func sign(keyPath, dir, version string) error {
	k, err := loadKey(keyPath)
	if err != nil {
		return fmt.Errorf("%w (run: go run ./cmd/lullwire-release keygen)", err)
	}
	sw, err := os.ReadFile(filepath.Join(dir, "sw.js"))
	if err != nil {
		return err
	}
	pub := pubRaw(&k.PublicKey)
	if !strings.Contains(string(sw), "const RELEASE_KEY = '"+pub+"';") {
		return errors.New("sw.js pins a different key (run keygen with this key, or check -key)")
	}
	files, err := appFiles(dir)
	if err != nil {
		return err
	}
	m, _ := json.Marshal(manifest{V: 1, Version: version, Key: pub, Files: files})
	h := sha256.Sum256(m)
	r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
	if err != nil {
		return err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	out, _ := json.Marshal(release{M: string(m), S: b64.EncodeToString(sig)})
	if err := os.WriteFile(filepath.Join(dir, "release.json"), append(out, '\n'), 0o644); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Printf("signed %s: %d files (%s), key %s\n", version, len(files), strings.Join(names, " "), fingerprint(pub))
	return nil
}

func verify(dir string) (manifest, error) {
	var rel release
	var m manifest
	b, err := os.ReadFile(filepath.Join(dir, "release.json"))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &rel); err != nil || rel.M == "" {
		return m, errors.New("release.json is not signed")
	}
	if err := json.Unmarshal([]byte(rel.M), &m); err != nil {
		return m, err
	}
	raw, err := b64.DecodeString(m.Key)
	sig, err2 := b64.DecodeString(rel.S)
	if err != nil || err2 != nil || len(raw) != 65 || len(sig) != 64 {
		return m, errors.New("bad key or signature encoding")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), raw) //nolint:staticcheck // plain uncompressed point
	if x == nil {
		return m, errors.New("bad key")
	}
	h := sha256.Sum256([]byte(rel.M))
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return m, errors.New("signature does not match")
	}
	sw, _ := os.ReadFile(filepath.Join(dir, "sw.js"))
	if !strings.Contains(string(sw), "const RELEASE_KEY = '"+m.Key+"';") {
		return m, errors.New("sw.js pins a different key than the one that signed release.json")
	}
	files, err := appFiles(dir)
	if err != nil {
		return m, err
	}
	for name, want := range m.Files {
		if files[name] != want {
			return m, fmt.Errorf("%s changed since signing", name)
		}
	}
	for name := range files {
		if _, ok := m.Files[name]; !ok {
			return m, fmt.Errorf("%s is not in the signed release", name)
		}
	}
	return m, nil
}

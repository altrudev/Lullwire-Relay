// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command lullwire-relay serves the Lullwire Relay app and its mailbox relay from a
// single self-contained binary. It uses only the Go standard library.
//
//	lullwire-relay                         # http://127.0.0.1:8080, data in ~/.lullwire-relay-data
//	lullwire-relay -addr 127.0.0.1:9000 -data /srv/lullwire
//	lullwire-relay -onion                  # behind a Tor onion service
//
// Put an HTTPS proxy, a tunnel or a Tor onion service in front of it: browsers
// only allow the app's cryptography on https://, .onion (Tor Browser) or localhost.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/altrudev/Lullwire-Relay/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.7.2"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		if err := runInit(os.Stdin, os.Stdout, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	cfg, cfgPath, err := loadConfig(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	set := func(name, def string) string { return setting(cfg, name, def) }
	_ = flag.String("config", cfgPath, "settings file written by \"lullwire-relay init\" (flags and environment variables override it)")
	addr := flag.String("addr", set("addr", "127.0.0.1:8080"), "listen address (keep it on 127.0.0.1 behind a proxy, tunnel or onion service)")
	data := flag.String("data", set("data", defaultDataDir()), "data folder for pending mail and recovery slots")
	webDir := flag.String("web", set("web", ""), "serve the app from this folder instead of the built-in copy")
	trusted := flag.String("trusted-proxies", set("trusted-proxies", ""), "comma-separated proxy IPs allowed to report client addresses (local ones are trusted automatically)")
	onion := flag.Bool("onion", isTrue(set("onion", "")), "Tor onion-service mode: limits apply per mailbox because Tor hides client addresses")
	fwd := flag.String("forwarded-header", set("forwarded-header", "X-Forwarded-For"), "header your proxy uses to report the client address (CF-Connecting-IP for Cloudflare Tunnel)")
	prefix := flag.String("path", set("path", ""), "private path for the app and relay, e.g. /k7q4mxp2/ (everything else shows the front page); see -new-path")
	cover := flag.String("cover", set("cover", ""), "HTML file shown at every other address (default: a plain placeholder page)")
	joinCode := flag.String("join-code", set("join-code", ""), "invite-only mode: people need this code (it travels inside your invites) to use the relay")
	newPath := flag.Bool("new-path", false, "print a random private path and join code, then exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Lullwire Relay %s\n\n  lullwire-relay init     answer a few questions and write a settings file\n  lullwire-relay [flags]  run the relay\n\nFlags:\n", version)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("lullwire-relay", version)
		return
	}
	if *newPath {
		fmt.Printf("-path /%s/ -join-code %s\n", randWord(10), randWord(16))
		return
	}
	base, err := cleanPrefix(*prefix)
	if err != nil {
		log.Fatal(err)
	}
	coverHTML := []byte(defaultCover)
	if *cover != "" {
		if coverHTML, err = os.ReadFile(*cover); err != nil {
			log.Fatalf("cover page: %v", err)
		}
	}

	site, err := siteFS(*webDir, *data)
	if err != nil {
		log.Fatal(err)
	}
	relay, err := NewRelay(*data, strings.Split(*trusted, ","), *onion)
	if err != nil {
		log.Fatalf("data folder: %v", err)
	}
	relay.SetForwardedHeader(*fwd)
	relay.SetJoinCode(*joinCode)
	if *onion && *joinCode == "" {
		log.Printf("note: behind Tor every visitor looks the same, so limits can't tell people apart; add -join-code to keep strangers from using this relay")
	}
	if *prefix != "" && *cover == "" {
		log.Printf("note: the built-in front page is the same on every Lullwire relay; -cover with a page of your own makes this server harder to recognise")
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           withPrefix(base, coverHTML, newMux(relay, site, *webDir == "")),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second, // covers a slow 60 s upload or a 20 s long-poll plus delivery
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	srv.RegisterOnShutdown(relay.Close) // waiting long-polls answer at once

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			relay.Sweep()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	mode := ""
	if *onion {
		mode += ", onion mode"
	}
	if relay.inviteOnly() {
		mode += ", invite-only"
	}
	if cfgPath != "" {
		mode += ", settings: " + cfgPath
	}
	log.Printf("lullwire-relay %s on http://%s%s (data: %s%s)", version, ln.Addr(), base, *data, mode)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		log.Print("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx) // finishes requests in flight before returning
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-stopped
}

// siteFS returns the app files: the built-in copy, or a folder on disk. A data
// folder inside a served folder is refused so mail can never be fetched by URL.
func siteFS(dir, data string) (fs.FS, error) {
	if dir == "" {
		return web.Files, nil
	}
	absWeb, err := realPath(dir)
	if err != nil {
		return nil, err
	}
	absData, err := realPath(data)
	if err != nil {
		return nil, err
	}
	if rel, err := filepath.Rel(absWeb, absData); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("data folder %s is inside the served folder %s; choose another -data", absData, absWeb)
	}
	return os.DirFS(absWeb), nil
}

// realPath resolves symlinks in the longest existing part of p, so a data folder
// reached through a link into the served folder is still recognised.
func realPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rest := ""
	for cur := abs; ; cur = filepath.Dir(cur) {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(real, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}

// randWord returns n random lowercase letters and digits (no look-alikes).
func randWord(n int) string {
	const abc = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, n)
	_, _ = cryptorand.Read(b)
	for i := range b {
		b[i] = abc[int(b[i])%len(abc)]
	}
	return string(b)
}

// cleanPrefix normalises -path to "/" or "/segment/.../".
func cleanPrefix(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/", nil
	}
	p = "/" + strings.Trim(p, "/") + "/"
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "?#%\\ ") {
			return "", fmt.Errorf("-path %q: use letters, digits, - and _ only", p)
		}
	}
	return p, nil
}

const defaultCover = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
<style>body{margin:0;font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1f2933;background:#fafafa;display:grid;place-items:center;min-height:100vh}main{max-width:32rem;padding:2rem;text-align:center}h1{font-weight:600;font-size:1.6rem;margin:0 0 .5rem}p{color:#52606d;margin:0}</style>
</head><body><main><h1>Welcome</h1><p>This site is being set up. Please check back later.</p></main></body></html>
`

// withPrefix serves the app and relay only under the private path. Every other
// address shows the front page (or 404), like an ordinary small website.
func withPrefix(base string, cover []byte, next http.Handler) http.Handler {
	if base == "/" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p := req.URL.Path
		if p+"/" == base { // "/secret" -> "/secret/"
			http.Redirect(w, req, base, http.StatusMovedPermanently)
			return
		}
		if strings.HasPrefix(p, base) {
			r2 := req.Clone(req.Context())
			r2.URL.Path = "/" + strings.TrimPrefix(p, base)
			r2.URL.RawPath = ""
			next.ServeHTTP(w, r2)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if p != "/" && p != "/index.html" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<!doctype html><title>Not found</title><p>Not found.</p>\n"))
			return
		}
		if req.Method == http.MethodGet {
			_, _ = w.Write(cover)
		}
	})
}

// newMux routes the relay API and the app. The relay answers at /relay.php so
// invites and builds made for the PHP relay keep working, and at /relay.
func newMux(relay *Relay, site fs.FS, fixed bool) http.Handler {
	static := newStatic(site, fixed)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/relay.php", "/relay":
			relay.ServeHTTP(w, req)
		case "/live":
			relay.serveLive(w, req)
		default:
			static.ServeHTTP(w, req)
		}
	})
}

type staticFiles struct {
	fs   fs.FS
	etag map[string]string
}

// newStatic serves the app. ETags are computed once for the built-in copy only;
// files served from disk (-web) may change, so they rely on modification times.
func newStatic(site fs.FS, fixed bool) *staticFiles {
	s := &staticFiles{fs: site, etag: map[string]string{}}
	if !fixed {
		return s
	}
	_ = fs.WalkDir(site, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, err := fs.ReadFile(site, p); err == nil {
				h := sha256.Sum256(b)
				s.etag[p] = `"` + hex.EncodeToString(h[:8]) + `"`
			}
		}
		return nil
	})
	return s
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("Not found\n"))
}

func (s *staticFiles) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p := path.Clean("/" + req.URL.Path)
	if strings.HasSuffix(p, "/") {
		p += "index.html"
	}
	name := strings.TrimPrefix(p, "/")
	if name == "" {
		name = "index.html"
	}
	// Never serve dotfiles, data folders, server code or Go sources. Compared in lower
	// case, because Windows and macOS file systems ignore case (Data/, relay.PHP).
	for _, seg := range strings.Split(strings.ToLower(name), "/") {
		if strings.HasPrefix(seg, ".") || seg == "data" {
			notFound(w)
			return
		}
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".php", ".go", ".sh", ".md":
		notFound(w)
		return
	}
	f, err := s.fs.Open(name)
	if err != nil {
		notFound(w)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		notFound(w)
		return
	}
	ctype := mime.TypeByExtension(path.Ext(name))
	switch path.Ext(name) {
	case ".js":
		ctype = "text/javascript; charset=utf-8"
	case ".json":
		ctype = "application/json"
	case ".svg":
		ctype = "image/svg+xml"
	case "":
		ctype = "application/octet-stream"
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", "no-cache")
	if tag, ok := s.etag[name]; ok {
		h.Set("ETag", tag)
	}
	rs, ok := f.(interface {
		Read([]byte) (int, error)
		Seek(int64, int) (int64, error)
	})
	if !ok {
		notFound(w)
		return
	}
	http.ServeContent(w, req, name, info.ModTime(), rs)
}

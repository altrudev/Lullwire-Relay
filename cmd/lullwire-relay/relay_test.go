// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func newTestRelay(t *testing.T, onion bool) (*Relay, http.Handler) {
	t.Helper()
	r, err := NewRelay(t.TempDir(), []string{"10.0.0.9"}, onion)
	if err != nil {
		t.Fatal(err)
	}
	site := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html>app")},
		"app.js":        {Data: []byte("x")},
		"vendor/q.js":   {Data: []byte("q")},
		".htaccess":     {Data: []byte("secret")},
		"relay.php":     {Data: []byte("<?php")},
		"data/x/1.m":    {Data: []byte("mail")},
		"embed.go":      {Data: []byte("package web")},
		"notes.md":      {Data: []byte("#")},
		"sub/.hidden":   {Data: []byte("h")},
		"img/a.svg":     {Data: []byte("<svg/>")},
		"manifest.json": {Data: []byte("{}")},
	}
	return r, newMux(r, site, true)
}

type call struct {
	method, url, body, remote string
	hdr                       map[string]string
}

func do(h http.Handler, c call) (*httptest.ResponseRecorder, map[string]any) {
	if c.method == "" {
		c.method = http.MethodPost
	}
	req := httptest.NewRequest(c.method, c.url, strings.NewReader(c.body))
	if c.remote != "" {
		req.RemoteAddr = c.remote
	}
	for k, v := range c.hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec, m
}

func secret(n int) string   { return fmt.Sprintf("%064x", n) }
func boxOf(s string) string { return sha256hex(s)[:32] }
func blob(n int) string     { return strings.Repeat("e", n) }

func TestPutGetAckRoundTrip(t *testing.T) {
	_, h := newTestRelay(t, false)
	s := secret(1)
	if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + boxOf(s), body: blob(100)}); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	var items []envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil || len(items) != 1 || len(items[0].ID) != 22 {
		t.Fatalf("get: %s", rec.Body)
	}
	do(h, call{url: "/relay.php?a=ack", body: `{"s":"` + s + `","ids":["` + items[0].ID + `"]}`})
	rec, _ = do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("after ack want [] got %s", rec.Body)
	}
}

func TestValidationMatchesPHP(t *testing.T) {
	_, h := newTestRelay(t, false)
	cases := []struct {
		c    call
		code int
		err  string
	}{
		{call{method: "GET", url: "/relay.php"}, 405, ""},
		{call{url: "/relay.php?a=get", body: "{}"}, 400, "bad s"},
		{call{url: "/relay.php?a=get", body: `{"s":"` + strings.Repeat("AB", 32) + `"}`}, 400, "bad s"},
		{call{url: "/relay.php?a=nope", body: `{"s":"` + secret(1) + `"}`}, 400, "bad action"},
		{call{url: "/relay.php?a=put&box[]=1", body: blob(100)}, 400, "bad box"},
		{call{url: "/relay.php?a=put&box=" + boxOf(secret(1)) + "&box=" + boxOf(secret(2)), body: blob(100)}, 400, "bad box"},
		{call{url: "/relay.php?a=put&box=" + boxOf(secret(1)), body: blob(80)}, 413, "bad size"},
		{call{url: "/relay.php?a=put&box=" + boxOf(secret(1)), body: blob(maxBlob + 1)}, 413, "bad size"},
		{call{url: "/relay.php?a=rget", body: `{"l":"zz"}`}, 400, "bad l"},
		{call{url: "/relay.php?a=rput", body: `{"l":"` + secret(1)[:32] + `"}`}, 400, "bad t"},
		{call{url: "/relay.php?a=rput", body: `{"l":"` + secret(1)[:32] + `","t":"` + secret(2) + `","d":"a b"}`}, 400, "bad data"},
	}
	for i, tc := range cases {
		rec, m := do(h, tc.c)
		if rec.Code != tc.code || (tc.err != "" && m["error"] != tc.err) {
			t.Errorf("case %d (%s): got %d %v, want %d %q", i, tc.c.url, rec.Code, m, tc.code, tc.err)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("case %d: missing relay headers", i)
		}
	}
}

func TestLongPollWakesOnPut(t *testing.T) {
	_, h := newTestRelay(t, false)
	s := secret(3)
	do(h, call{url: "/relay.php?a=put&box=" + boxOf(s), body: blob(100)}) // box becomes known
	rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	var items []envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &items)
	do(h, call{url: "/relay.php?a=ack", body: `{"s":"` + s + `","ids":["` + items[0].ID + `"]}`})

	done := make(chan time.Duration)
	start := time.Now()
	go func() {
		do(h, call{url: "/relay.php?a=get&wait=10", body: `{"s":"` + s + `"}`})
		done <- time.Since(start)
	}()
	time.Sleep(300 * time.Millisecond)
	do(h, call{url: "/relay.php?a=put&box=" + boxOf(s), body: blob(100)})
	select {
	case d := <-done:
		if d > 2*time.Second {
			t.Fatalf("long-poll woke after %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll did not wake on put")
	}
}

func TestUnknownMailboxDoesNotHoldConnection(t *testing.T) {
	_, h := newTestRelay(t, false)
	start := time.Now()
	do(h, call{url: "/relay.php?a=get&wait=20", body: `{"s":"` + secret(99) + `"}`})
	if d := time.Since(start); d > 4*time.Second || d < 2*time.Second {
		t.Fatalf("unknown mailbox waited %v, want about 3s", d)
	}
}

func TestLiveConnectionsCappedPerClient(t *testing.T) {
	_, h := newTestRelay(t, false)
	codes := make(chan int, 10)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := secret(100 + i)
			rec, _ := do(h, call{url: "/relay.php?a=get&wait=2", body: `{"s":"` + s + `"}`, remote: "198.51.100.7:5000"})
			codes <- rec.Code
		}(i)
	}
	wg.Wait()
	close(codes)
	n429 := 0
	for c := range codes {
		if c == 429 {
			n429++
		}
	}
	if n429 != 2 {
		t.Fatalf("want 2 refused live connections, got %d", n429)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=get&wait=1", body: `{"s":"` + secret(200) + `"}`, remote: "203.0.113.9:5000"}); rec.Code != 200 {
		t.Fatalf("other client refused: %d", rec.Code)
	}
}

func TestForwardedHeadersTrustedOnlyFromProxies(t *testing.T) {
	r, _ := newTestRelay(t, false)
	mk := func(remote, xff string) string {
		req := httptest.NewRequest("POST", "/relay.php", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		ip, _ := r.clientIP(req)
		return ip
	}
	if got := mk("198.51.100.7:1", "1.2.3.4"); got != "198.51.100.7" {
		t.Errorf("outside client spoofed XFF: %s", got)
	}
	if got := mk("127.0.0.1:1", "9.9.9.9, 1.2.3.4"); got != "1.2.3.4" {
		t.Errorf("local proxy: want last hop, got %s", got)
	}
	if got := mk("10.0.0.9:1", "5.6.7.8"); got != "5.6.7.8" {
		t.Errorf("configured proxy: got %s", got)
	}
	if got := mk("[::1]:1", "not-an-ip"); got != "::1" {
		t.Errorf("bad XFF should fall back: %s", got)
	}
}

func TestPutRateLimit(t *testing.T) {
	_, h := newTestRelay(t, false)
	ok, refused := 0, 0
	for i := 0; i < putsPerMin+5; i++ {
		rec, _ := do(h, call{url: "/relay.php?a=put&box=" + boxOf(secret(i)), body: blob(100), remote: "198.51.100.7:1"})
		if rec.Code == 200 {
			ok++
		} else if rec.Code == 429 {
			refused++
		}
	}
	if ok != putsPerMin || refused != 5 {
		t.Fatalf("ok=%d refused=%d", ok, refused)
	}
}

func TestOnionModeLimitsPerMailbox(t *testing.T) {
	_, h := newTestRelay(t, true)
	// Behind Tor every request is from 127.0.0.1 with no forwarded header.
	for i := 0; i < 200; i++ { // many different senders' mail all reaches different boxes
		if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + boxOf(secret(i)), body: blob(100), remote: "127.0.0.1:1"}); rec.Code != 200 {
			t.Fatalf("onion put %d refused: %d", i, rec.Code)
		}
	}
	box := boxOf(secret(5000))
	refused := 0
	for i := 0; i < onionPutsPerBoxMin+3; i++ {
		if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + box, body: blob(100), remote: "127.0.0.1:1"}); rec.Code == 429 {
			refused++
		}
	}
	if refused != 3 {
		t.Fatalf("per-box onion limit: refused %d", refused)
	}
	// Live connections: capped per mailbox, not shared by everyone on 127.0.0.1.
	var wg sync.WaitGroup
	codes := make([]int, 6)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, _ := do(h, call{url: "/relay.php?a=get&wait=1", body: `{"s":"` + secret(300+i) + `"}`, remote: "127.0.0.1:1"})
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != 200 {
			t.Fatalf("onion user %d refused (%d): limits must not be shared across mailboxes", i, c)
		}
	}
}

func TestMailboxQuota(t *testing.T) {
	r, h := newTestRelay(t, false)
	box := boxOf(secret(7))
	var wg sync.WaitGroup
	for i := 0; i < maxPerBox+20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			do(h, call{url: "/relay.php?a=put&box=" + box, body: blob(100), remote: fmt.Sprintf("198.51.%d.%d:1", i/250, i%250)})
		}(i)
	}
	wg.Wait()
	if ids, _ := r.pending(box); len(ids) != maxPerBox {
		t.Fatalf("concurrent puts stored %d, want exactly %d", len(ids), maxPerBox)
	}
}

func TestRecoverySlots(t *testing.T) {
	_, h := newTestRelay(t, false)
	l, tok := secret(1)[:32], secret(2)
	if rec, _ := do(h, call{url: "/relay.php?a=rput", body: `{"l":"` + l + `","t":"` + tok + `","d":"abc_-1"}`}); rec.Code != 200 {
		t.Fatalf("rput %d", rec.Code)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=rput", body: `{"l":"` + l + `","t":"` + secret(3) + `","d":"evil"}`}); rec.Code != 403 {
		t.Fatalf("overwrite with wrong token: %d", rec.Code)
	}
	if _, m := do(h, call{url: "/relay.php?a=rget", body: `{"l":"` + l + `"}`}); m["d"] != "abc_-1" {
		t.Fatalf("rget %v", m)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=rdel", body: `{"l":"` + l + `","t":"` + secret(3) + `"}`}); rec.Code != 403 {
		t.Fatalf("rdel with wrong token: %d", rec.Code)
	}
	do(h, call{url: "/relay.php?a=rdel", body: `{"l":"` + l + `","t":"` + tok + `"}`})
	if rec, _ := do(h, call{url: "/relay.php?a=rget", body: `{"l":"` + l + `"}`}); rec.Code != 404 {
		t.Fatalf("after rdel: %d", rec.Code)
	}
	// New slots: 5 per client per day.
	refused := 0
	for i := 0; i < 7; i++ {
		rec, _ := do(h, call{url: "/relay.php?a=rput", body: fmt.Sprintf(`{"l":"%032x","t":"%s","d":"x"}`, 1000+i, tok), remote: "198.51.100.7:1"})
		if rec.Code == 429 {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("slot rate limit refused %d, want 2", refused)
	}
}

func TestSharesDataWithPHPRelay(t *testing.T) {
	r, h := newTestRelay(t, false)
	s := secret(42)
	box := boxOf(s)
	// Mail written by relay.php: <data>/<box>/<10-digit time><12 hex>.m
	_ = os.MkdirAll(filepath.Join(r.data, box), 0o700)
	_ = os.WriteFile(filepath.Join(r.data, box, "1793500000"+"a1b2c3d4e5f6"+".m"), []byte(blob(100)), 0o600)
	// A slot written by relay.php
	l := secret(1)[:32]
	php, _ := json.Marshal(map[string]string{"h": sha256hex(secret(2)), "d": "phpdata"})
	_ = os.WriteFile(filepath.Join(r.recover, l+".json"), php, 0o600)

	rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	if !strings.Contains(rec.Body.String(), `"1793500000a1b2c3d4e5f6"`) {
		t.Fatalf("PHP-written mail not delivered: %s", rec.Body)
	}
	if _, m := do(h, call{url: "/relay.php?a=rget", body: `{"l":"` + l + `"}`}); m["d"] != "phpdata" {
		t.Fatalf("PHP slot not read: %v", m)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=rput", body: `{"l":"` + l + `","t":"` + secret(2) + `","d":"new"}`}); rec.Code != 200 {
		t.Fatalf("PHP slot token not honoured: %d", rec.Code)
	}
}

func TestSweep(t *testing.T) {
	r, _ := newTestRelay(t, false)
	box := boxOf(secret(1))
	dir := filepath.Join(r.data, box)
	_ = os.MkdirAll(dir, 0o700)
	old := time.Now().Add(-ttl - time.Hour)
	for _, n := range []string{"1000000000aaaaaaaaaaaa.m", "x.m.tmp"} {
		p := filepath.Join(dir, n)
		_ = os.WriteFile(p, []byte("x"), 0o600)
		_ = os.Chtimes(p, old, old)
	}
	fresh := filepath.Join(r.data, boxOf(secret(2)))
	_ = os.MkdirAll(fresh, 0o700)
	_ = os.WriteFile(filepath.Join(fresh, "1900000000bbbbbbbbbbbb.m"), []byte("x"), 0o600)
	slot := filepath.Join(r.recover, secret(3)[:32]+".json")
	_ = os.WriteFile(slot, []byte("{}"), 0o600)
	so := time.Now().Add(-slotTTL - time.Hour)
	_ = os.Chtimes(slot, so, so)
	r.allow("put", "k", time.Minute, 1)
	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	r.Sweep()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("expired mailbox not removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("fresh mail removed")
	}
	if _, err := os.Stat(slot); !os.IsNotExist(err) {
		t.Error("stale slot not removed")
	}
	if len(r.counts) != 0 {
		t.Errorf("expired rate windows kept: %d", len(r.counts))
	}
}

func TestStaticFiles(t *testing.T) {
	_, h := newTestRelay(t, false)
	want := map[string]int{
		"/": 200, "/index.html": 200, "/app.js": 200, "/vendor/q.js": 200, "/img/a.svg": 200,
		"/.htaccess": 404, "/relay.php": 405, "/data/x/1.m": 404, "/embed.go": 404,
		"/notes.md": 404, "/sub/.hidden": 404, "/missing": 404, "/../app.js": 200,
		"/vendor/../.htaccess": 404, "/%2e%2e/relay.php": 404,
	}
	for p, code := range want {
		req := httptest.NewRequest("GET", "/", nil)
		req.URL.Path = p
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != code {
			t.Errorf("GET %s = %d, want %d", p, rec.Code, code)
		}
		if p == "/" && (rec.Header().Get("Content-Security-Policy") != "frame-ancestors 'none'" || rec.Header().Get("X-Frame-Options") != "DENY") {
			t.Error("anti-framing headers missing")
		}
	}
	rec, _ := do(h, call{method: "POST", url: "/index.html"})
	if rec.Code != 405 {
		t.Errorf("POST to a static file = %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/app.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("app.js content type %q", ct)
	}
	b, _ := io.ReadAll(rec.Body)
	if !bytes.Equal(b, []byte("x")) {
		t.Errorf("app.js body %q", b)
	}
}

func TestDataInsideWebRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := siteFS(dir, filepath.Join(dir, "data")); err == nil {
		t.Fatal("data inside web folder accepted")
	}
	if _, err := siteFS(dir, filepath.Join(filepath.Dir(dir), "elsewhere")); err != nil {
		t.Fatalf("data outside web refused: %v", err)
	}
	if _, err := siteFS(filepath.Join(dir, "web"), filepath.Join(dir, "web..data")); err != nil {
		t.Fatalf("sibling with similar name refused: %v", err)
	}
}

// ---- regressions from the independent review ---------------------------------

func TestOnionIgnoresClientSuppliedForwardedHeaders(t *testing.T) {
	_, h := newTestRelay(t, true)
	refused := 0
	for i := 0; i < onionSlotsPerDay+10; i++ {
		rec, _ := do(h, call{url: "/relay.php?a=rput", body: fmt.Sprintf(`{"l":"%032x","t":"%s","d":"x"}`, 5000+i, secret(2)),
			remote: "127.0.0.1:1", hdr: map[string]string{"X-Forwarded-For": fmt.Sprintf("10.9.%d.%d", i/250, i%250), "CF-Connecting-IP": fmt.Sprintf("10.8.0.%d", i%250)}})
		if rec.Code == 429 {
			refused++
		}
	}
	if refused != 10 {
		t.Fatalf("spoofed headers bypassed onion slot limit: refused %d of 10 extra", refused)
	}
	codes := make([]int, 5)
	var wg sync.WaitGroup
	s := secret(777)
	do(h, call{url: "/relay.php?a=put&box=" + boxOf(s), body: blob(100), remote: "127.0.0.1:1"})
	rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`, remote: "127.0.0.1:1"})
	var items []envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &items)
	do(h, call{url: "/relay.php?a=ack", body: `{"s":"` + s + `","ids":["` + items[0].ID + `"]}`, remote: "127.0.0.1:1"})
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, _ := do(h, call{url: "/relay.php?a=get&wait=1", body: `{"s":"` + s + `"}`, remote: "127.0.0.1:1",
				hdr: map[string]string{"X-Forwarded-For": fmt.Sprintf("10.7.0.%d", i)}})
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()
	n := 0
	for _, c := range codes {
		if c == 429 {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("spoofed headers bypassed per-mailbox live cap: %v", codes)
	}
}

func TestForwardedHeaderChoice(t *testing.T) {
	r, _ := newTestRelay(t, false)
	req := httptest.NewRequest("POST", "/relay.php", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")
	req.Header.Set("X-Forwarded-For", "2.2.2.2")
	if ip, _ := r.clientIP(req); ip != "2.2.2.2" {
		t.Errorf("default should use X-Forwarded-For, got %s", ip)
	}
	r.SetForwardedHeader("cf-connecting-ip")
	if ip, _ := r.clientIP(req); ip != "1.1.1.1" {
		t.Errorf("CF-Connecting-IP when chosen, got %s", ip)
	}
}

func TestRecoveryMissesDoNotStallDelivery(t *testing.T) {
	_, h := newTestRelay(t, false)
	var wg sync.WaitGroup
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			do(h, call{url: "/relay.php?a=rget", body: fmt.Sprintf(`{"l":"%032x"}`, 90000+i)})
		}(i)
	}
	time.Sleep(20 * time.Millisecond)
	worst := time.Duration(0)
	for i := 0; i < 20; i++ {
		start := time.Now()
		do(h, call{url: "/relay.php?a=put&box=" + boxOf(secret(i)), body: blob(100)})
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	wg.Wait()
	if worst > 50*time.Millisecond {
		t.Fatalf("puts stalled behind recovery lookups: worst %v", worst)
	}
}

func TestDeliveryIsCappedAndStreamed(t *testing.T) {
	r, h := newTestRelay(t, false)
	s := secret(888)
	box := boxOf(s)
	_ = os.MkdirAll(r.boxDir(box), 0o700)
	for i := 0; i < 16; i++ { // 16 x 500 KB written directly (bypassing put limits)
		_ = os.WriteFile(filepath.Join(r.boxDir(box), fmt.Sprintf("%010d%012x.m", 1790000000+i, i)), bytes.Repeat([]byte{byte(i)}, 500_000), 0o600)
	}
	rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	var items []envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatalf("streamed JSON invalid: %v", err)
	}
	if len(items) == 0 || len(items) > maxDeliver/500_000 {
		t.Fatalf("delivered %d items of 500 KB, cap is %d bytes", len(items), maxDeliver)
	}
	if items[0].ID != "1790000000000000000000" {
		t.Fatalf("wrong order: first id %s", items[0].ID)
	}
	// One oversized envelope is still delivered on its own.
	big := secret(889)
	_ = os.MkdirAll(r.boxDir(boxOf(big)), 0o700)
	_ = os.WriteFile(filepath.Join(r.boxDir(boxOf(big)), "1790000000aaaaaaaaaaaa.m"), make([]byte, maxDeliver+10), 0o600)
	rec, _ = do(h, call{url: "/relay.php?a=get", body: `{"s":"` + big + `"}`})
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil || len(items) != 1 {
		t.Fatalf("oversized envelope not delivered alone: %v %d", err, len(items))
	}
}

func TestCloseAnswersWaitingLongPolls(t *testing.T) {
	r, h := newTestRelay(t, false)
	s := secret(31)
	do(h, call{url: "/relay.php?a=put&box=" + boxOf(s), body: blob(100)})
	rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	var items []envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &items)
	do(h, call{url: "/relay.php?a=ack", body: `{"s":"` + s + `","ids":["` + items[0].ID + `"]}`})
	done := make(chan string)
	go func() {
		rec, _ := do(h, call{url: "/relay.php?a=get&wait=20", body: `{"s":"` + s + `"}`})
		done <- strings.TrimSpace(rec.Body.String())
	}()
	time.Sleep(200 * time.Millisecond)
	r.Close()
	select {
	case body := <-done:
		if body != "[]" {
			t.Fatalf("got %q", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long-poll still waiting after Close")
	}
}

func TestMiscReviewFixes(t *testing.T) {
	if leadingInt("5abc") != 5 || leadingInt("abc") != 0 || leadingInt("99999999999999") != 999999999 {
		t.Error("leadingInt should behave like PHP (int)")
	}
	r, _ := newTestRelay(t, false)
	for i := 0; i < maxCounters; i++ {
		r.counts[fmt.Sprint(i)] = counter{n: 1, exp: time.Now().Add(time.Hour).Unix()}
	}
	if r.allow("put", "new-client", time.Minute, 100) {
		t.Error("counter table full: new windows must be refused")
	}
	// Data folder reached through a symlink into the served folder.
	dir := t.TempDir()
	webDir := filepath.Join(dir, "web")
	_ = os.MkdirAll(filepath.Join(webDir, "store"), 0o700)
	if err := os.Symlink(filepath.Join(webDir, "store"), filepath.Join(dir, "link")); err == nil {
		if _, err := siteFS(webDir, filepath.Join(dir, "link", "data")); err == nil {
			t.Error("symlinked data folder inside web accepted")
		}
	}
	// ETags only for the fixed built-in copy.
	if len(newStatic(fstest.MapFS{"a.js": {Data: []byte("x")}}, false).etag) != 0 {
		t.Error("disk-served files must not get startup ETags")
	}
}

// ---- private path, front page, invite-only ------------------------------------

func TestPrivatePathAndCover(t *testing.T) {
	r, inner := newTestRelay(t, false)
	_ = r
	h := withPrefix("/k7q4/", []byte("COVER"), inner)
	get := func(p string) (int, string) {
		req := httptest.NewRequest("GET", "/", nil)
		req.URL.Path = p
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if c, b := get("/"); c != 200 || b != "COVER" {
		t.Errorf("/ = %d %q", c, b)
	}
	for _, p := range []string{"/index.html.bak", "/relay.php", "/app.js", "/k7q", "/k7q4x/"} {
		if c, b := get(p); c == 200 || strings.Contains(b, "app") {
			t.Errorf("%s leaked: %d %q", p, c, b)
		}
	}
	if c, _ := get("/k7q4"); c != 301 {
		t.Errorf("/k7q4 should redirect, got %d", c)
	}
	if c, b := get("/k7q4/"); c != 200 || !strings.Contains(b, "app") {
		t.Errorf("app under prefix: %d %q", c, b)
	}
	rec, _ := do(h, call{url: "/k7q4/relay.php?a=info"})
	if rec.Code != 200 {
		t.Errorf("relay under prefix: %d", rec.Code)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=info"}); rec.Code == 200 {
		t.Error("relay reachable outside the private path")
	}
	for _, bad := range []string{"/../x/", "/a b/", "/a%2f/"} {
		if _, err := cleanPrefix(bad); err == nil {
			t.Errorf("cleanPrefix accepted %q", bad)
		}
	}
	if p, _ := cleanPrefix("abc/def"); p != "/abc/def/" {
		t.Errorf("cleanPrefix normalisation: %q", p)
	}
}

func TestInviteOnly(t *testing.T) {
	r, h := newTestRelay(t, false)
	r.SetJoinCode("open sesame")
	_, info := do(h, call{url: "/relay.php?a=info"})
	if info["invite"] != true {
		t.Fatalf("info: %v", info)
	}
	s := secret(1)
	box := boxOf(s)
	if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + box, body: blob(100)}); rec.Code != 404 {
		t.Errorf("put to non-member = %d", rec.Code)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`}); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("get by non-member should be an empty mailbox, got %d %s", rec.Code, rec.Body)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=join", body: `{"s":"` + s + `","code":"wrong"}`}); rec.Code != 403 {
		t.Errorf("wrong code = %d", rec.Code)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=join", body: `{"s":"` + s + `","code":" open sesame "}`}); rec.Code != 200 {
		t.Fatalf("join = %d", rec.Code)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + box, body: blob(100)}); rec.Code != 200 {
		t.Errorf("put to member = %d", rec.Code)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`}); rec.Code != 200 {
		t.Errorf("get by member = %d", rec.Code)
	}
	// Recovery: storing needs membership; reading needs only the 128-bit locator.
	l := secret(9)[:32]
	if rec, _ := do(h, call{url: "/relay.php?a=rput", body: `{"l":"` + l + `","t":"` + secret(2) + `","d":"x"}`}); rec.Code != 403 {
		t.Errorf("rput without membership = %d", rec.Code)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=rput", body: `{"l":"` + l + `","t":"` + secret(2) + `","d":"x","s":"` + s + `"}`}); rec.Code != 200 {
		t.Errorf("rput by member = %d", rec.Code)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=rget", body: `{"l":"` + l + `"}`}); rec.Code != 200 {
		t.Errorf("rget = %d", rec.Code)
	}
	// Membership survives a restart.
	r2, err := NewRelay(r.data, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	r2.SetJoinCode("open sesame")
	if !r2.isMember(box) {
		t.Error("membership lost on restart")
	}
	// Guessing the code is rate limited.
	refused := 0
	for i := 0; i < 15; i++ {
		rec, _ := do(h, call{url: "/relay.php?a=join", body: `{"s":"` + secret(50+i) + `","code":"guess"}`, remote: "198.51.100.7:1"})
		if rec.Code == 429 {
			refused++
		}
	}
	if refused != 5 {
		t.Errorf("join attempts refused %d, want 5", refused)
	}
	// Open relays accept everything and join is a no-op.
	_, h2 := newTestRelay(t, false)
	if rec, _ := do(h2, call{url: "/relay.php?a=join", body: `{"s":"` + s + `"}`}); rec.Code != 200 {
		t.Errorf("join on open relay = %d", rec.Code)
	}
}

// Wrong join codes are limited; the right code always works, so guessing can't lock people out.
func TestJoinOnlyFailuresCount(t *testing.T) {
	r, h := newTestRelay(t, true) // behind Tor every visitor shares one rate-limit key
	r.SetJoinCode("right-code")
	for i := 0; i < 15; i++ {
		do(h, call{url: "/relay.php?a=join", body: `{"s":"` + secret(500+i) + `","code":"wrong"}`})
	}
	rec, _ := do(h, call{url: "/relay.php?a=join", body: `{"s":"` + secret(600) + `","code":"wrong"}`})
	if rec.Code != 429 {
		t.Errorf("guessing was not limited: %d", rec.Code)
	}
	r2, h2 := newTestRelay(t, true)
	r2.SetJoinCode("right-code")
	for i := 0; i < 70; i++ { // well past both the per-client and the relay-wide limit
		do(h2, call{url: "/relay.php?a=join", body: `{"s":"` + secret(700+i) + `","code":"wrong"}`})
	}
	for i := 0; i < 20; i++ {
		if rec, _ := do(h2, call{url: "/relay.php?a=join", body: `{"s":"` + secret(800+i) + `","code":"right-code"}`}); rec.Code != 200 {
			t.Fatalf("member %d with the right code was refused: %d", i, rec.Code)
		}
	}
}

// Addresses in one IPv6 /64 count as one client.
func TestIPv6GroupedBy64(t *testing.T) {
	r, _ := newTestRelay(t, false)
	key := func(ip string) string {
		req := httptest.NewRequest("POST", "/relay.php", nil)
		req.RemoteAddr = "[" + ip + "]:5000"
		k, _ := r.clientKey(req)
		return k
	}
	if key("2001:db8:1:2::1") != key("2001:db8:1:2:ffff::9") {
		t.Error("one /64 should be one client")
	}
	if key("2001:db8:1:2::1") == key("2001:db8:1:3::1") {
		t.Error("different /64s should be different clients")
	}
}

// New memberships are limited and capped; renewals always work; stale ones expire.
func TestMemberLimitsAndExpiry(t *testing.T) {
	r, h := newTestRelay(t, false)
	r.SetJoinCode("code")
	join := func(n int, ip string) int {
		rec, _ := do(h, call{url: "/relay.php?a=join", body: `{"s":"` + secret(n) + `","code":"code"}`, remote: ip + ":4000"})
		return rec.Code
	}
	for i := 0; i < 30; i++ {
		if c := join(1000+i, "203.0.113.5"); c != 200 {
			t.Fatalf("join %d: %d", i, c)
		}
	}
	if c := join(2000, "203.0.113.5"); c != 429 {
		t.Errorf("31st new member from one client: %d, want 429", c)
	}
	if c := join(1000, "203.0.113.5"); c != 200 {
		t.Errorf("renewing an existing membership must always work: %d", c)
	}
	if c := join(2001, "198.51.100.9"); c != 200 {
		t.Errorf("another client: %d", c)
	}
	box := sha256hex(secret(1001))[:32]
	old := time.Now().Add(-memberTTL - time.Hour)
	_ = os.Chtimes(filepath.Join(r.memberDir, box), old, old)
	r.Sweep()
	if r.isMember(box) {
		t.Error("a membership not renewed for memberTTL should expire")
	}
	if !r.isMember(sha256hex(secret(1000))[:32]) {
		t.Error("a renewed membership must stay")
	}
}

// Server files stay hidden whatever their case (Windows and macOS ignore it).
func TestStaticBlockIgnoresCase(t *testing.T) {
	_, h := newTestRelay(t, false)
	for _, p := range []string{"/relay.config.PHP", "/Data/x", "/README.MD", "/.Git/config"} {
		if rec, _ := do(h, call{method: "GET", url: p}); rec.Code != 404 {
			t.Errorf("%s served with %d", p, rec.Code)
		}
	}
}

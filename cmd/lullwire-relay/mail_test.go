// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mailHello(t *testing.T, w *testWS, s string, cover bool) {
	t.Helper()
	w.json(map[string]any{"op": "mail", "s": s, "cover": cover})
	if m := w.expectOp(t, "ready"); m["mail"] != true {
		t.Fatalf("ready without mail: %v", m)
	}
}

func putFrame(rid uint32, box string, body []byte) []byte {
	f := make([]byte, 5, 21+len(body))
	f[0] = 1
	binary.BigEndian.PutUint32(f[1:5], rid)
	b, _ := hex.DecodeString(box)
	return append(append(f, b...), body...)
}

// expectMail reads frames until a mail frame arrives, skipping cover traffic.
func expectMail(t *testing.T, w *testWS) map[string]any {
	t.Helper()
	for {
		_, b, err := w.read(3 * time.Second)
		var m map[string]any
		if err != nil || json.Unmarshal(b, &m) != nil {
			t.Fatalf("no mail frame: %v %s", err, b)
		}
		if m["op"] == "m" || m["op"] == "put" {
			return m
		}
	}
}

func TestMailPushAckAndPut(t *testing.T) {
	r, srv := liveServer(t, "")
	s := secret(41)
	box := boxOf(s)
	// Mail that was waiting before the connection is pushed at once.
	if code, _ := r.store(box, []byte(blob(200))); code != 0 {
		t.Fatal("store", code)
	}
	w := dialWS(t, srv, "/live")
	w.pong = true
	mailHello(t, w, s, false)
	m := expectMail(t, w)
	if m["op"] != "m" || len(m["id"].(string)) != 22 {
		t.Fatalf("pending mail not pushed: %v", m)
	}
	d, _ := base64.StdEncoding.DecodeString(m["d"].(string))
	if string(d) != blob(200) {
		t.Fatal("wrong content")
	}
	// New mail (here: delivered over the same connection) is pushed as it arrives.
	w.write(0x2, putFrame(7, box, []byte(blob(300))), true)
	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		x := expectMail(t, w)
		got[x["op"].(string)] = true
		if x["op"] == "put" && (x["ok"] != true || x["r"].(float64) != 7) {
			t.Fatalf("put answer: %v", x)
		}
	}
	if !got["put"] || !got["m"] {
		t.Fatalf("expected a put answer and a push: %v", got)
	}
	// Acknowledged mail is deleted.
	ids, _ := r.pending(box)
	w.json(map[string]any{"op": "ack", "ids": []string{ids[0], ids[1]}})
	time.Sleep(200 * time.Millisecond)
	if left, _ := r.pending(box); len(left) != 0 {
		t.Fatalf("ack did not delete: %v", left)
	}
	// Unacknowledged mail is pushed again on the next connection, not twice on one.
	_, _ = r.store(box, []byte(blob(150)))
	if x := expectMail(t, w); x["op"] != "m" {
		t.Fatal("no push")
	}
	if _, b, err := w.read(500 * time.Millisecond); err == nil && strings.Contains(string(b), `"op":"m"`) {
		t.Fatal("same envelope pushed twice on one connection")
	}
	w.c.Close()
	w2 := dialWS(t, srv, "/live")
	mailHello(t, w2, s, false)
	if x := expectMail(t, w2); x["op"] != "m" {
		t.Fatal("unacknowledged mail not pushed again after reconnecting")
	}
}

func TestMailPutChecks(t *testing.T) {
	r, srv := liveServer(t, "code-1")
	member := secret(51)
	r.mu.Lock()
	r.members[boxOf(member)] = true
	r.mu.Unlock()
	w := dialWS(t, srv, "/live")
	mailHello(t, w, member, false)
	cases := []struct {
		box  string
		body []byte
		want float64
	}{
		{boxOf(secret(52)), []byte(blob(200)), 404}, // not a member of this invite-only relay
		{boxOf(member), []byte(blob(50)), 413},      // too small
		{boxOf(member), []byte(blob(200)), 0},
	}
	for i, c := range cases {
		w.write(0x2, putFrame(uint32(i+1), c.box, c.body), true)
		for {
			x := expectMail(t, w)
			if x["op"] != "put" {
				continue
			}
			if c.want == 0 && x["ok"] != true || c.want != 0 && x["e"] != c.want {
				t.Fatalf("case %d: %v", i, x)
			}
			break
		}
	}
	// Noise frames are dropped without an answer.
	w.write(0x2, append([]byte{0}, make([]byte, 1200)...), true)
	if _, b, err := w.read(400 * time.Millisecond); err == nil && strings.Contains(string(b), `"op":"put"`) {
		t.Fatal("noise was answered")
	}
	// Deliveries over the connection share the HTTP rate limit.
	limited := false
	for i := 0; i < putsPerMin+5 && !limited; i++ {
		w.write(0x2, putFrame(uint32(100+i), boxOf(member), []byte(blob(100))), true)
		for {
			x := expectMail(t, w)
			if x["op"] != "put" {
				continue
			}
			limited = x["e"] == float64(429)
			break
		}
	}
	if !limited {
		t.Fatal("puts over the live connection are not rate limited")
	}
}

func TestMailCoverAndLimits(t *testing.T) {
	r, srv := liveServer(t, "")
	r.hub.coverMin, r.hub.coverSpread = 50*time.Millisecond, 50*time.Millisecond
	w := dialWS(t, srv, "/live")
	mailHello(t, w, secret(61), true)
	m := w.expectOp(t, "n")
	if p, _ := base64.StdEncoding.DecodeString(m["p"].(string)); len(p) < 1000 {
		t.Fatal("cover frame too small")
	}
	// Mail connections count towards the per-client live limit.
	var conns []*testWS
	for i := 0; i < livePerKey+1; i++ {
		c := dialWSFrom(t, srv, "/live", "198.51.100.9")
		c.json(map[string]any{"op": "mail", "s": secret(70 + i)})
		_, b, _ := c.read(2 * time.Second)
		conns = append(conns, c)
		if i == livePerKey && !strings.Contains(string(b), "too many") {
			t.Fatalf("connection %d over the limit was accepted: %s", i, b)
		}
	}
	for _, c := range conns {
		c.c.Close()
	}
	// The relay says it supports live mail.
	_, h := newTestRelay(t, false)
	_, info := do(h, call{url: "/relay.php?a=info", body: "{}"})
	if info["mail"] != true {
		t.Fatalf("info: %v", info)
	}
	_ = r
}

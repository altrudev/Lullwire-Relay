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

func sendHello(t *testing.T, w *testWS) {
	t.Helper()
	w.json(map[string]any{"op": "send"})
	if m := w.expectOp(t, "ready"); m["send"] != true {
		t.Fatalf("ready without send: %v", m)
	}
}

func putFrame(kind byte, rid uint32, box string, body []byte) []byte {
	f := make([]byte, 5, 21+len(body))
	f[0] = kind
	binary.BigEndian.PutUint32(f[1:5], rid)
	b, _ := hex.DecodeString(box)
	if len(b) != 16 {
		b = make([]byte, 16)
	}
	return append(append(f, b...), body...)
}

// next reads JSON frames until one with the given op arrives.
func next(t *testing.T, w *testWS, op string) map[string]any {
	t.Helper()
	for {
		_, b, err := w.read(3 * time.Second)
		var m map[string]any
		if err != nil || json.Unmarshal(b, &m) != nil {
			t.Fatalf("no %q frame: %v %s", op, err, b)
		}
		if m["op"] == op {
			return m
		}
	}
}

func TestMailPushAckAndSend(t *testing.T) {
	r, srv := liveServer(t, "")
	s := secret(41)
	box := boxOf(s)
	if code, _ := r.store(box, []byte(blob(200))); code != 0 { // waiting before the connection
		t.Fatal("store", code)
	}
	w := dialWS(t, srv, "/live")
	w.pong = true
	mailHello(t, w, s, false)
	m := next(t, w, "m")
	if d, _ := base64.StdEncoding.DecodeString(m["d"].(string)); string(d) != blob(200) {
		t.Fatal("wrong content")
	}
	// Deliveries go over a separate, anonymous send connection; the mail connection gets them.
	snd := dialWS(t, srv, "/live")
	sendHello(t, snd)
	snd.write(0x2, putFrame(1, 7, box, []byte(blob(300))), true)
	if p := next(t, snd, "put"); p["ok"] != true || p["r"].(float64) != 7 {
		t.Fatalf("put answer: %v", p)
	}
	if x := next(t, w, "m"); x["id"] == m["id"] {
		t.Fatal("same envelope twice")
	}
	// The mail connection no longer accepts deliveries (they would name the sender).
	w.write(0x2, putFrame(1, 8, box, []byte(blob(300))), true)
	if _, b, err := w.read(500 * time.Millisecond); err == nil && strings.Contains(string(b), `"op":"put"`) {
		t.Fatal("mail connection took a delivery")
	}
	// Acknowledged mail is deleted; the rest is pushed again on the next connection.
	ids, _ := r.pending(box)
	w.json(map[string]any{"op": "ack", "ids": []string{ids[0]}})
	time.Sleep(200 * time.Millisecond)
	if left, _ := r.pending(box); len(left) != 1 {
		t.Fatalf("ack: %v", left)
	}
	w.c.Close()
	w2 := dialWS(t, srv, "/live")
	mailHello(t, w2, s, false)
	if x := next(t, w2, "m"); x["id"] != ids[1] {
		t.Fatal("unacknowledged mail not pushed again after reconnecting")
	}
}

func TestSendChecksAndCover(t *testing.T) {
	r, srv := liveServer(t, "code-1")
	member := secret(51)
	r.mu.Lock()
	r.members[boxOf(member)] = true
	r.mu.Unlock()
	w := dialWS(t, srv, "/live")
	sendHello(t, w)
	cases := []struct {
		kind byte
		box  string
		body []byte
		want float64
	}{
		{1, boxOf(secret(52)), []byte(blob(200)), 404}, // not a member of this invite-only relay
		{1, boxOf(member), []byte(blob(50)), 413},      // too small
		{1, boxOf(member), []byte(blob(200)), 0},
		{0, "", make([]byte, 1200), 0}, // cover: answered exactly like a delivery
	}
	for i, c := range cases {
		w.write(0x2, putFrame(c.kind, uint32(i+1), c.box, c.body), true)
		x := next(t, w, "put")
		if x["r"].(float64) != float64(i+1) || (c.want == 0 && x["ok"] != true) || (c.want != 0 && x["e"] != c.want) {
			t.Fatalf("case %d: %v", i, x)
		}
	}
	if ids, _ := r.pending(boxOf(member)); len(ids) != 1 {
		t.Fatalf("cover traffic was stored: %v", ids)
	}
	// Deliveries share the HTTP rate limit.
	limited := false
	for i := 0; i < putsPerMin+5 && !limited; i++ {
		w.write(0x2, putFrame(1, uint32(100+i), boxOf(member), []byte(blob(100))), true)
		limited = next(t, w, "put")["e"] == float64(429)
	}
	if !limited {
		t.Fatal("deliveries over the send connection are not rate limited")
	}
	// Invite-only: a mailbox that hasn't joined can't hold a mail connection open.
	nm := dialWS(t, srv, "/live")
	nm.json(map[string]any{"op": "mail", "s": secret(53)})
	if m := nm.expectOp(t, "error"); !strings.Contains(m["msg"].(string), "join") {
		t.Fatal(m)
	}
}

func TestMailCoverFramesLookLikeMail(t *testing.T) {
	r, srv := liveServer(t, "")
	r.hub.coverMin, r.hub.coverSpread = 50*time.Millisecond, 50*time.Millisecond
	w := dialWS(t, srv, "/live")
	mailHello(t, w, secret(61), true)
	n := next(t, w, "n")
	p, _ := base64.StdEncoding.DecodeString(n["d"].(string))
	if len(p) < envMin || len(p) >= envMin+envVar || len(n["id"].(string)) != 22 {
		t.Fatalf("cover frame shape: id %v, %d bytes", n["id"], len(p))
	}
	_, _, _ = r, srv, w
}

func TestLiveConnectionLimits(t *testing.T) {
	r, srv := liveServer(t, "")
	// Open connections are capped per client.
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
	// New connections are rate limited, and made-up mailboxes are never remembered.
	refused := false
	for i := 0; i < newLivePerMin+5 && !refused; i++ {
		c := dialWSFrom(t, srv, "/live", "198.51.100.10")
		c.json(map[string]any{"op": "mail", "s": secret(1000 + i)})
		_, b, _ := c.read(2 * time.Second)
		refused = strings.Contains(string(b), "too many")
		c.c.Close()
	}
	r.mu.Lock()
	known := len(r.known)
	r.mu.Unlock()
	if !refused || known != 0 {
		t.Fatalf("rate limit on new connections: %v; mailboxes remembered: %d", refused, known)
	}
	// The relay says it supports live mail.
	_, h := newTestRelay(t, false)
	if _, info := do(h, call{url: "/relay.php?a=info", body: "{}"}); info["mail"] != true {
		t.Fatalf("info: %v", info)
	}
}

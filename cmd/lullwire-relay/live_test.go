// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A minimal WebSocket client for tests (masks frames as browsers do).
type testWS struct {
	c    net.Conn
	br   *bufio.Reader
	pong bool // answer pings, as browsers do
}

func dialWS(t *testing.T, srv *httptest.Server, path string) *testWS {
	t.Helper()
	return dialWSFrom(t, srv, path, "")
}

// dialWSFrom connects as if forwarded for client address ip by a local proxy.
func dialWSFrom(t *testing.T, srv *httptest.Server, path, ip string) *testWS {
	t.Helper()
	extra := ""
	if ip != "" {
		extra = "X-Forwarded-For: " + ip + "\r\n"
	}
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 16)
	_, _ = rand.Read(k)
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n%s\r\n", path, base64.StdEncoding.EncodeToString(k), extra)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("handshake: %v %v", err, resp)
	}
	return &testWS{c: c, br: br}
}

func (w *testWS) write(op byte, data []byte, masked bool) {
	hdr := []byte{0x80 | op}
	m := byte(0)
	if masked {
		m = 0x80
	}
	switch n := len(data); {
	case n < 126:
		hdr = append(hdr, m|byte(n))
	case n < 1<<16:
		hdr = append(hdr, m|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, m|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	body := append([]byte(nil), data...)
	if masked {
		key := []byte{1, 2, 3, 4}
		hdr = append(hdr, key...)
		for i := range body {
			body[i] ^= key[i%4]
		}
	}
	_, _ = w.c.Write(append(hdr, body...))
}

func (w *testWS) json(v any) { b, _ := json.Marshal(v); w.write(0x1, b, true) }

// read returns the next data frame (skipping pings), or an error on close/timeout.
func (w *testWS) read(timeout time.Duration) (byte, []byte, error) {
	_ = w.c.SetReadDeadline(time.Now().Add(timeout))
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			return 0, nil, err
		}
		n := uint64(h[1] & 0x7f)
		if n == 126 {
			var e [2]byte
			_, _ = io.ReadFull(w.br, e[:])
			n = uint64(binary.BigEndian.Uint16(e[:]))
		} else if n == 127 {
			var e [8]byte
			_, _ = io.ReadFull(w.br, e[:])
			n = binary.BigEndian.Uint64(e[:])
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(w.br, p); err != nil {
			return 0, nil, err
		}
		switch h[0] & 0x0f {
		case 0x9:
			if w.pong {
				w.write(0xA, p, true)
			}
			continue
		case 0xA:
			continue
		case 0x8:
			return 0x8, nil, io.EOF
		}
		return h[0] & 0x0f, p, nil
	}
}

func (w *testWS) expectOp(t *testing.T, op string) map[string]any {
	t.Helper()
	_, b, err := w.read(3 * time.Second)
	var m map[string]any
	if err != nil || json.Unmarshal(b, &m) != nil || m["op"] != op {
		t.Fatalf("want %q, got %s (%v)", op, b, err)
	}
	return m
}

func liveServer(t *testing.T, code string) (*Relay, *httptest.Server) {
	r, h := newTestRelay(t, false)
	r.SetJoinCode(code)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return r, srv
}

func TestCallRoundTrip(t *testing.T) {
	_, srv := liveServer(t, "")
	room := secret(77)
	a := dialWS(t, srv, "/live")
	a.json(map[string]string{"op": "open", "room": room, "s": secret(1)})
	if m := a.expectOp(t, "ready"); m["peer"] != false {
		t.Fatalf("caller alone: %v", m)
	}
	b := dialWS(t, srv, "/live")
	b.json(map[string]string{"op": "join", "room": room})
	if m := b.expectOp(t, "ready"); m["peer"] != true {
		t.Fatalf("callee sees caller: %v", m)
	}
	a.expectOp(t, "peer")
	frame := bytes.Repeat([]byte{0xAB}, 40000) // an encrypted video frame
	a.write(0x2, frame, true)
	if op, got, err := b.read(3 * time.Second); err != nil || op != 0x2 || !bytes.Equal(got, frame) {
		t.Fatalf("frame not forwarded: op=%d len=%d err=%v", op, len(got), err)
	}
	b.write(0x2, []byte("reply"), true)
	if _, got, _ := a.read(3 * time.Second); string(got) != "reply" {
		t.Fatalf("reply: %q", got)
	}
	a.write(0x1, []byte(`{"op":"chatter"}`), true) // text after hello is not forwarded
	a.write(0x2, []byte("after"), true)
	if _, got, _ := b.read(3 * time.Second); string(got) != "after" {
		t.Fatalf("text frame leaked or order broken: %q", got)
	}
	// A third person can't join a 1:1 call.
	c := dialWS(t, srv, "/live")
	c.json(map[string]string{"op": "join", "room": room})
	if m := c.expectOp(t, "error"); m["msg"] != "call full" {
		t.Fatalf("third peer: %v", m)
	}
	// Hanging up tells the other side.
	b.write(0x8, nil, true)
	if m := a.expectOp(t, "peer"); m["here"] != false {
		t.Fatalf("leave not signalled: %v", m)
	}
}

func TestCallRejections(t *testing.T) {
	r, srv := liveServer(t, "secret code")
	// Joining a call that doesn't exist.
	x := dialWS(t, srv, "/live")
	x.json(map[string]string{"op": "join", "room": secret(5)})
	x.expectOp(t, "error")
	// Invite-only: only members may open calls.
	y := dialWS(t, srv, "/live")
	y.json(map[string]string{"op": "open", "room": secret(6), "s": secret(1)})
	if m := y.expectOp(t, "error"); m["msg"] != "join code required" {
		t.Fatalf("non-member opened a call: %v", m)
	}
	r.mu.Lock()
	r.members[boxOf(secret(1))] = true
	r.mu.Unlock()
	z := dialWS(t, srv, "/live")
	z.json(map[string]string{"op": "open", "room": secret(6), "s": secret(1)})
	z.expectOp(t, "ready")
	// Unmasked client frames break the protocol and close the connection.
	u := dialWS(t, srv, "/live")
	u.write(0x1, []byte(`{"op":"join","room":"`+secret(6)+`"}`), false)
	for {
		_, b, err := u.read(2 * time.Second)
		if err != nil {
			if err.Error() == "i/o timeout" {
				t.Fatal("connection stayed open after an unmasked frame")
			}
			break // closed, as required
		}
		if strings.Contains(string(b), `"ready"`) {
			t.Fatal("unmasked frame accepted")
		}
	}
	// Oversized messages close the connection.
	v := dialWS(t, srv, "/live")
	v.json(map[string]string{"op": "join", "room": secret(6)})
	v.expectOp(t, "ready")
	v.write(0x2, make([]byte, wsMaxMessage+1), true)
	if _, _, err := v.read(2 * time.Second); err == nil || err.Error() == "i/o timeout" {
		// either closed (EOF) or reset is fine; a timeout means it stayed open
		if err != nil && err.Error() == "i/o timeout" {
			t.Fatal("oversized message did not close the connection")
		}
	}
	// Plain HTTP to /live is refused.
	resp, err := http.Get(srv.URL + "/live")
	if err != nil || resp.StatusCode != 400 {
		t.Fatalf("plain GET /live: %v %v", err, resp)
	}
}

func TestRoomsPerClientLimit(t *testing.T) {
	_, srv := liveServer(t, "")
	ok := 0
	for i := 0; i < roomsPerClient+2; i++ {
		w := dialWS(t, srv, "/live")
		w.json(map[string]string{"op": "open", "room": secret(100 + i), "s": secret(1)})
		_, b, _ := w.read(2 * time.Second)
		if strings.Contains(string(b), `"ready"`) {
			ok++
		}
	}
	if ok != roomsPerClient {
		t.Fatalf("one client opened %d rooms, limit %d", ok, roomsPerClient)
	}
}

func TestBadHelloClosesQuickly(t *testing.T) {
	_, srv := liveServer(t, "")
	w := dialWS(t, srv, "/live")
	start := time.Now()
	_, _, err := w.read(15 * time.Second) // send nothing
	if err == nil && time.Since(start) > 12*time.Second {
		t.Fatal("silent connection kept open")
	}
	if time.Since(start) > 12*time.Second {
		t.Fatalf("silent connection lasted %v", time.Since(start))
	}
}

// A muted call sends no media, but answering pings must keep it connected.
func TestPongKeepsCallAlive(t *testing.T) {
	r, srv := liveServer(t, "")
	r.hub.idle, r.hub.ping = time.Second, 200*time.Millisecond
	room := secret(9)
	a := dialWS(t, srv, "/live")
	a.json(map[string]string{"op": "open", "room": room, "s": secret(1)})
	a.expectOp(t, "ready")
	b := dialWS(t, srv, "/live")
	b.json(map[string]string{"op": "join", "room": room})
	b.expectOp(t, "ready")
	a.expectOp(t, "peer")
	a.pong, b.pong = true, true // both only answer pings: nobody sends media for 3 s
	go func() { _, _, _ = a.read(10 * time.Second) }()
	if _, _, err := b.read(3 * time.Second); !strings.Contains(fmt.Sprint(err), "timeout") {
		t.Fatalf("muted side was disconnected: %v", err)
	}
	a.write(0x2, []byte("still here"), true)
	if op, p, err := b.read(2 * time.Second); err != nil || op != 0x2 || string(p) != "still here" {
		t.Fatalf("muted side lost the call: %v", err)
	}
}

// Control frames must not be fragmented and carry at most 125 bytes.
func TestControlFrameRules(t *testing.T) {
	_, srv := liveServer(t, "")
	for name, frame := range map[string][]byte{
		"fragmented ping": {0x09, 0x80, 0, 0, 0, 0},
		"long close":      append([]byte{0x88, 0x80 | 126, 0, 126, 0, 0, 0, 0}, make([]byte, 126)...),
	} {
		w := dialWS(t, srv, "/live")
		_, _ = w.c.Write(frame)
		if m := w.expectOp(t, "error"); m["msg"] != "bad hello" {
			t.Errorf("%s: got %v", name, m)
		}
	}
}

// Each client may sit in a limited number of rooms as the one who joins, too.
func TestJoinsPerClientLimit(t *testing.T) {
	_, srv := liveServer(t, "")
	var rooms []string
	for i := 0; i <= roomsPerClient; i++ {
		room := secret(300 + i)
		o := dialWSFrom(t, srv, "/live", fmt.Sprintf("203.0.113.%d", 10+i))
		o.json(map[string]string{"op": "open", "room": room, "s": secret(400 + i)})
		o.expectOp(t, "ready")
		rooms = append(rooms, room)
	}
	for i, room := range rooms {
		j := dialWSFrom(t, srv, "/live", "198.51.100.7")
		j.json(map[string]string{"op": "join", "room": room})
		if i < roomsPerClient {
			j.expectOp(t, "ready")
		} else if m := j.expectOp(t, "error"); m["msg"] != "busy" {
			t.Errorf("join beyond the limit: %v", m)
		}
	}
}

// A slow reader can't make the relay hold more than about wsOutBytes for it.
func TestOutQueueByteBudget(t *testing.T) {
	c := &wsConn{out: make(chan wsMsg, wsOutQueue), done: make(chan struct{})}
	frame := make([]byte, 200<<10)
	sent := 0
	for i := 0; i < 50; i++ {
		if c.send(0x2, frame) {
			sent++
		}
	}
	if q := c.queued.Load(); q > wsOutBytes || sent != wsOutBytes/len(frame) {
		t.Fatalf("queued %d bytes in %d frames", q, sent)
	}
	if !c.send(0x9, nil) {
		t.Fatal("control frames must still go out when media is being dropped")
	}
}

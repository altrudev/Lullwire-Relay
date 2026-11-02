// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Live calls. Two people meet in a "room" on the relay and the relay forwards
// their binary WebSocket messages to each other. Every message is already
// encrypted end to end by the app (a per-call key exchanged inside the chat), so
// the relay only sees opaque frames, sizes and timing — the same view it has of
// mail. To the network it is an ordinary WebSocket over the relay's HTTPS address.
//
// Protocol (first message is text JSON, within 10 s):
//
//	{"op":"open","room":<64 hex>,"s":<mailbox secret>}  caller creates the room
//	{"op":"join","room":<64 hex>}                        callee joins it
//	{"op":"mail","s":<mailbox secret>,"cover":bool}       live mail instead (see mail.go)
//
// The relay answers {"op":"ready","peer":bool} and later {"op":"peer","here":bool}
// as the other side arrives or leaves. After that, binary messages are forwarded.

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	wsGUID         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsMaxMessage   = 256 << 10       // largest frame the app sends (a video keyframe)
	wsOutQueue     = 96              // messages buffered towards a slow peer before dropping
	wsOutBytes     = 1 << 20         // ... and at most this many bytes of them
	wsBytesPerSec  = 600 << 10       // per connection, about 4.8 Mbit/s sustained
	wsBurst        = 2 << 20         // short bursts allowed above that
	roomLifetime   = 4 * time.Hour   // longest call
	roomAlone      = 2 * time.Minute // a room with one person waiting closes after this
	maxRooms       = 500             // rooms on the relay at once
	roomsPerClient = 4               // rooms one client (or one mailbox, behind Tor) may open, and may join
)

const (
	wsIdle = 60 * time.Second // no data and no pong: close
	wsPing = 20 * time.Second // how often the relay pings
)

type room struct {
	id      string
	peers   [2]*wsConn
	owner   string // rate-limit key of the creator
	created time.Time
}

type wsConn struct {
	conn   net.Conn
	br     *bufio.Reader
	out    chan wsMsg
	done   chan struct{}
	once   sync.Once
	tokens float64
	last   time.Time
	queued atomic.Int64 // bytes waiting in out
	ping   time.Duration
	maxMsg int // largest message accepted from the client
}

type wsMsg struct {
	op   byte
	data []byte
}

type liveHub struct {
	mu    sync.Mutex
	rooms map[string]*room
	owned map[string]int // rooms opened, per client
	in    map[string]int // rooms joined, per client
	idle  time.Duration  // wsIdle, shorter in tests
	ping  time.Duration  // wsPing, shorter in tests

	coverMin, coverSpread time.Duration // cover traffic timing, shorter in tests
}

func newLiveHub() *liveHub {
	return &liveHub{rooms: map[string]*room{}, owned: map[string]int{}, in: map[string]int{}, idle: wsIdle, ping: wsPing, coverMin: coverMin, coverSpread: coverSpread}
}

// ---- WebSocket framing (RFC 6455, server side) --------------------------------

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// upgrade completes the WebSocket handshake and takes over the connection.
func upgrade(w http.ResponseWriter, req *http.Request, ping time.Duration) (*wsConn, error) {
	key := req.Header.Get("Sec-WebSocket-Key")
	if req.Method != http.MethodGet || !headerHas(req.Header, "Connection", "upgrade") ||
		!headerHas(req.Header, "Upgrade", "websocket") || req.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, errors.New("not a websocket request")
	}
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 16 {
		return nil, errors.New("bad websocket key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("server cannot hijack")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{}) // server read/write timeouts no longer apply
	sum := sha1.Sum([]byte(key + wsGUID))
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		conn.Close()
		return nil, err
	}
	c := &wsConn{conn: conn, br: rw.Reader, out: make(chan wsMsg, wsOutQueue), done: make(chan struct{}),
		tokens: wsBurst, last: time.Now(), ping: ping, maxMsg: wsMaxMessage}
	go c.writer()
	return c, nil
}

// readMessage returns one complete (defragmented) data message, answering pings
// and closes on the way. Client frames must be masked, as the RFC requires.
func (c *wsConn) readMessage(timeout time.Duration) (op byte, data []byte, err error) {
	var msgOp byte
	var buf []byte
	deadline := time.Now().Add(timeout)
	for {
		_ = c.conn.SetReadDeadline(deadline)
		var h [2]byte
		if _, err = io.ReadFull(c.br, h[:]); err != nil {
			return 0, nil, err
		}
		fin, opcode, masked := h[0]&0x80 != 0, h[0]&0x0f, h[1]&0x80 != 0
		if h[0]&0x70 != 0 || !masked {
			return 0, nil, errors.New("protocol error")
		}
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var e [2]byte
			if _, err = io.ReadFull(c.br, e[:]); err != nil {
				return 0, nil, err
			}
			n = uint64(binary.BigEndian.Uint16(e[:]))
		case 127:
			var e [8]byte
			if _, err = io.ReadFull(c.br, e[:]); err != nil {
				return 0, nil, err
			}
			n = binary.BigEndian.Uint64(e[:])
		}
		if n > uint64(c.maxMsg) || uint64(len(buf))+n > uint64(c.maxMsg) {
			return 0, nil, errors.New("message too large")
		}
		var mask [4]byte
		if _, err = io.ReadFull(c.br, mask[:]); err != nil {
			return 0, nil, err
		}
		payload := make([]byte, n)
		if _, err = io.ReadFull(c.br, payload); err != nil {
			return 0, nil, err
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		if opcode >= 0x8 && (!fin || n > 125) { // control frames: never fragmented, at most 125 bytes
			return 0, nil, errors.New("protocol error")
		}
		switch opcode {
		case 0x8: // close
			c.send(0x8, nil)
			return 0, nil, io.EOF
		case 0x9: // ping
			c.send(0xA, payload)
			continue
		case 0xA: // pong: the peer is alive, even if it has nothing to send (muted, camera off)
			deadline = time.Now().Add(timeout)
			continue
		case 0x1, 0x2:
			if msgOp != 0 {
				return 0, nil, errors.New("protocol error")
			}
			msgOp = opcode
		case 0x0:
			if msgOp == 0 {
				return 0, nil, errors.New("protocol error")
			}
		default:
			return 0, nil, errors.New("protocol error")
		}
		buf = append(buf, payload...)
		if fin {
			return msgOp, buf, nil
		}
	}
}

// send queues a frame; when the peer can't keep up, frames are dropped rather
// than buffered without limit (the app recovers with the next keyframe).
func (c *wsConn) send(op byte, data []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	if c.queued.Add(int64(len(data))) > wsOutBytes && len(data) > 0 && op == 0x2 {
		c.queued.Add(-int64(len(data)))
		return false
	}
	select {
	case c.out <- wsMsg{op, data}:
		return true
	default:
		c.queued.Add(-int64(len(data)))
		return false
	}
}

// sendWait queues a frame, waiting up to timeout for room in the queue. Mail uses it:
// unlike media, an envelope is never dropped (it stays on the relay if the wait fails).
func (c *wsConn) sendWait(op byte, data []byte, timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	defer t.Stop()
	c.queued.Add(int64(len(data)))
	select {
	case c.out <- wsMsg{op, data}:
		return true
	case <-c.done:
	case <-t.C:
	}
	c.queued.Add(-int64(len(data)))
	return false
}

func (c *wsConn) sendJSON(v any) {
	b, _ := json.Marshal(v)
	c.send(0x1, b)
}

// pingAfter varies the ping interval by ±25%, so the connection has no fixed rhythm.
func pingAfter(d time.Duration) time.Duration {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return d*3/4 + time.Duration(binary.BigEndian.Uint16(b[:]))*d/2/65536
}

func (c *wsConn) writer() {
	ping := time.NewTimer(pingAfter(c.ping))
	defer ping.Stop()
	for {
		select {
		case m := <-c.out:
			err := c.writeFrame(m.op, m.data)
			c.queued.Add(-int64(len(m.data)))
			if err != nil || m.op == 0x8 {
				c.close()
				return
			}
		case <-ping.C:
			if c.writeFrame(0x9, nil) != nil {
				c.close()
				return
			}
			ping.Reset(pingAfter(c.ping))
		case <-c.done:
			return
		}
	}
}

func (c *wsConn) writeFrame(op byte, data []byte) error {
	hdr := []byte{0x80 | op}
	switch n := len(data); {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n < 1<<16:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.conn.Write(hdr); err != nil {
		return err
	}
	_, err := c.conn.Write(data)
	return err
}

// shutdown sends whatever is queued plus a close frame, then closes. It waits at
// most two seconds for a slow peer.
func (c *wsConn) shutdown() {
	if c.send(0x8, nil) {
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
		}
	}
	c.close()
}

func (c *wsConn) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}

// allowBytes is a token bucket that keeps one connection from flooding the relay.
func (c *wsConn) allowBytes(n int) bool {
	now := time.Now()
	c.tokens += now.Sub(c.last).Seconds() * wsBytesPerSec
	if c.tokens > wsBurst {
		c.tokens = wsBurst
	}
	c.last = now
	if c.tokens < float64(n) {
		return false
	}
	c.tokens -= float64(n)
	return true
}

// ---- rooms ----------------------------------------------------------------------

type liveHello struct {
	Op    string `json:"op"`
	Room  string `json:"room"`
	S     string `json:"s"`
	Cover bool   `json:"cover"`
}

func (r *Relay) serveLive(w http.ResponseWriter, req *http.Request) {
	c, err := upgrade(w, req, r.hub.ping)
	if err != nil {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		fail(w, 400, "websocket required")
		return
	}
	defer c.shutdown()
	op, msg, err := c.readMessage(10 * time.Second)
	var hello liveHello
	if err == nil && op == 0x1 && json.Unmarshal(msg, &hello) == nil && hello.Op == "mail" {
		r.serveMail(c, req, hello)
		return
	}
	if err != nil || op != 0x1 || !isHex(hello.Room, 64) {
		c.sendJSON(map[string]string{"op": "error", "msg": "bad hello"})
		return
	}
	key, distinct := r.clientKey(req)
	var rm *room
	var slot int
	switch hello.Op {
	case "open":
		if !isHex(hello.S, 64) || !r.isMember(sha256hex(hello.S)[:32]) {
			c.sendJSON(map[string]string{"op": "error", "msg": "join code required"})
			return
		}
		if !distinct && r.onion {
			key = "box|" + sha256hex(hello.S)[:32]
		}
		rm, err = r.hub.open(hello.Room, key, c)
	case "join":
		if !distinct { // behind Tor everyone shares one address; joining still needs the room's secret id
			key = ""
		}
		rm, slot, err = r.hub.join(hello.Room, key, c)
	default:
		err = errors.New("bad op")
	}
	if err != nil {
		c.sendJSON(map[string]string{"op": "error", "msg": err.Error()})
		return
	}
	defer r.hub.leave(rm, slot, c, hello.Op == "join", key)
	r.hub.mu.Lock()
	other := rm.peers[1-slot]
	r.hub.mu.Unlock()
	c.sendJSON(map[string]any{"op": "ready", "peer": other != nil})
	if other != nil {
		other.sendJSON(map[string]any{"op": "peer", "here": true})
	}

	// Close the room when it outlives a call, when someone waits alone too long,
	// or when the relay shuts down.
	go func() {
		alone := time.NewTimer(roomAlone)
		defer alone.Stop()
		life := time.NewTimer(time.Until(rm.created.Add(roomLifetime)))
		defer life.Stop()
		for {
			select {
			case <-alone.C:
				r.hub.mu.Lock()
				lonely := rm.peers[0] == nil || rm.peers[1] == nil
				r.hub.mu.Unlock()
				if lonely {
					c.close()
					return
				}
				alone.Reset(roomAlone) // check again: if the other person leaves, this room closes too
			case <-life.C:
				c.close()
				return
			case <-r.quit:
				c.send(0x8, nil)
				c.close()
				return
			case <-c.done:
				return
			}
		}
	}()

	for {
		op, data, err := c.readMessage(r.hub.idle)
		if err != nil {
			return
		}
		if !c.allowBytes(len(data)+2) || op != 0x2 { // every frame counts towards the bandwidth limit
			continue // only opaque binary frames are forwarded; over the limit they're dropped, like a congested network would
		}
		r.hub.mu.Lock()
		peer := rm.peers[1-slot]
		r.hub.mu.Unlock()
		if peer != nil {
			peer.send(0x2, data)
		}
	}
}

func (h *liveHub) open(id, owner string, c *wsConn) (*room, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.rooms[id]; exists {
		return nil, errors.New("room exists")
	}
	if len(h.rooms) >= maxRooms || h.owned[owner] >= roomsPerClient {
		return nil, errors.New("busy")
	}
	rm := &room{id: id, owner: owner, created: time.Now()}
	rm.peers[0] = c
	h.rooms[id] = rm
	h.owned[owner]++
	return rm, nil
}

func (h *liveHub) join(id, who string, c *wsConn) (*room, int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rm := h.rooms[id]
	if rm == nil {
		return nil, 0, errors.New("no such call")
	}
	if who != "" && h.in[who] >= roomsPerClient {
		return nil, 0, errors.New("busy")
	}
	for i := range rm.peers {
		if rm.peers[i] == nil {
			rm.peers[i] = c
			if who != "" {
				h.in[who]++
			}
			return rm, i, nil
		}
	}
	return nil, 0, errors.New("call full")
}

func (h *liveHub) leave(rm *room, slot int, c *wsConn, joined bool, who string) {
	h.mu.Lock()
	if joined && who != "" {
		if h.in[who]--; h.in[who] <= 0 {
			delete(h.in, who)
		}
	}
	if rm.peers[slot] == c {
		rm.peers[slot] = nil
	}
	other := rm.peers[1-slot]
	empty := rm.peers[0] == nil && rm.peers[1] == nil
	if empty {
		if h.rooms[rm.id] == rm {
			delete(h.rooms, rm.id)
		}
		if h.owned[rm.owner]--; h.owned[rm.owner] <= 0 {
			delete(h.owned, rm.owner)
		}
	}
	h.mu.Unlock()
	if other != nil {
		other.sendJSON(map[string]any{"op": "peer", "here": false})
	}
}

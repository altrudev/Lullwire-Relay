// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Live mail over the same WebSocket endpoint as calls (/live). The app keeps two
// connections: a mail connection, opened with its mailbox secret, that receives; and
// a send connection that carries nothing identifying, so deliveries are not tied to
// the sender's mailbox (sealed sender holds as it does for plain HTTP puts). To the
// network they are long-lived HTTPS connections to your server, like any chat app.
//
// Mail connection, after {"op":"mail","s":<secret>,"cover":bool} -> {"op":"ready","mail":true}:
//
//	relay -> app  text  {"op":"m","id":<22 hex>,"d":<base64 envelope>}   pending and new mail
//	app -> relay  text  {"op":"ack","ids":[...]}                          delete delivered mail
//	relay -> app  text  {"op":"n","id":<22 hex>,"d":<base64 noise>}       cover (if asked for); the app
//	                                                                      answers with a dummy ack
//
// Send connection, after {"op":"send"} -> {"op":"ready","send":true}:
//
//	(on an invite-only relay the hello carries "j": sha256("lullwire-join|" + join code),
//	so only people who were invited can open one; it doesn't say which mailbox is theirs)
//	app -> relay  binary 0x01 | request id (4) | box (16) | envelope      deliver to a mailbox here
//	app -> relay  binary 0x00 | request id (4) | 16 bytes | noise          cover traffic
//	relay -> app  text  {"op":"put","r":<id>,"ok":true} or {...,"e":<status>}  (cover gets "ok" too)
//
// Deliveries pass exactly the checks an HTTP put does. Cover traffic has the same
// shapes and sizes as the real thing, in both directions.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	sendMaxMessage = maxBlob + 64        // largest frame on a send connection
	mailMaxMessage = 64 << 10            // acknowledgements only
	mailInflight   = maxDeliver          // bytes sent but not yet acknowledged
	mailSendWait   = 20 * time.Second    // how long delivery waits for a slow reader
	newLivePerMin  = 60                  // new live connections per client per minute
	onionNewPerMin = 1200                // ... relay-wide behind Tor (clients look alike)
	coverMin       = 20 * time.Second    // cover traffic: one frame every 20–90 s
	coverSpread    = 70 * time.Second    //
	envMin, envVar = minBlob + 1024, 128 // size of a typical 1 KiB-class envelope (with its random tail)
)

// randInt returns a uniform-enough random number in [0, n).
func randInt(n int) int {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}

func (h *liveHub) coverDelay() time.Duration {
	return h.coverMin + time.Duration(randInt(int(h.coverSpread/time.Millisecond)))*time.Millisecond
}

// liveSlot admits one more live connection for a client (or, behind Tor, for a
// mailbox or the relay as a whole): a rate limit on new connections and a cap on
// open ones. It returns a release function, or nil when over a limit.
func (r *Relay) liveSlot(req *http.Request, kind, box string) func() {
	key, distinct := r.clientKey(req)
	limit, perMin, global := livePerKey, newLivePerMin, false
	if !distinct && r.onion { // behind Tor every client looks the same
		if box != "" {
			key, limit = "box|"+box, onionLivePerBox
		} else {
			key, limit, perMin = "send|onion", onionLiveTotal/2, onionNewPerMin
		}
		global = true
	}
	if !r.allow("live-new", kind+"|"+key, time.Minute, perMin) {
		return nil
	}
	// The relay-wide budget (Tor) is charged only for connections that passed every other check.
	if global && !r.allow("live-new-all", "onion", time.Minute, onionNewPerMin) {
		return nil
	}
	key = kind + "|" + key
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.live[key] >= limit || (r.onion && r.liveAll >= onionLiveTotal) {
		return nil
	}
	r.live[key]++
	r.liveAll++
	return func() {
		r.mu.Lock()
		if r.live[key]--; r.live[key] <= 0 {
			delete(r.live, key)
		}
		r.liveAll--
		r.mu.Unlock()
	}
}

func (r *Relay) serveMail(c *wsConn, req *http.Request, hello liveHello) {
	if !isHex(hello.S, 64) {
		c.sendJSON(map[string]string{"op": "error", "msg": "bad s"})
		return
	}
	box := sha256hex(hello.S)[:32]
	if !r.isMember(box) { // invite-only: nothing can arrive for it, so nothing to wait for
		c.sendJSON(map[string]string{"op": "error", "msg": "join code required"})
		return
	}
	release := r.liveSlot(req, "mail", box)
	if release == nil {
		c.sendJSON(map[string]string{"op": "error", "msg": "too many live connections"})
		return
	}
	defer release()
	// Like a long-poll: only a mailbox that exists counts as known, and the map is capped.
	if _, err := os.Stat(r.boxDir(box)); err == nil {
		r.mu.Lock()
		if _, ok := r.known[box]; ok || len(r.known) < maxCounters {
			r.known[box] = r.now()
		}
		r.mu.Unlock()
	}
	c.maxMsg = mailMaxMessage
	c.sendJSON(map[string]any{"op": "ready", "mail": true})

	var mu sync.Mutex
	inflight := map[string]int64{} // sent, not yet acknowledged
	var inflightBytes int64
	acked := make(chan struct{}, 1)
	go func() { // reader: acknowledgements (real, and dummy ones answering cover traffic)
		defer c.close()
		for {
			op, data, err := c.readMessage(r.hub.idle)
			if err != nil {
				return
			}
			if !c.allowBytes(len(data)+2) || op != 0x1 {
				continue
			}
			var m struct {
				Op  string `json:"op"`
				IDs []any  `json:"ids"`
			}
			if json.Unmarshal(data, &m) != nil || m.Op != "ack" {
				continue
			}
			r.remove(box, m.IDs)
			mu.Lock()
			for _, v := range m.IDs {
				if id, ok := v.(string); ok {
					inflightBytes -= inflight[id]
					delete(inflight, id)
				}
			}
			mu.Unlock()
			select {
			case acked <- struct{}{}:
			default:
			}
		}
	}()

	if hello.Cover { // noise shaped exactly like a delivered 1 KiB-class message
		go func() {
			t := time.NewTimer(r.hub.coverDelay())
			defer t.Stop()
			for {
				select {
				case <-t.C:
					pad := make([]byte, envMin+randInt(envVar))
					_, _ = rand.Read(pad)
					id := make([]byte, 11)
					_, _ = rand.Read(id)
					msg, _ := json.Marshal(map[string]string{"op": "n", "id": hex.EncodeToString(id), "d": base64.StdEncoding.EncodeToString(pad)})
					c.send(0x1, msg)
					t.Reset(r.hub.coverDelay())
				case <-c.done:
					return
				}
			}
		}()
	}

	for { // delivery: everything pending, then whatever arrives
		ch, done := r.waiter(box)
		ids, _ := r.pending(box)
		mu.Lock() // forget what was removed some other way (expired, acknowledged over HTTP)
		still := make(map[string]bool, len(ids))
		for _, id := range ids {
			still[id] = true
		}
		for id, n := range inflight {
			if !still[id] {
				inflightBytes -= n
				delete(inflight, id)
			}
		}
		mu.Unlock()
		for _, id := range ids {
			mu.Lock()
			_, sent := inflight[id]
			full := inflightBytes >= mailInflight
			mu.Unlock()
			if sent {
				continue
			}
			if full {
				break
			}
			b, err := os.ReadFile(filepath.Join(r.boxDir(box), id+".m"))
			if err != nil {
				continue
			}
			msg, _ := json.Marshal(map[string]string{"op": "m", "id": id, "d": base64.StdEncoding.EncodeToString(b)})
			if !c.sendWait(0x1, msg, mailSendWait) {
				done()
				return
			}
			mu.Lock()
			inflight[id] = int64(len(b))
			inflightBytes += int64(len(b))
			mu.Unlock()
		}
		select {
		case <-ch:
		case <-acked:
		case <-c.done:
			done()
			return
		case <-r.quit:
			done()
			c.send(0x8, nil)
			return
		}
		done()
	}
}

// serveSend carries deliveries (and cover traffic) for an app, without knowing who it is.
func (r *Relay) serveSend(c *wsConn, req *http.Request, hello liveHello) {
	if r.inviteOnly() && subtle.ConstantTimeCompare([]byte(hello.J), []byte(r.joinHash)) != 1 {
		c.sendJSON(map[string]string{"op": "error", "msg": "join code required"})
		return
	}
	release := r.liveSlot(req, "send", "")
	if release == nil {
		c.sendJSON(map[string]string{"op": "error", "msg": "too many live connections"})
		return
	}
	defer release()
	c.maxMsg = sendMaxMessage
	c.sendJSON(map[string]any{"op": "ready", "send": true})
	go func() {
		select {
		case <-r.quit:
			c.send(0x8, nil)
		case <-c.done:
		}
	}()
	for {
		op, data, err := c.readMessage(r.hub.idle)
		if err != nil {
			return
		}
		if op != 0x2 || len(data) < 21 || data[0] > 1 {
			continue
		}
		rid := binary.BigEndian.Uint32(data[1:5])
		answer := func(code int) {
			if code == 0 {
				c.sendJSON(map[string]any{"op": "put", "r": rid, "ok": true})
			} else {
				c.sendJSON(map[string]any{"op": "put", "r": rid, "e": code})
			}
		}
		if !c.allowBytes(len(data) + 2) {
			answer(429)
			continue
		}
		if data[0] == 0 { // cover traffic: answered like a delivery, then forgotten
			answer(0)
			continue
		}
		to, body := hex.EncodeToString(data[5:21]), data[21:]
		code, _ := r.admitPut(req, to)
		if code == 0 && (len(body) < minBlob || len(body) > maxBlob) {
			code = 413
		}
		if code == 0 { // the same cap on concurrent heavy work as HTTP deliveries
			select {
			case r.busy <- struct{}{}:
				code, _ = r.store(to, append([]byte(nil), body...))
				<-r.busy
			case <-time.After(5 * time.Second):
				code = 503
			}
		}
		answer(code)
	}
}

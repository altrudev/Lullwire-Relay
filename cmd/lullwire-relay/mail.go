// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Live mail over the same WebSocket endpoint as calls (/live). The app keeps one
// connection open; to the network it's one long-lived HTTPS connection to your
// server, much like any chat app. It replaces long-polling where it works.
//
// After {"op":"mail","s":<secret>,"cover":bool} the relay answers {"op":"ready","mail":true}, then:
//
//	relay -> app  text   {"op":"m","id":<22 hex>,"d":<base64 envelope>}    pending and new mail
//	app -> relay  text   {"op":"ack","ids":[...]}                           delete delivered mail
//	app -> relay  binary 0x01 | request id (4) | box (16) | envelope        deliver to a mailbox here
//	relay -> app  text   {"op":"put","r":<request id>,"ok":true} or {...,"e":<status>}
//	app -> relay  binary 0x00 | anything                                   cover traffic, dropped
//	relay -> app  text   {"op":"n","p":<random>}                             cover traffic (if asked for)
//
// Deliveries over the connection pass exactly the checks an HTTP put does.

import (
	"crypto/rand"
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
	mailMaxMessage = maxBlob + 64     // largest frame the app may send on a mail connection
	mailInflight   = maxDeliver       // bytes sent but not yet acknowledged
	mailSendWait   = 20 * time.Second // how long delivery waits for a slow reader
)

// Cover traffic: one frame every 20–90 s.
const coverMin, coverSpread = 20 * time.Second, 70 * time.Second

// randInt returns a uniform-enough random number in [0, n).
func randInt(n int) int {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}

func (h *liveHub) coverDelay() time.Duration {
	return h.coverMin + time.Duration(randInt(int(h.coverSpread/time.Millisecond)))*time.Millisecond
}

func (r *Relay) serveMail(c *wsConn, req *http.Request, hello liveHello) {
	if !isHex(hello.S, 64) {
		c.sendJSON(map[string]string{"op": "error", "msg": "bad s"})
		return
	}
	box := sha256hex(hello.S)[:32]
	// A live connection counts like a long-poll towards the per-client limit.
	key, distinct := r.clientKey(req)
	limit := livePerKey
	if !distinct && r.onion {
		key, limit = "box|"+box, onionLivePerBox
	}
	r.mu.Lock()
	over := r.live[key] >= limit || (r.onion && r.liveAll >= onionLiveTotal)
	if !over {
		r.live[key]++
		r.liveAll++
		r.known[box] = r.now()
	}
	r.mu.Unlock()
	if over {
		c.sendJSON(map[string]string{"op": "error", "msg": "too many live connections"})
		return
	}
	defer func() {
		r.mu.Lock()
		if r.live[key]--; r.live[key] <= 0 {
			delete(r.live, key)
		}
		r.liveAll--
		r.mu.Unlock()
	}()
	c.maxMsg = mailMaxMessage
	c.sendJSON(map[string]any{"op": "ready", "mail": true})

	var mu sync.Mutex
	inflight := map[string]int64{} // sent, not yet acknowledged
	var inflightBytes int64
	acked := make(chan struct{}, 1)
	go func() { // reader: acknowledgements, deliveries, cover traffic
		defer c.close()
		for {
			op, data, err := c.readMessage(r.hub.idle)
			if err != nil {
				return
			}
			if !c.allowBytes(len(data) + 2) {
				if op == 0x2 && len(data) >= 21 && data[0] == 1 {
					c.sendJSON(map[string]any{"op": "put", "r": binary.BigEndian.Uint32(data[1:5]), "e": 429})
				}
				continue
			}
			switch {
			case op == 0x1:
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
			case op == 0x2 && len(data) >= 21 && data[0] == 1:
				rid := binary.BigEndian.Uint32(data[1:5])
				to, body := hex.EncodeToString(data[5:21]), data[21:]
				code, _ := r.admitPut(req, to)
				if code == 0 && (len(body) < minBlob || len(body) > maxBlob) {
					code = 413
				}
				if code == 0 {
					code, _ = r.store(to, append([]byte(nil), body...))
				}
				if code == 0 {
					c.sendJSON(map[string]any{"op": "put", "r": rid, "ok": true})
				} else {
					c.sendJSON(map[string]any{"op": "put", "r": rid, "e": code})
				}
			}
			// binary frames starting with 0x00 are cover traffic: counted, then dropped
		}
	}()

	if hello.Cover { // noise shaped like a delivered message, at random times
		go func() {
			t := time.NewTimer(r.hub.coverDelay())
			defer t.Stop()
			for {
				select {
				case <-t.C:
					pad := make([]byte, 1100+randInt(150))
					_, _ = rand.Read(pad)
					c.sendJSON(map[string]string{"op": "n", "p": base64.StdEncoding.EncodeToString(pad)})
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

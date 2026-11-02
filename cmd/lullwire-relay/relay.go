// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The relay: a dumb mailbox for opaque encrypted blobs. It never sees plaintext,
// sender identity, names or contacts. The HTTP API and the on-disk layout match
// web/relay.php exactly, so the two relays are interchangeable and can share a
// data folder:
//
//	<data>/<box>/<id>.m        one pending envelope (id = 10-digit time + 12 hex)
//	<data>/recover/<l>.json     {"h": sha256(write token), "d": encrypted backup}
//
// Mailboxes: anyone holding a box id can drop a blob in; only the holder of the
// box's secret (box = first 32 hex of sha256(secret)) can read or delete.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Limits. Kept identical to relay.php.
const (
	maxBlob     = 524288  // bytes per blob
	maxSlot     = 786432  // bytes per recovery slot
	minBlob     = 93      // smallest valid envelope
	maxPerBox   = 500     // pending messages per mailbox
	maxBoxBytes = 8 << 20 // pending bytes per mailbox
	ttl         = 14 * 24 * time.Hour
	slotTTL     = 180 * 24 * time.Hour
	memberTTL   = 180 * 24 * time.Hour // invite-only memberships not renewed for this long expire
	maxMembers  = 20000                // members an invite-only relay keeps at most
	maxWait     = 20                   // seconds a live (long-poll) request may wait
	minFree     = 256 << 20            // refuse new data below this much free disk
	putsPerMin  = 120                  // per client
	slotsPerDay = 5                    // new recovery slots per client
	livePerKey  = 6                    // concurrent long-polls per client
	maxGet      = 100                  // envelopes returned per get
	maxAck      = 200                  // ids accepted per ack
	// Onion mode: Tor hides client addresses, so limits are keyed per mailbox
	// (and a few are global) instead of per client.
	onionPutsPerBoxMin = 120
	onionPutsTotalMin  = 3000
	onionSlotsPerDay   = 50
	onionLivePerBox    = 2
	onionLiveTotal     = 2000
	// Resource caps that protect small devices (phones, Pis).
	maxBusy     = 128     // requests reading or writing bodies at the same time
	maxDeliver  = 2 << 20 // raw bytes of mail returned per get; the app fetches the rest next
	maxCounters = 200000  // rate-limit windows tracked at once; beyond this, new ones are refused
)

// Relay holds configuration and in-memory state. Pending mail lives on disk;
// rate counters, live-connection slots and wake-up channels live in memory.
type Relay struct {
	data    string
	recover string
	trusted map[string]bool
	onion   bool
	now     func() time.Time

	mu      sync.Mutex
	waiters map[string][]chan struct{} // box -> goroutines waiting for mail
	live    map[string]int             // client or box key -> open long-polls
	liveAll int
	counts  map[string]counter   // rate window key -> count
	known   map[string]time.Time // boxes that have received mail -> last seen
	salt    [16]byte
	saltDay string
	stripes [256]sync.Mutex // per-mailbox write locks, striped by box id

	hub       *liveHub
	joinHash  string          // sha256 of the join code; empty = open relay
	members   map[string]bool // invite-only: mailboxes allowed on this relay
	memberDir string

	fwdHeader string        // header a trusted proxy uses to report the client address
	busy      chan struct{} // semaphore for body-heavy work
	quit      chan struct{} // closed on shutdown so waiting long-polls answer at once
	quitOnce  sync.Once
	torHint   sync.Once
}

type counter struct {
	n   int
	exp int64 // unix time after which the window is over
}

// NewRelay creates the data folders (mode 0700) and returns a ready relay.
func NewRelay(data string, trusted []string, onion bool) (*Relay, error) {
	data = filepath.Clean(data)
	r := &Relay{
		data: data, recover: filepath.Join(data, "recover"),
		trusted: map[string]bool{}, onion: onion, now: time.Now,
		waiters: map[string][]chan struct{}{}, live: map[string]int{},
		counts: map[string]counter{}, known: map[string]time.Time{},
		fwdHeader: "X-Forwarded-For", busy: make(chan struct{}, maxBusy), quit: make(chan struct{}),
		members: map[string]bool{}, memberDir: filepath.Join(data, "members"), hub: newLiveHub(),
	}
	for _, t := range trusted {
		if t = strings.TrimSpace(t); t != "" {
			r.trusted[t] = true
		}
	}
	for _, d := range []string{data, r.recover, r.memberDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	entries, _ := os.ReadDir(r.memberDir)
	for _, e := range entries {
		if isHex(e.Name(), 32) {
			r.members[e.Name()] = true
		}
	}
	return r, nil
}

// SetJoinCode turns on invite-only mode: only mailboxes registered with this
// code can receive mail, fetch it, store recovery backups or open calls.
func (r *Relay) SetJoinCode(code string) {
	if code = strings.TrimSpace(code); code != "" {
		r.joinHash = sha256hex("lullwire-join|" + code)
	}
}

func (r *Relay) inviteOnly() bool { return r.joinHash != "" }

func (r *Relay) isMember(box string) bool {
	if !r.inviteOnly() {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.members[box]
}

// ---- helpers ---------------------------------------------------------------

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isB64URL(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func okJSON(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]bool{"ok": true}) }

// atomicWrite writes via a temp file and rename, like the PHP relay.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- client identity and limits --------------------------------------------

func isLoopback(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// Close makes waiting long-polls answer immediately; used on shutdown.
func (r *Relay) Close() { r.quitOnce.Do(func() { close(r.quit) }) }

// SetForwardedHeader chooses the header a trusted proxy uses to report the
// client address: X-Forwarded-For (last hop) or e.g. CF-Connecting-IP.
func (r *Relay) SetForwardedHeader(h string) {
	if h = strings.TrimSpace(h); h != "" {
		r.fwdHeader = http.CanonicalHeaderKey(h)
	}
}

// clientIP returns the real client address. The forwarded header is trusted only
// from a configured proxy, or from a local proxy/tunnel when not in onion mode
// (behind Tor every connection is local and any header is client-supplied).
// distinct is false when the address can't tell clients apart.
func (r *Relay) clientIP(req *http.Request) (ip string, distinct bool) {
	remote, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		remote = req.RemoteAddr
	}
	local := isLoopback(remote)
	if !r.trusted[remote] && (!local || r.onion) {
		return remote, !local
	}
	if v := req.Header.Get(r.fwdHeader); v != "" {
		if r.fwdHeader == "X-Forwarded-For" {
			parts := strings.Split(v, ",")
			v = parts[len(parts)-1] // the hop our own proxy added
		}
		if v = strings.TrimSpace(v); net.ParseIP(v) != nil {
			return v, true
		}
	}
	if local && !r.onion {
		r.torHint.Do(func() {
			log.Printf("note: requests arrive from %s with no %s header; if this relay is behind Tor, restart it with -onion", remote, r.fwdHeader)
		})
	}
	return remote, !local
}

// acquire reserves a slot for body-heavy work. Short bursts queue for up to five
// seconds; after that the relay answers 503 so the client retries later.
func (r *Relay) acquire(w http.ResponseWriter) (release func(), ok bool) {
	select {
	case r.busy <- struct{}{}:
		return func() { <-r.busy }, true
	default:
	}
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case r.busy <- struct{}{}:
		return func() { <-r.busy }, true
	case <-t.C:
		w.Header().Set("Retry-After", "2")
		fail(w, 503, "busy")
		return nil, false
	}
}

// clientKey hashes the client address with a daily salt; nothing identifying is kept.
func (r *Relay) clientKey(req *http.Request) (string, bool) {
	ip, distinct := r.clientIP(req)
	r.mu.Lock()
	day := r.now().UTC().Format("20060102")
	if day != r.saltDay {
		_, _ = rand.Read(r.salt[:])
		r.saltDay = day
		r.counts = map[string]counter{} // old windows are meaningless with a new salt
	}
	salt := r.salt
	r.mu.Unlock()
	// One IPv6 subscriber usually holds a whole /64; treat it as one client.
	if p := net.ParseIP(ip); p != nil && p.To4() == nil {
		ip = p.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	h := sha256.Sum256(append(salt[:], ip...))
	return hex.EncodeToString(h[:12]), distinct
}

// allow counts one event in a fixed window and reports whether it is within max.
func (r *Relay) allow(name, key string, window time.Duration, max int) bool {
	secs := int64(window / time.Second)
	slot := r.now().Unix() / secs
	k := name + "|" + key + "|" + strconv.FormatInt(slot, 10)
	r.mu.Lock()
	defer r.mu.Unlock()
	c, seen := r.counts[k]
	if !seen && len(r.counts) >= maxCounters {
		return false // fail closed rather than grow without bound
	}
	c.n++
	c.exp = (slot + 1) * secs
	r.counts[k] = c
	return c.n <= max
}

// used reports how many events were counted in the current window, without counting one.
func (r *Relay) used(name, key string, window time.Duration) int {
	slot := r.now().Unix() / int64(window/time.Second)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[name+"|"+key+"|"+strconv.FormatInt(slot, 10)].n
}

func (r *Relay) diskOK() bool {
	free, ok := diskFree(r.data)
	return !ok || free > minFree
}

// lockBox serializes writes to one mailbox (or recovery slot). Locks are striped
// over a fixed array, so memory never grows with the number of mailboxes.
func (r *Relay) lockBox(key string) func() {
	h := sha256.Sum256([]byte(key))
	m := &r.stripes[h[0]]
	m.Lock()
	return m.Unlock
}

// ---- mailbox storage ---------------------------------------------------------

type envelope struct {
	ID string `json:"id"`
	D  string `json:"d"`
}

func (r *Relay) boxDir(box string) string { return filepath.Join(r.data, box) }

// pending lists a box's envelope ids in delivery order and their total size.
func (r *Relay) pending(box string) (ids []string, bytes int64) {
	entries, err := os.ReadDir(r.boxDir(box))
	if err != nil {
		return nil, 0
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".m") || !isHex(strings.TrimSuffix(name, ".m"), 22) {
			continue
		}
		ids = append(ids, strings.TrimSuffix(name, ".m"))
		if info, err := e.Info(); err == nil {
			bytes += info.Size()
		}
	}
	sort.Strings(ids)
	return ids, bytes
}

func (r *Relay) wake(box string) {
	r.mu.Lock()
	for _, ch := range r.waiters[box] {
		close(ch)
	}
	delete(r.waiters, box)
	r.mu.Unlock()
}

func (r *Relay) waiter(box string) (chan struct{}, func()) {
	ch := make(chan struct{})
	r.mu.Lock()
	r.waiters[box] = append(r.waiters[box], ch)
	r.mu.Unlock()
	return ch, func() {
		r.mu.Lock()
		list := r.waiters[box]
		for i, c := range list {
			if c == ch {
				r.waiters[box] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(r.waiters[box]) == 0 {
			delete(r.waiters, box)
		}
		r.mu.Unlock()
	}
}

// ---- HTTP API ----------------------------------------------------------------

func setRelayHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
}

// readJSON reads at most max bytes of a JSON object; anything else yields an empty map.
func readJSON(req *http.Request, max int64) map[string]any {
	b, err := io.ReadAll(io.LimitReader(req.Body, max))
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil || m == nil {
		return map[string]any{}
	}
	return m
}

func strArg(m map[string]any, k string, n int) (string, bool) {
	s, ok := m[k].(string)
	return s, ok && isHex(s, n)
}

func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	setRelayHeaders(w)
	if req.Method == http.MethodOptions {
		return
	}
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	q := req.URL.Query()
	switch a := q.Get("a"); a {
	case "info": // what the app needs to know before signing up
		writeJSON(w, http.StatusOK, map[string]any{"v": 2, "invite": r.inviteOnly(), "calls": true})
	case "put":
		r.put(w, req, q.Get("box"))
	case "rput", "rget", "rdel":
		r.slot(w, req, a)
	default:
		in := readJSON(req, 16384)
		s, ok := strArg(in, "s", 64)
		if !ok {
			fail(w, 400, "bad s")
			return
		}
		box := sha256hex(s)[:32]
		if a == "join" {
			r.join(w, req, box, in)
			return
		}
		// Fetching from a mailbox that hasn't joined is harmless: nothing can be delivered
		// to it, so it simply stays empty. Sending to it is what invite-only mode refuses.
		switch a {
		case "get":
			r.get(w, req, box, q.Get("wait"))
		case "ack":
			r.ack(w, box, in)
		default:
			fail(w, 400, "bad action")
		}
	}
}

// join registers a mailbox on an invite-only relay. On an open relay it is a no-op.
func (r *Relay) join(w http.ResponseWriter, req *http.Request, box string, in map[string]any) {
	if !r.inviteOnly() {
		okJSON(w)
		return
	}
	key, distinct := r.clientKey(req)
	code, _ := in["code"].(string)
	got := sha256hex("lullwire-join|" + strings.TrimSpace(code))
	if subtle.ConstantTimeCompare([]byte(got), []byte(r.joinHash)) != 1 {
		// Wrong codes are limited. The limits never apply to the right code, so
		// guessing can't lock out people who have it.
		if r.used("join", key, time.Hour) >= 10 || r.used("join-all", "all", time.Minute) >= 60 {
			fail(w, 429, "too many attempts")
			return
		}
		r.allow("join", key, time.Hour, 10)
		r.allow("join-all", "all", time.Minute, 60)
		fail(w, 403, "wrong join code")
		return
	}
	r.mu.Lock()
	known, count := r.members[box], len(r.members)
	r.mu.Unlock()
	if known { // already a member: just note that it's still in use
		now := r.now()
		_ = os.Chtimes(filepath.Join(r.memberDir, box), now, now)
		okJSON(w)
		return
	}
	// The code travels in invites and invites get forwarded, so new memberships are
	// limited too: per client (not behind Tor, where everyone shares one address),
	// relay-wide, in total, and never when the disk is nearly full.
	if (distinct && !r.allow("join-new", key, time.Hour, 30)) || !r.allow("join-new-all", "all", time.Hour, 600) {
		fail(w, 429, "too many new members, try later")
		return
	}
	if count >= maxMembers || !r.diskOK() {
		fail(w, 507, "relay full")
		return
	}
	if err := os.WriteFile(filepath.Join(r.memberDir, box), nil, 0o600); err != nil {
		fail(w, 500, "storage error")
		return
	}
	r.mu.Lock()
	r.members[box] = true
	r.mu.Unlock()
	okJSON(w)
}

func (r *Relay) put(w http.ResponseWriter, req *http.Request, box string) {
	if len(req.URL.Query()["box"]) != 1 || !isHex(box, 32) {
		fail(w, 400, "bad box")
		return
	}
	if !r.isMember(box) { // invite-only: no mailbox by that name here
		fail(w, 404, "unknown box")
		return
	}
	key, distinct := r.clientKey(req)
	var allowed bool
	if !distinct && r.onion {
		allowed = r.allow("put-all", "onion", time.Minute, onionPutsTotalMin) &&
			r.allow("put-box", box, time.Minute, onionPutsPerBoxMin)
	} else {
		allowed = r.allow("put", key, time.Minute, putsPerMin)
	}
	if !allowed {
		fail(w, 429, "slow down")
		return
	}
	if !r.diskOK() {
		fail(w, 507, "relay storage full")
		return
	}
	release, ok := r.acquire(w)
	if !ok {
		return
	}
	defer release()
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBlob+1))
	if err != nil || len(body) < minBlob || len(body) > maxBlob {
		fail(w, 413, "bad size")
		return
	}
	unlock := r.lockBox(box)
	ids, bytes := r.pending(box)
	if len(ids) >= maxPerBox || bytes+int64(len(body)) > maxBoxBytes {
		unlock()
		fail(w, 429, "box full")
		return
	}
	if err := os.MkdirAll(r.boxDir(box), 0o700); err != nil {
		unlock()
		fail(w, 500, "storage error")
		return
	}
	id := fmt.Sprintf("%010d", r.now().Unix()) + randHex(6)
	err = atomicWrite(filepath.Join(r.boxDir(box), id+".m"), body)
	unlock()
	if err != nil {
		fail(w, 500, "storage error")
		return
	}
	r.mu.Lock()
	r.known[box] = r.now()
	r.mu.Unlock()
	r.wake(box)
	okJSON(w)
}

func (r *Relay) get(w http.ResponseWriter, req *http.Request, box, waitArg string) {
	wait := leadingInt(waitArg) // like PHP's (int) cast: "5abc" -> 5
	wait = max(0, min(maxWait, wait))
	if wait > 0 {
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
		}
		r.mu.Unlock()
		if over { // too many live connections from this client: tell it to back off
			w.Header().Set("Retry-After", "3")
			fail(w, 429, "too many live connections")
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
		// A mailbox that has never received mail: answer after a short pause instead of
		// holding a connection open for whoever made up the secret.
		_, err := os.Stat(r.boxDir(box))
		r.mu.Lock()
		if err == nil {
			r.known[box] = r.now()
		}
		_, isKnown := r.known[box]
		r.mu.Unlock()
		if !isKnown {
			wait = min(wait, 3)
		}
	}
	deadline := time.NewTimer(time.Duration(wait) * time.Second)
	defer deadline.Stop()
	for {
		ch, done := r.waiter(box) // register before checking, so a put in between still wakes us
		ids, _ := r.pending(box)
		if len(ids) > 0 || wait == 0 {
			done()
			r.deliver(w, box, ids)
			return
		}
		select {
		case <-ch:
			done()
		case <-deadline.C:
			done()
			r.deliver(w, box, nil)
			return
		case <-r.quit: // shutting down: answer now so the client reconnects elsewhere
			done()
			r.deliver(w, box, nil)
			return
		case <-req.Context().Done():
			done()
			return
		}
	}
}

// deliver streams pending mail as a JSON array without holding it in memory.
// It stops after maxGet envelopes or about maxDeliver bytes; the app asks again
// for the rest straight after acknowledging these.
func (r *Relay) deliver(w http.ResponseWriter, box string, ids []string) {
	w.Header().Set("Content-Type", "application/json")
	if len(ids) == 0 {
		_, _ = io.WriteString(w, "[]\n")
		return
	}
	release, ok := r.acquire(w)
	if !ok {
		return
	}
	defer release()
	_, _ = io.WriteString(w, "[")
	sent, total := 0, int64(0)
	for _, id := range ids {
		f, err := os.Open(filepath.Join(r.boxDir(box), id+".m"))
		if err != nil {
			continue
		}
		info, err := f.Stat()
		if err != nil || (sent > 0 && total+info.Size() > maxDeliver) {
			f.Close()
			break
		}
		if sent > 0 {
			_, _ = io.WriteString(w, ",")
		}
		// ids are 22 hex characters and base64 needs no JSON escaping.
		_, _ = io.WriteString(w, `{"id":"`+id+`","d":"`)
		enc := base64.NewEncoder(base64.StdEncoding, w)
		_, _ = io.Copy(enc, f)
		_ = enc.Close()
		f.Close()
		_, _ = io.WriteString(w, `"}`)
		sent++
		total += info.Size()
		if sent >= maxGet {
			break
		}
	}
	_, _ = io.WriteString(w, "]\n")
}

// leadingInt parses leading decimal digits, ignoring the rest (PHP-style).
func leadingInt(s string) int {
	n := 0
	for i := 0; i < len(s) && i < 9 && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func (r *Relay) ack(w http.ResponseWriter, box string, in map[string]any) {
	ids, _ := in["ids"].([]any)
	if len(ids) > maxAck {
		ids = ids[:maxAck]
	}
	for _, v := range ids {
		if id, ok := v.(string); ok && isHex(id, 22) {
			_ = os.Remove(filepath.Join(r.boxDir(box), id+".m"))
		}
	}
	okJSON(w)
}

type slotRecord struct {
	H string `json:"h"`
	D string `json:"d"`
}

func (r *Relay) slot(w http.ResponseWriter, req *http.Request, a string) {
	release, ok := r.acquire(w)
	if !ok {
		return
	}
	in := readJSON(req, maxSlot+4096)
	release() // the body is read; locks below are held only briefly
	l, ok := strArg(in, "l", 32)
	if !ok {
		fail(w, 400, "bad l")
		return
	}
	path := filepath.Join(r.recover, l+".json")
	if a != "rget" { // reads need no lock: slots are replaced by atomic rename
		unlock := r.lockBox("recover|" + l)
		defer unlock()
	}
	var rec slotRecord
	raw, err := os.ReadFile(path)
	exists := err == nil
	if exists {
		_ = json.Unmarshal(raw, &rec)
	}
	if a == "rget" {
		if !exists {
			n, _ := rand.Int(rand.Reader, big.NewInt(100))
			time.Sleep(time.Duration(50+n.Int64()) * time.Millisecond) // blur hit/miss timing
			fail(w, 404, "none")
			return
		}
		now := r.now()
		_ = os.Chtimes(path, now, now) // keep active slots from expiring
		writeJSON(w, http.StatusOK, map[string]string{"d": rec.D})
		return
	}
	t, ok := strArg(in, "t", 64)
	if !ok {
		fail(w, 400, "bad t")
		return
	}
	th := sha256hex(t)
	if exists && subtle.ConstantTimeCompare([]byte(rec.H), []byte(th)) != 1 {
		fail(w, 403, "wrong token")
		return
	}
	if a == "rdel" {
		_ = os.Remove(path)
		okJSON(w)
		return
	}
	d, _ := in["d"].(string)
	if len(d) > maxSlot || !isB64URL(d) {
		fail(w, 400, "bad data")
		return
	}
	if r.inviteOnly() {
		s, ok := strArg(in, "s", 64)
		if !ok || !r.isMember(sha256hex(s)[:32]) {
			fail(w, 403, "join code required")
			return
		}
	}
	if !exists {
		key, distinct := r.clientKey(req)
		allowed := r.allow("slot", key, 24*time.Hour, slotsPerDay)
		if !distinct && r.onion {
			allowed = r.allow("slot-all", "onion", 24*time.Hour, onionSlotsPerDay)
		}
		if !allowed {
			fail(w, 429, "too many new slots today")
			return
		}
	}
	if !r.diskOK() {
		fail(w, 507, "relay storage full")
		return
	}
	b, _ := json.Marshal(slotRecord{H: th, D: d})
	if err := atomicWrite(path, b); err != nil {
		fail(w, 500, "storage error")
		return
	}
	okJSON(w)
}

// ---- housekeeping --------------------------------------------------------------

// Sweep deletes expired mail, stale recovery slots, leftover temp files and old
// rate-limit windows. It runs hourly.
func (r *Relay) Sweep() {
	now := r.now()
	entries, _ := os.ReadDir(r.data)
	for _, e := range entries {
		if !e.IsDir() || !isHex(e.Name(), 32) {
			continue
		}
		dir := filepath.Join(r.data, e.Name())
		files, _ := os.ReadDir(dir)
		for _, f := range files {
			info, err := f.Info()
			if err != nil {
				continue
			}
			age := now.Sub(info.ModTime())
			if (strings.HasSuffix(f.Name(), ".m") && age > ttl) || (strings.HasSuffix(f.Name(), ".tmp") && age > 10*time.Minute) {
				_ = os.Remove(filepath.Join(dir, f.Name()))
			}
		}
		unlock := r.lockBox(e.Name()) // not while a put is creating this folder
		_ = os.Remove(dir)            // only succeeds when empty
		unlock()
	}
	// Memberships nobody has renewed for memberTTL expire (the app renews its own on
	// every start; temporary mailboxes from device moves simply lapse).
	if r.inviteOnly() {
		members, _ := os.ReadDir(r.memberDir)
		for _, f := range members {
			info, err := f.Info()
			if err != nil || now.Sub(info.ModTime()) <= memberTTL {
				continue
			}
			if os.Remove(filepath.Join(r.memberDir, f.Name())) == nil {
				r.mu.Lock()
				delete(r.members, f.Name())
				r.mu.Unlock()
			}
		}
	}
	slots, _ := os.ReadDir(r.recover)
	for _, f := range slots {
		info, err := f.Info()
		if err != nil {
			continue
		}
		limit := slotTTL
		if strings.HasSuffix(f.Name(), ".tmp") {
			limit = 10 * time.Minute
		}
		if now.Sub(info.ModTime()) > limit {
			_ = os.Remove(filepath.Join(r.recover, f.Name()))
		}
	}
	r.mu.Lock()
	cur := now.Unix()
	for k, c := range r.counts {
		if c.exp < cur {
			delete(r.counts, k)
		}
	}
	for box, seen := range r.known {
		if now.Sub(seen) > ttl {
			delete(r.known, box)
		}
	}
	r.mu.Unlock()
}

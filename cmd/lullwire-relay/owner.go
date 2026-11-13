// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The relay owner: one device that may see how the relay is used, remove members,
// make single-use invites, switch off the shared join code and restart the relay.
//
// Claiming: on the server, "lullwire-relay -owner-code" (with the relay's usual
// settings) writes a one-time code, valid 30 minutes. The owner's app generates a
// random 32-byte owner token and sends {"op":"claim","code":…,"h":sha256("lullwire-owner|"+token)}.
// The relay keeps only that hash; the token never leaves the device except as the
// "o" field of later owner requests, over HTTPS. A new code replaces the owner (a
// lost phone is recovered from the server, never through the app).
//
// What the owner sees is what the relay already has: counts, sizes and times. Members
// appear under an alias, sha256("lullwire-member|"+mailbox)[:12]; the app matches
// aliases against its own contacts on the device, so names never reach the relay.
//
// Single-use invites replace the shared code as the way in. Membership and sending
// are now separate: a member key (handed to members when they join or renew) proves
// membership on the anonymous send connection, and removing someone rotates it.
//
// Files in the data folder:
//
//	owner.json          {"h": sha256 of the owner token, "since": unix}
//	owner-claim.json    {"h": sha256("lullwire-claim|"+code), "exp": unix}   one-time, 30 minutes
//	member.key          the member key (hex)
//	settings.json       {"shared_off": bool}
//	invites/<id>.json   {"c": created, "e": expires}; id = sha256("lullwire-invite|"+code)[:32]
//	stats.json          {"days": [...]}  daily counts, last 30 days
//	members/<box>       {"j": joined}; the file's time is the last activity

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	claimTTL       = 30 * time.Minute
	inviteDays     = 7    // default lifetime of a single-use invite
	maxInviteDays  = 30   //
	maxInvites     = 1000 // outstanding single-use invites
	statsDays      = 30   // daily counts kept
	ownerFailsHour = 20   // wrong owner tokens per client per hour
	ownerFailsAll  = 200  // ... relay-wide
	claimFailsHour = 10   // wrong claim codes per client per hour
	claimFailsAll  = 50   // ... relay-wide
)

// dayStats are the counts the owner sees per day (UTC).
type dayStats struct {
	D      string `json:"d"`      // 2026-11-13
	In     int    `json:"in"`     // envelopes stored for members
	Bytes  int64  `json:"bytes"`  // their size
	Active int    `json:"active"` // mailboxes that fetched mail or renewed
	Joins  int    `json:"joins"`  // new members
	Calls  int    `json:"calls"`  // call rooms opened
}

func alias(box string) string { return sha256hex("lullwire-member|" + box)[:12] }

func inviteID(code string) string {
	return sha256hex("lullwire-invite|" + strings.TrimSpace(code))[:32]
}

// writeOwnerClaim stores a one-time claim code for -owner-code.
func writeOwnerClaim(data, code string, now time.Time) error {
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]any{"h": sha256hex("lullwire-claim|" + code), "exp": now.Add(claimTTL).Unix()})
	return atomicWrite(filepath.Join(data, "owner-claim.json"), b)
}

// loadOwnerState reads the owner, member key, settings and stats; called by NewRelay.
func (r *Relay) loadOwnerState() error {
	var o struct{ H string }
	if b, err := os.ReadFile(filepath.Join(r.data, "owner.json")); err == nil && json.Unmarshal(b, &o) == nil && isHex(o.H, 64) {
		r.ownerHash = o.H
	}
	keyPath := filepath.Join(r.data, "member.key")
	if b, err := os.ReadFile(keyPath); err == nil && isHex(strings.TrimSpace(string(b)), 64) {
		r.memberKey = strings.TrimSpace(string(b))
	} else if err := r.rotateMemberKeyLocked(); err != nil {
		return err
	}
	var s struct {
		SharedOff bool `json:"shared_off"`
	}
	if b, err := os.ReadFile(filepath.Join(r.data, "settings.json")); err == nil && json.Unmarshal(b, &s) == nil {
		r.sharedOff = s.SharedOff
	}
	var st struct{ Days []dayStats }
	if b, err := os.ReadFile(filepath.Join(r.data, "stats.json")); err == nil && json.Unmarshal(b, &st) == nil {
		r.days = st.Days
	}
	return os.MkdirAll(r.inviteDir, 0o700)
}

// rotateMemberKeyLocked makes a new member key; the caller holds r.mu (or is NewRelay).
func (r *Relay) rotateMemberKeyLocked() error {
	k := randHex(32)
	if err := atomicWrite(filepath.Join(r.data, "member.key"), []byte(k)); err != nil {
		return err
	}
	r.memberKey = k
	return nil
}

// memberProof is what a send connection must present: sha256("lullwire-member|"+key).
func (r *Relay) memberProof() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return sha256hex("lullwire-member|" + r.memberKey)
}

// sendAllowed checks the proof on a send connection: the member key, or (LEGACY, for
// apps before 0.8 and while the shared code is on) the shared join code's hash.
func (r *Relay) sendAllowed(j string) bool {
	if !r.inviteOnly() {
		return true
	}
	r.mu.Lock()
	mk, off := sha256hex("lullwire-member|"+r.memberKey), r.sharedOff
	r.mu.Unlock()
	if subtle.ConstantTimeCompare([]byte(j), []byte(mk)) == 1 {
		return true
	}
	return !off && subtle.ConstantTimeCompare([]byte(j), []byte(r.joinHash)) == 1
}

// sharedCodeOK reports whether code is the shared join code and it still admits people.
func (r *Relay) sharedCodeOK(code string) bool {
	r.mu.Lock()
	off := r.sharedOff
	r.mu.Unlock()
	got := sha256hex("lullwire-join|" + strings.TrimSpace(code))
	return subtle.ConstantTimeCompare([]byte(got), []byte(r.joinHash)) == 1 && !off
}

// inviteValid reports whether code is an unexpired single-use invite, without using it.
func (r *Relay) inviteValid(code string) bool {
	if strings.TrimSpace(code) == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(r.inviteDir, inviteID(code)+".json"))
	var inv struct{ E int64 }
	return err == nil && json.Unmarshal(b, &inv) == nil && r.now().Unix() < inv.E
}

// useInvite consumes a single-use invite. Removing the file is the claim: of two
// people racing with the same code, exactly one succeeds.
func (r *Relay) useInvite(code string) bool {
	return r.inviteValid(code) && os.Remove(filepath.Join(r.inviteDir, inviteID(code)+".json")) == nil
}

// today returns the counts for the current UTC day, starting a new day when needed.
// The caller holds r.mu.
func (r *Relay) todayLocked() *dayStats {
	d := r.now().UTC().Format("2006-01-02")
	if n := len(r.days); n == 0 || r.days[n-1].D != d {
		r.days = append(r.days, dayStats{D: d})
		if len(r.days) > statsDays {
			r.days = append([]dayStats(nil), r.days[len(r.days)-statsDays:]...)
		}
		r.activeToday = map[string]bool{}
	}
	return &r.days[len(r.days)-1]
}

// touch notes that a member's app was active: for last-seen times and daily counts.
func (r *Relay) touch(box string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inviteOnly() && !r.members[box] {
		return
	}
	if _, ok := r.seen[box]; ok || len(r.seen) < maxCounters {
		r.seen[box] = r.now()
	}
	d := r.todayLocked()
	if !r.activeToday[box] && len(r.activeToday) < maxCounters {
		r.activeToday[box] = true
		d.Active++
	}
}

func (r *Relay) countDelivery(n int) {
	r.mu.Lock()
	d := r.todayLocked()
	d.In++
	d.Bytes += int64(n)
	r.mu.Unlock()
}

func (r *Relay) countJoin() { r.mu.Lock(); r.todayLocked().Joins++; r.mu.Unlock() }
func (r *Relay) countCall() { r.mu.Lock(); r.todayLocked().Calls++; r.mu.Unlock() }

// saveStats writes the daily counts, and moves last-seen times onto the member files
// (at most once an hour each), so they survive a restart and renew the membership.
func (r *Relay) saveStats() {
	r.mu.Lock()
	r.todayLocked()
	b, _ := json.Marshal(map[string]any{"days": r.days})
	type seenAt struct {
		box string
		at  time.Time
	}
	var flush []seenAt
	for box, at := range r.seen {
		if r.members[box] {
			flush = append(flush, seenAt{box, at})
		}
	}
	r.mu.Unlock()
	_ = atomicWrite(filepath.Join(r.data, "stats.json"), b)
	for _, s := range flush {
		p := filepath.Join(r.memberDir, s.box)
		if info, err := os.Stat(p); err == nil && s.at.Sub(info.ModTime()) > time.Hour {
			_ = os.Chtimes(p, s.at, s.at)
		}
	}
}

// sweepOwner expires invites and an unused claim code.
func (r *Relay) sweepOwner() {
	now := r.now().Unix()
	entries, _ := os.ReadDir(r.inviteDir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(r.inviteDir, e.Name()))
		var inv struct{ E int64 }
		if err != nil || json.Unmarshal(b, &inv) != nil || inv.E <= now {
			_ = os.Remove(filepath.Join(r.inviteDir, e.Name()))
		}
	}
	var c struct{ Exp int64 }
	p := filepath.Join(r.data, "owner-claim.json")
	if b, err := os.ReadFile(p); err == nil && (json.Unmarshal(b, &c) != nil || c.Exp <= now) {
		_ = os.Remove(p)
	}
	r.saveStats()
}

// trackConn registers a live connection so the owner can count it and removal can
// close it. box is "" for send connections. The returned func unregisters it.
func (r *Relay) trackConn(box string, c *wsConn) func() {
	r.mu.Lock()
	if box == "" {
		r.sendConns[c] = true
	} else {
		if r.mailConns[box] == nil {
			r.mailConns[box] = map[*wsConn]bool{}
		}
		r.mailConns[box][c] = true
	}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		if box == "" {
			delete(r.sendConns, c)
		} else if m := r.mailConns[box]; m != nil {
			delete(m, c)
			if len(m) == 0 {
				delete(r.mailConns, box)
			}
		}
		r.mu.Unlock()
	}
}

// closeConns ends connections; done outside r.mu.
func closeConns(cs []*wsConn) {
	for _, c := range cs {
		c.send(0x8, nil)
		c.close()
	}
}

// ---- the owner API: POST ?a=owner ---------------------------------------------

func (r *Relay) owner(w http.ResponseWriter, req *http.Request) {
	release, ok := r.acquire(w)
	if !ok {
		return
	}
	in := readJSON(req, 16384)
	release()
	key, _ := r.clientKey(req)
	op, _ := in["op"].(string)
	if op == "claim" {
		r.ownerClaim(w, key, in)
		return
	}
	tok, ok := strArg(in, "o", 64)
	r.mu.Lock()
	h := r.ownerHash
	r.mu.Unlock()
	if !ok || h == "" || subtle.ConstantTimeCompare([]byte(sha256hex("lullwire-owner|"+tok)), []byte(h)) != 1 {
		// The right token is never limited, so guessing can't lock the owner out.
		if r.used("owner-bad", key, time.Hour) >= ownerFailsHour || r.used("owner-bad-all", "all", time.Hour) >= ownerFailsAll {
			fail(w, 429, "too many attempts")
			return
		}
		r.allow("owner-bad", key, time.Hour, ownerFailsHour)
		r.allow("owner-bad-all", "all", time.Hour, ownerFailsAll)
		fail(w, 403, "not the owner") // the same whether or not the relay has an owner yet
		return
	}
	switch op {
	case "status":
		writeJSON(w, http.StatusOK, r.ownerStatus())
	case "members":
		writeJSON(w, http.StatusOK, map[string]any{"members": r.memberList()})
	case "remove":
		id, _ := in["id"].(string)
		if !isHex(id, 12) {
			fail(w, 400, "bad id")
			return
		}
		if !r.removeMember(id) {
			fail(w, 404, "no such member")
			return
		}
		okJSON(w)
	case "invite":
		days := inviteDays
		if d, ok := in["days"].(float64); ok && d >= 1 && d <= maxInviteDays {
			days = int(d)
		}
		inv, err := r.newInvite(days)
		if err != nil {
			fail(w, 507, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, inv)
	case "invites":
		writeJSON(w, http.StatusOK, map[string]any{"invites": r.inviteList()})
	case "revoke":
		id, _ := in["id"].(string)
		if !isHex(id, 32) {
			fail(w, 400, "bad id")
			return
		}
		_ = os.Remove(filepath.Join(r.inviteDir, id+".json"))
		okJSON(w)
	case "shared":
		on, ok := in["on"].(bool)
		if !ok || !r.inviteOnly() {
			fail(w, 400, "this relay has no shared join code")
			return
		}
		if err := r.setShared(on); err != nil {
			fail(w, 500, "storage error")
			return
		}
		okJSON(w)
	case "restart":
		if r.restart == nil {
			fail(w, 501, "restart is not available on this system; restart the relay on the server")
			return
		}
		log.Print("owner: restart requested")
		okJSON(w)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() { time.Sleep(300 * time.Millisecond); r.restart() }()
	default:
		fail(w, 400, "bad op")
	}
}

func (r *Relay) ownerClaim(w http.ResponseWriter, key string, in map[string]any) {
	if r.used("claim-bad", key, time.Hour) >= claimFailsHour || r.used("claim-bad-all", "all", time.Hour) >= claimFailsAll {
		fail(w, 429, "too many attempts")
		return
	}
	code, _ := in["code"].(string)
	h, hok := strArg(in, "h", 64)
	p := filepath.Join(r.data, "owner-claim.json")
	var c struct {
		H   string
		Exp int64
	}
	b, err := os.ReadFile(p)
	good := err == nil && json.Unmarshal(b, &c) == nil && r.now().Unix() < c.Exp && hok &&
		subtle.ConstantTimeCompare([]byte(sha256hex("lullwire-claim|"+strings.TrimSpace(code))), []byte(c.H)) == 1
	if !good || os.Remove(p) != nil { // single use: whoever removes the file has claimed it
		r.allow("claim-bad", key, time.Hour, claimFailsHour)
		r.allow("claim-bad-all", "all", time.Hour, claimFailsAll)
		fail(w, 403, "wrong or expired owner code")
		return
	}
	ob, _ := json.Marshal(map[string]any{"h": h, "since": r.now().Unix()})
	if err := atomicWrite(filepath.Join(r.data, "owner.json"), ob); err != nil {
		fail(w, 500, "storage error")
		return
	}
	r.mu.Lock()
	r.ownerHash = h
	r.mu.Unlock()
	log.Print("owner: a device claimed this relay")
	okJSON(w)
}

func (r *Relay) setShared(on bool) error {
	b, _ := json.Marshal(map[string]bool{"shared_off": !on})
	if err := atomicWrite(filepath.Join(r.data, "settings.json"), b); err != nil {
		return err
	}
	r.mu.Lock()
	r.sharedOff = !on
	var cs []*wsConn
	if !on { // send connections opened with the shared code must prove the member key now
		for c := range r.sendConns {
			cs = append(cs, c)
		}
	}
	r.mu.Unlock()
	closeConns(cs)
	log.Printf("owner: shared join code turned %s", map[bool]string{true: "on", false: "off"}[on])
	return nil
}

func (r *Relay) newInvite(days int) (map[string]any, error) {
	entries, _ := os.ReadDir(r.inviteDir)
	if len(entries) >= maxInvites {
		return nil, errors.New("too many open invites; revoke some first")
	}
	if !r.diskOK() {
		return nil, errors.New("relay storage full")
	}
	code := randWord(12)
	now := r.now()
	exp := now.Add(time.Duration(days) * 24 * time.Hour).Unix()
	b, _ := json.Marshal(map[string]int64{"c": now.Unix(), "e": exp})
	id := inviteID(code)
	if err := atomicWrite(filepath.Join(r.inviteDir, id+".json"), b); err != nil {
		return nil, errors.New("storage error")
	}
	return map[string]any{"code": code, "id": id, "created": now.Unix(), "expires": exp}, nil
}

func (r *Relay) inviteList() []map[string]any {
	now := r.now().Unix()
	out := []map[string]any{}
	entries, _ := os.ReadDir(r.inviteDir)
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".json")
		b, err := os.ReadFile(filepath.Join(r.inviteDir, e.Name()))
		var inv struct{ C, E int64 }
		if !isHex(id, 32) || err != nil || json.Unmarshal(b, &inv) != nil || inv.E <= now {
			continue
		}
		out = append(out, map[string]any{"id": id, "created": inv.C, "expires": inv.E})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["created"].(int64) > out[j]["created"].(int64) })
	return out
}

// memberList returns every member under its alias, oldest first. joined is 0 for
// memberships from before 0.8, which didn't record it.
func (r *Relay) memberList() []map[string]any {
	r.mu.Lock()
	boxes := make([]string, 0, len(r.members))
	for box := range r.members {
		boxes = append(boxes, box)
	}
	seen := make(map[string]time.Time, len(boxes))
	for _, b := range boxes {
		seen[b] = r.seen[b]
	}
	r.mu.Unlock()
	out := make([]map[string]any, 0, len(boxes))
	for _, box := range boxes {
		p := filepath.Join(r.memberDir, box)
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		last := info.ModTime()
		if seen[box].After(last) {
			last = seen[box]
		}
		var m struct{ J int64 }
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			_ = json.Unmarshal(b, &m)
		}
		_, pendingBytes := r.pending(box)
		out = append(out, map[string]any{"id": alias(box), "joined": m.J, "seen": last.Unix(), "waiting": pendingBytes})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i]["joined"].(int64), out[j]["joined"].(int64)
		if a != b {
			return a < b
		}
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	return out
}

// removeMember takes a member off the relay: membership, waiting mail and live
// connections go, and the member key changes, so their app can't keep a send
// connection or rejoin without a new invite (or the shared code, if it's still on).
func (r *Relay) removeMember(id string) bool {
	r.mu.Lock()
	box := ""
	for b := range r.members {
		if alias(b) == id {
			box = b
			break
		}
	}
	if box == "" {
		r.mu.Unlock()
		return false
	}
	delete(r.members, box)
	delete(r.seen, box)
	var cs []*wsConn
	for c := range r.mailConns[box] {
		cs = append(cs, c)
	}
	for c := range r.sendConns {
		cs = append(cs, c)
	}
	keyErr := r.rotateMemberKeyLocked()
	r.mu.Unlock()
	if keyErr != nil {
		log.Printf("owner: could not change the member key: %v", keyErr)
	}
	_ = os.Remove(filepath.Join(r.memberDir, box))
	unlock := r.lockBox(box)
	_ = os.RemoveAll(r.boxDir(box))
	unlock()
	closeConns(cs)
	r.wake(box)
	log.Print("owner: removed a member")
	return true
}

func (r *Relay) ownerStatus() map[string]any {
	r.saveStats()
	now := r.now()
	var boxes, msgs int
	var bytes int64
	entries, _ := os.ReadDir(r.data)
	for _, e := range entries {
		if !e.IsDir() || !isHex(e.Name(), 32) {
			continue
		}
		ids, n := r.pending(e.Name())
		if len(ids) > 0 {
			boxes++
			msgs += len(ids)
			bytes += n
		}
	}
	backups := 0
	slots, _ := os.ReadDir(r.recover)
	for _, s := range slots {
		if strings.HasSuffix(s.Name(), ".json") {
			backups++
		}
	}
	free, ok := diskFree(r.data)
	diskFreeBytes := int64(-1)
	if ok {
		diskFreeBytes = int64(free)
	}
	invites := len(r.inviteList())
	r.hub.mu.Lock()
	calls := len(r.hub.rooms)
	r.hub.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	var a1, a7 int
	for _, at := range r.seen {
		if d := now.Sub(at); d <= 24*time.Hour {
			a1++
			a7++
		} else if d <= 7*24*time.Hour {
			a7++
		}
	}
	days := append([]dayStats(nil), r.days...)
	return map[string]any{
		"version": version, "started": r.started.Unix(), "now": now.Unix(), "restart": r.restart != nil,
		"invite_only": r.inviteOnly(), "shared": r.inviteOnly() && !r.sharedOff,
		"members": len(r.members), "active_1d": a1, "active_7d": a7,
		"pending": map[string]any{"mailboxes": boxes, "messages": msgs, "bytes": bytes},
		"backups": backups, "disk_free": diskFreeBytes, "invites": invites,
		"live": map[string]int{"mail": len(r.mailConns), "send": len(r.sendConns), "calls": calls},
		"days": days,
	}
}

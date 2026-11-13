// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// claimOwner makes this test the relay's owner and returns the owner token.
func claimOwner(t *testing.T, r *Relay, h http.Handler) string {
	t.Helper()
	if err := writeOwnerClaim(r.data, "claim-me", time.Now()); err != nil {
		t.Fatal(err)
	}
	tok := secret(4242)
	rec, _ := do(h, call{url: "/relay.php?a=owner", body: `{"op":"claim","code":"claim-me","h":"` + sha256hex("lullwire-owner|"+tok) + `"}`})
	if rec.Code != 200 {
		t.Fatalf("claim = %d %s", rec.Code, rec.Body)
	}
	return tok
}

func ownerDo(h http.Handler, tok, op string, extra ...string) (int, map[string]any) {
	body := `{"o":"` + tok + `","op":"` + op + `"`
	for _, e := range extra {
		body += "," + e
	}
	rec, m := do(h, call{url: "/relay.php?a=owner", body: body + "}"})
	return rec.Code, m
}

func joinWith(h http.Handler, s, code string) (int, map[string]any) {
	rec, m := do(h, call{url: "/relay.php?a=join", body: `{"s":"` + s + `","code":"` + code + `"}`})
	return rec.Code, m
}

func TestOwnerClaim(t *testing.T) {
	r, h := newTestRelay(t, false)
	if _, info := do(h, call{url: "/relay.php?a=info"}); info["owner"] != true {
		t.Fatalf("info should offer the owner dashboard: %v", info)
	}
	if c, m := ownerDo(h, secret(1), "status"); c != 403 || m["error"] != "not the owner" {
		t.Fatalf("status before any claim = %d %v", c, m)
	}
	if err := writeOwnerClaim(r.data, "right-code", time.Now()); err != nil {
		t.Fatal(err)
	}
	hash := sha256hex("lullwire-owner|" + secret(7))
	claim := func(code, h2 string) int {
		rec, _ := do(h, call{url: "/relay.php?a=owner", body: `{"op":"claim","code":"` + code + `","h":"` + h2 + `"}`})
		return rec.Code
	}
	if c := claim("wrong-code", hash); c != 403 {
		t.Errorf("wrong claim code = %d", c)
	}
	if c := claim("right-code", "nothex"); c != 403 {
		t.Errorf("claim without a token hash = %d", c)
	}
	if c := claim(" right-code ", hash); c != 200 {
		t.Fatalf("claim = %d", c)
	}
	if c := claim("right-code", sha256hex("x")); c != 403 {
		t.Errorf("a claim code works only once: %d", c)
	}
	if _, err := os.Stat(filepath.Join(r.data, "owner-claim.json")); !os.IsNotExist(err) {
		t.Error("used claim code left on disk")
	}
	if c, _ := ownerDo(h, secret(7), "status"); c != 200 {
		t.Errorf("owner status = %d", c)
	}
	if c, m := ownerDo(h, secret(8), "status"); c != 403 || m["error"] != "not the owner" {
		t.Errorf("someone else = %d %v", c, m)
	}
	// The owner survives a restart; only the hash is stored.
	b, _ := os.ReadFile(filepath.Join(r.data, "owner.json"))
	if strings.Contains(string(b), secret(7)) || !strings.Contains(string(b), hash) {
		t.Errorf("owner.json should hold only the token's hash: %s", b)
	}
	r2, err := NewRelay(r.data, nil, false)
	if err != nil || r2.ownerHash != hash {
		t.Errorf("owner lost on restart: %v", err)
	}
	// An expired claim code is refused.
	_ = writeOwnerClaim(r.data, "late", time.Now().Add(-claimTTL-time.Minute))
	if c := claim("late", hash); c != 403 {
		t.Errorf("expired claim code = %d", c)
	}
	// A new code replaces the owner (a lost phone is recovered from the server).
	_ = writeOwnerClaim(r.data, "again", time.Now())
	if c := claim("again", sha256hex("lullwire-owner|"+secret(9))); c != 200 {
		t.Fatalf("re-claim = %d", c)
	}
	if c, _ := ownerDo(h, secret(7), "status"); c != 403 {
		t.Errorf("the old owner device must lose access: %d", c)
	}
}

func TestOwnerGuessingLimited(t *testing.T) {
	r, h := newTestRelay(t, false)
	tok := claimOwner(t, r, h)
	limited := false
	for i := 0; i < ownerFailsHour+5; i++ {
		if c, _ := ownerDo(h, secret(100+i), "status"); c == 429 {
			limited = true
		}
	}
	if !limited {
		t.Error("wrong owner tokens were not limited")
	}
	if c, _ := ownerDo(h, tok, "status"); c != 200 {
		t.Errorf("the right token must always work: %d", c)
	}
	// Claim codes: limited before they are even checked.
	_ = writeOwnerClaim(r.data, "real", time.Now())
	for i := 0; i < claimFailsHour; i++ {
		do(h, call{url: "/relay.php?a=owner", body: `{"op":"claim","code":"guess","h":"` + secret(1) + `"}`})
	}
	rec, _ := do(h, call{url: "/relay.php?a=owner", body: `{"op":"claim","code":"real","h":"` + secret(1) + `"}`})
	if rec.Code != 429 {
		t.Errorf("claim guessing not limited: %d", rec.Code)
	}
}

func TestSingleUseInvites(t *testing.T) {
	r, h := newTestRelay(t, false)
	r.SetJoinCode("shared")
	tok := claimOwner(t, r, h)
	c, inv := ownerDo(h, tok, "invite", `"days":3`)
	if c != 200 {
		t.Fatalf("invite = %d", c)
	}
	code := inv["code"].(string)
	if exp := int64(inv["expires"].(float64)); exp < time.Now().Add(71*time.Hour).Unix() || exp > time.Now().Add(73*time.Hour).Unix() {
		t.Errorf("3-day invite expires at %d", exp)
	}
	if _, l := ownerDo(h, tok, "invites"); len(l["invites"].([]any)) != 1 {
		t.Errorf("invites: %v", l)
	}
	c, m := joinWith(h, secret(1), code)
	if c != 200 || !isHex(m["k"].(string), 64) || m["shared"] != true {
		t.Fatalf("join with invite = %d %v", c, m)
	}
	if !r.isMember(boxOf(secret(1))) {
		t.Fatal("not a member after joining")
	}
	if c, _ := joinWith(h, secret(2), code); c != 403 {
		t.Errorf("an invite works once: %d", c)
	}
	if _, l := ownerDo(h, tok, "invites"); len(l["invites"].([]any)) != 0 {
		t.Errorf("used invite still listed: %v", l)
	}
	// Revoked and expired invites are refused.
	_, inv = ownerDo(h, tok, "invite")
	ownerDo(h, tok, "revoke", `"id":"`+inv["id"].(string)+`"`)
	if c, _ := joinWith(h, secret(3), inv["code"].(string)); c != 403 {
		t.Errorf("revoked invite = %d", c)
	}
	_, inv = ownerDo(h, tok, "invite", `"days":1`)
	r.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if c, _ := joinWith(h, secret(4), inv["code"].(string)); c != 403 {
		t.Errorf("expired invite = %d", c)
	}
	r.Sweep()
	if entries, _ := os.ReadDir(r.inviteDir); len(entries) != 0 {
		t.Errorf("expired invite not swept: %d left", len(entries))
	}
	// An invite isn't used up by a join the relay refuses for another reason.
	r.now = time.Now
	_, inv = ownerDo(h, tok, "invite")
	for i := 0; i < 30; i++ { // fill this client's new-member allowance
		joinWith(h, secret(500+i), "shared")
	}
	if c, _ := joinWith(h, secret(600), inv["code"].(string)); c != 429 {
		t.Fatalf("expected the new-member limit, got %d", c)
	}
	if !r.inviteValid(inv["code"].(string)) {
		t.Error("a refused join used up the invite")
	}
}

func TestSharedCodeOff(t *testing.T) {
	r, h := newTestRelay(t, false)
	r.SetJoinCode("shared")
	tok := claimOwner(t, r, h)
	if c, _ := joinWith(h, secret(1), "shared"); c != 200 {
		t.Fatal("join with the shared code")
	}
	if c, _ := ownerDo(h, tok, "shared", `"on":false`); c != 200 {
		t.Fatal("turning the shared code off")
	}
	if c, _ := joinWith(h, secret(2), "shared"); c != 403 {
		t.Errorf("shared code still admits new people: %d", c)
	}
	// Existing members renew without any code, and learn the shared code is off.
	c, m := joinWith(h, secret(1), "")
	if c != 200 || m["shared"] != false {
		t.Errorf("renewal = %d %v", c, m)
	}
	if _, m := joinWith(h, secret(1), "shared"); m["code"] != false {
		t.Errorf("renewal should say the held code no longer admits anyone: %v", m)
	}
	// It stays off across a restart, and can be turned on again.
	r2, _ := NewRelay(r.data, nil, false)
	if !r2.sharedOff {
		t.Error("setting lost on restart")
	}
	ownerDo(h, tok, "shared", `"on":true`)
	if c, _ := joinWith(h, secret(3), "shared"); c != 200 {
		t.Errorf("shared code back on = %d", c)
	}
	open, h2 := newTestRelay(t, false)
	tok2 := claimOwner(t, open, h2)
	if c, _ := ownerDo(h2, tok2, "shared", `"on":false`); c != 400 {
		t.Errorf("an open relay has no shared code to switch: %d", c)
	}
}

func TestSendProof(t *testing.T) {
	r, srv := liveServer(t, "shared")
	h := srv.Config.Handler
	tok := claimOwner(t, r, h)
	_, m := joinWith(h, secret(1), "shared")
	key := m["k"].(string)
	try := func(j string) string {
		w := dialWS(t, srv, "/live")
		w.json(map[string]any{"op": "send", "j": j})
		_, msg, err := w.read(2 * time.Second)
		if err != nil {
			return "closed"
		}
		var v map[string]any
		_ = json.Unmarshal(msg, &v)
		return v["op"].(string)
	}
	if got := try(sha256hex("lullwire-member|" + key)); got != "ready" {
		t.Errorf("member key = %s", got)
	}
	if got := try(sha256hex("lullwire-join|shared")); got != "ready" {
		t.Errorf("LEGACY shared code while on = %s", got)
	}
	ownerDo(h, tok, "shared", `"on":false`)
	if got := try(sha256hex("lullwire-join|shared")); got != "error" {
		t.Errorf("LEGACY shared code after it's off = %s", got)
	}
	if got := try(sha256hex("lullwire-member|" + key)); got != "ready" {
		t.Errorf("member key after the shared code is off = %s", got)
	}
}

func TestRemoveMember(t *testing.T) {
	r, srv := liveServer(t, "shared")
	h := srv.Config.Handler
	tok := claimOwner(t, r, h)
	_, inv := ownerDo(h, tok, "invite")
	victim, friend := secret(1), secret(2)
	_, m := joinWith(h, victim, inv["code"].(string))
	oldKey := m["k"].(string)
	joinWith(h, friend, "shared")
	box := boxOf(victim)
	if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + box, body: blob(200)}); rec.Code != 200 {
		t.Fatal("put")
	}
	mailWS := dialWS(t, srv, "/live")
	mailWS.json(map[string]any{"op": "mail", "s": victim})
	mailWS.expectOp(t, "ready")
	sendWS := dialWS(t, srv, "/live")
	sendWS.json(map[string]any{"op": "send", "j": sha256hex("lullwire-member|" + oldKey)})
	sendWS.expectOp(t, "ready")

	_, list := ownerDo(h, tok, "members")
	members := list["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("members: %v", list)
	}
	for _, x := range members {
		e := x.(map[string]any)
		if strings.Contains(e["id"].(string), box[:12]) || e["seen"].(float64) == 0 {
			t.Errorf("member entry leaks the mailbox or lacks last-seen: %v", e)
		}
	}
	if c, _ := ownerDo(h, tok, "remove", `"id":"`+alias(box)+`"`); c != 200 {
		t.Fatalf("remove = %d", c)
	}
	if r.isMember(box) {
		t.Error("still a member")
	}
	if _, err := os.Stat(r.boxDir(box)); !os.IsNotExist(err) {
		t.Error("waiting mail not deleted")
	}
	for name, w := range map[string]*testWS{"mail": mailWS, "send": sendWS} {
		if _, _, err := w.read(2 * time.Second); err == nil {
			if _, _, err = w.read(2 * time.Second); err == nil {
				t.Errorf("%s connection still open after removal", name)
			}
		}
	}
	if r.sendAllowed(sha256hex("lullwire-member|" + oldKey)) {
		t.Error("the old member key still opens send connections")
	}
	if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + box, body: blob(200)}); rec.Code != 404 {
		t.Errorf("mail for a removed member = %d", rec.Code)
	}
	if c, _ := joinWith(h, victim, inv["code"].(string)); c != 403 {
		t.Errorf("rejoining with the used invite = %d", c)
	}
	// Everyone else gets the new key on their next renewal.
	_, m = joinWith(h, friend, "")
	if m["k"] == oldKey || !r.sendAllowed(sha256hex("lullwire-member|"+m["k"].(string))) {
		t.Error("remaining members did not get a working new key")
	}
	if c, _ := ownerDo(h, tok, "remove", `"id":"`+alias(box)+`"`); c != 404 {
		t.Errorf("removing twice = %d", c)
	}
	if c, _ := ownerDo(h, tok, "remove", `"id":"../../x"`); c != 400 {
		t.Errorf("bad id = %d", c)
	}
}

func TestOwnerStatus(t *testing.T) {
	r, h := newTestRelay(t, false)
	r.SetJoinCode("shared")
	tok := claimOwner(t, r, h)
	for i := 1; i <= 3; i++ {
		joinWith(h, secret(i), "shared")
	}
	for i := 0; i < 4; i++ {
		do(h, call{url: "/relay.php?a=put&box=" + boxOf(secret(1)), body: blob(1000)})
	}
	do(h, call{url: "/relay.php?a=get", body: `{"s":"` + secret(2) + `"}`})
	c, st := ownerDo(h, tok, "status")
	if c != 200 {
		t.Fatal(c)
	}
	pending := st["pending"].(map[string]any)
	days := st["days"].([]any)
	today := days[len(days)-1].(map[string]any)
	if st["members"].(float64) != 3 || st["active_1d"].(float64) != 3 || pending["messages"].(float64) != 4 ||
		pending["bytes"].(float64) != 4000 || today["in"].(float64) != 4 || today["joins"].(float64) != 3 ||
		st["invite_only"] != true || st["shared"] != true || st["version"] != version {
		t.Errorf("status: %v", st)
	}
	// Counts persist across a restart.
	r.saveStats()
	r2, _ := NewRelay(r.data, nil, false)
	if len(r2.days) == 0 || r2.days[len(r2.days)-1].In != 4 {
		t.Errorf("stats lost on restart: %v", r2.days)
	}
}

func TestOwnerRestart(t *testing.T) {
	r, h := newTestRelay(t, false)
	tok := claimOwner(t, r, h)
	if c, _ := ownerDo(h, tok, "restart"); c != 501 {
		t.Errorf("restart where unsupported = %d", c)
	}
	var called atomic.Bool
	r.restart = func() { called.Store(true) }
	if c, _ := ownerDo(h, tok, "restart"); c != 200 {
		t.Fatalf("restart = %d", c)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !called.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !called.Load() {
		t.Error("restart hook not called")
	}
	if c, _ := ownerDo(h, secret(1), "restart"); c != 403 {
		t.Errorf("restart by someone else = %d", c)
	}
}

func TestTemporaryMailboxesForMoves(t *testing.T) {
	r, h := newTestRelay(t, false)
	r.SetJoinCode("shared")
	joinWith(h, secret(1), "shared")
	tok := claimOwner(t, r, h)
	ownerDo(h, tok, "shared", `"on":false`)
	temp := func(s, by string) int {
		rec, _ := do(h, call{url: "/relay.php?a=join", body: `{"s":"` + s + `","by":"` + by + `","temp":true}`})
		return rec.Code
	}
	if c := temp(secret(50), secret(99)); c != 403 {
		t.Errorf("a non-member admitted a mailbox: %d", c)
	}
	if c := temp(secret(50), secret(1)); c != 200 || !r.isMember(boxOf(secret(50))) {
		t.Fatalf("member admitting a move mailbox = %d", c)
	}
	if _, l := ownerDo(h, tok, "members"); len(l["members"].([]any)) != 1 {
		t.Errorf("temporary mailboxes must not be listed as members: %v", l)
	}
	for i := 0; i < tempPerHour; i++ {
		temp(secret(60+i), secret(1))
	}
	if c := temp(secret(70), secret(1)); c != 403 {
		t.Errorf("temporary admissions not limited: %d", c)
	}
	r.now = func() time.Time { return time.Now().Add(61 * time.Minute) }
	if r.isMember(boxOf(secret(50))) {
		t.Error("a temporary mailbox outlived its hour")
	}
	r.Sweep()
	if len(r.temp) != 0 {
		t.Errorf("expired temporary mailboxes not swept: %d", len(r.temp))
	}
}

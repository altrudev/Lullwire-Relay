// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A browser's side of a subscription: its key pair and auth secret.
type testBrowser struct {
	key  *ecdh.PrivateKey
	auth []byte
}

func newTestBrowser(t *testing.T) testBrowser {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 16)
	rand.Read(a)
	return testBrowser{k, a}
}

func (b testBrowser) sub(endpoint string) string {
	e := base64.RawURLEncoding
	return `{"endpoint":"` + endpoint + `","keys":{"p256dh":"` + e.EncodeToString(b.key.PublicKey().Bytes()) + `","auth":"` + e.EncodeToString(b.auth) + `"}}`
}

// decrypt is the receiving side of RFC 8291, as a browser does it.
func (b testBrowser) decrypt(t *testing.T, body []byte) []byte {
	t.Helper()
	salt, rs, idlen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	asPub, ct := body[21:21+idlen], body[21+idlen:]
	if rs != 4096 || idlen != 65 {
		t.Fatalf("header: rs %d idlen %d", rs, idlen)
	}
	pk, err := ecdh.P256().NewPublicKey(asPub)
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := b.key.ECDH(pk)
	ikm := hmacSHA256(hmacSHA256(b.auth, shared), []byte("WebPush: info\x00"), b.key.PublicKey().Bytes(), asPub, []byte{1})
	prk := hmacSHA256(salt, ikm)
	block, _ := aes.NewCipher(hmacSHA256(prk, []byte("Content-Encoding: aes128gcm\x00"), []byte{1})[:16])
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, hmacSHA256(prk, []byte("Content-Encoding: nonce\x00"), []byte{1})[:12], ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain[len(plain)-1] != 2 {
		t.Fatal("missing last-record delimiter")
	}
	return plain[:len(plain)-1]
}

func pushCall(h http.Handler, s, body string) int {
	rec, _ := do(h, call{url: "/relay.php?a=push", body: `{"s":"` + s + `",` + body + `}`})
	return rec.Code
}

func TestPushSubscriptions(t *testing.T) {
	r, h := newTestRelay(t, false)
	if c := pushCall(h, secret(1), `"sub":{}`); c != 404 {
		t.Errorf("push while off = %d", c)
	}
	if err := r.EnablePush("mailto:test@example.com"); err != nil {
		t.Fatal(err)
	}
	_, info := do(h, call{url: "/relay.php?a=info"})
	key, _ := b64urlBytes(info["push"].(string))
	if len(key) != 65 || key[0] != 4 {
		t.Fatalf("info should carry the uncompressed VAPID key: %v", info["push"])
	}
	// The key survives a restart, so subscriptions keep working.
	r2, _ := NewRelay(r.data, nil, false)
	r2.EnablePush("x")
	if r2.push.pub != r.push.pub {
		t.Error("VAPID key changed on restart")
	}
	b := newTestBrowser(t)
	for _, bad := range []string{
		"http://fcm.googleapis.com/x", "https://127.0.0.1/x", "https://localhost/x", "https://fcm.googleapis.com.evil.com/x",
		"https://evil.com/fcm.googleapis.com", "https://web.push.apple.com:8443/x", "https://user@fcm.googleapis.com/x",
		"https://push.apple.com.evil.com/x", "file:///etc/passwd", "https://" + strings.Repeat("a", 1100) + ".push.apple.com/x",
	} {
		if c := pushCall(h, secret(1), `"sub":`+b.sub(bad)); c != 400 {
			t.Errorf("endpoint %.60s accepted: %d", bad, c)
		}
	}
	for _, good := range []string{"https://fcm.googleapis.com/fcm/send/abc", "https://web.push.apple.com/QAbc", "https://updates.push.services.mozilla.com/wpush/v2/x", "https://wns2-par02p.notify.windows.com/w/?token=x"} {
		if c := pushCall(h, secret(1), `"sub":`+b.sub(good)); c != 200 {
			t.Errorf("endpoint %s refused: %d", good, c)
		}
	}
	var subs []pushSub
	raw, _ := os.ReadFile(filepath.Join(r.push.dir, boxOf(secret(1))+".json"))
	json.Unmarshal(raw, &subs)
	if len(subs) != maxPushPerBox || !strings.Contains(subs[0].E, "windows") {
		t.Errorf("want the newest %d subscriptions, got %d", maxPushPerBox, len(subs))
	}
	if c := pushCall(h, secret(1), `"sub":{"endpoint":"https://fcm.googleapis.com/x","keys":{"p256dh":"AAAA","auth":"AAAAAAAAAAAAAAAAAAAAAA"}}`); c != 400 {
		t.Errorf("bad browser key accepted: %d", c)
	}
	if c := pushCall(h, secret(1), `"off":true`); c != 200 {
		t.Fatal("off")
	}
	if _, err := os.Stat(filepath.Join(r.push.dir, boxOf(secret(1))+".json")); !os.IsNotExist(err) {
		t.Error("subscriptions left after turning push off")
	}
	// Invite-only: members only.
	r.SetJoinCode("jc")
	if c := pushCall(h, secret(2), `"sub":`+b.sub("https://fcm.googleapis.com/x")); c != 403 {
		t.Errorf("non-member subscribed: %d", c)
	}
}

func TestPushWake(t *testing.T) {
	var mu sync.Mutex
	var got []*http.Request
	var bodies [][]byte
	status := 201
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		got = append(got, req)
		bodies = append(bodies, b)
		st := status
		mu.Unlock()
		w.WriteHeader(st)
	}))
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)
	old := pushHostOK
	pushHostOK = func(u *url.URL) bool { return u.Host == srvURL.Host }
	defer func() { pushHostOK = old }()

	r, h := newTestRelay(t, false)
	r.SetJoinCode("jc")
	if err := r.EnablePush("mailto:owner@example.com"); err != nil {
		t.Fatal(err)
	}
	r.push.client = srv.Client()
	joinWith(h, secret(1), "jc")
	b := newTestBrowser(t)
	if c := pushCall(h, secret(1), `"sub":`+b.sub(srv.URL+"/push/1")); c != 200 {
		t.Fatalf("subscribe = %d", c)
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(got) }
	waitFor := func(n int) bool {
		for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
			if count() >= n {
				return true
			}
		}
		return false
	}
	box := boxOf(secret(1))
	put := func() { do(h, call{url: "/relay.php?a=put&box=" + box, body: blob(300)}) }

	put()
	if !waitFor(1) {
		t.Fatal("no push for new mail")
	}
	mu.Lock()
	req, body := got[0], bodies[0]
	mu.Unlock()
	if p := b.decrypt(t, body); string(p) != `{"t":"m"}` {
		t.Errorf("payload %q", p)
	}
	if req.Header.Get("Content-Encoding") != "aes128gcm" || req.Header.Get("TTL") == "" || req.Header.Get("Urgency") != "high" {
		t.Errorf("headers: %v", req.Header)
	}
	// VAPID: a JWT signed by the key the app subscribed with, for this push service.
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "vapid t=") || !strings.HasSuffix(auth, ", k="+r.push.pub) {
		t.Fatalf("authorization: %s", auth)
	}
	jwt := strings.TrimSuffix(strings.TrimPrefix(auth, "vapid t="), ", k="+r.push.pub)
	parts := strings.Split(jwt, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	pubBytes, _ := b64urlBytes(r.push.pub)
	x, y := elliptic.Unmarshal(elliptic.P256(), pubBytes)
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("VAPID signature does not verify")
	}
	var claims map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(cb, &claims)
	if claims["aud"] != srv.URL || claims["sub"] != "mailto:owner@example.com" || int64(claims["exp"].(float64)) <= time.Now().Unix() {
		t.Errorf("claims: %v", claims)
	}

	// More mail before the app fetches: no more signals for a while.
	put()
	put()
	time.Sleep(200 * time.Millisecond)
	if n := count(); n != 1 {
		t.Errorf("signals before the app fetched: %d, want 1", n)
	}
	// After a fetch, the next arrival signals again.
	do(h, call{url: "/relay.php?a=get", body: `{"s":"` + secret(1) + `"}`})
	put()
	if !waitFor(2) {
		t.Error("no signal after the app fetched")
	}
	// Mail for someone without push signals nobody.
	joinWith(h, secret(2), "jc")
	do(h, call{url: "/relay.php?a=put&box=" + boxOf(secret(2)), body: blob(300)})
	time.Sleep(200 * time.Millisecond)
	if n := count(); n != 2 {
		t.Errorf("signals: %d, want 2", n)
	}
	// A push service that says the subscription is gone: it's dropped.
	mu.Lock()
	status = 410
	mu.Unlock()
	do(h, call{url: "/relay.php?a=get", body: `{"s":"` + secret(1) + `"}`})
	put()
	waitFor(3)
	file := filepath.Join(r.push.dir, box+".json")
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			break
		}
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Error("subscription kept after 410 Gone")
	}
	// Removing a member removes their subscriptions.
	pushCall(h, secret(2), `"sub":`+b.sub(srv.URL+"/push/2"))
	tok := claimOwner(t, r, h)
	ownerDo(h, tok, "remove", `"id":"`+alias(boxOf(secret(2)))+`"`)
	if _, err := os.Stat(filepath.Join(r.push.dir, boxOf(secret(2))+".json")); !os.IsNotExist(err) {
		t.Error("removed member's push subscription kept")
	}
	if _, st := ownerDo(h, tok, "status"); st["push"].(float64) != 0 {
		t.Errorf("status push count: %v", st["push"])
	}
}

func TestPushNotWhileConnected(t *testing.T) {
	calls := 0
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { mu.Lock(); calls++; mu.Unlock(); w.WriteHeader(201) }))
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)
	old := pushHostOK
	pushHostOK = func(u *url.URL) bool { return u.Host == srvURL.Host }
	defer func() { pushHostOK = old }()
	r, lsrv := liveServer(t, "")
	h := lsrv.Config.Handler
	r.EnablePush("x")
	r.push.client = srv.Client()
	b := newTestBrowser(t)
	pushCall(h, secret(1), `"sub":`+b.sub(srv.URL+"/p"))
	ws := dialWS(t, lsrv, "/live")
	ws.json(map[string]any{"op": "mail", "s": secret(1)})
	ws.expectOp(t, "ready")
	do(h, call{url: "/relay.php?a=put&box=" + boxOf(secret(1)), body: blob(300)})
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Errorf("pushed %d times while the app was connected", calls)
	}
}

// For an independent check (tests/push-check.py decrypts with the http_ece library).
func TestPushVectorFile(t *testing.T) {
	out := os.Getenv("PUSH_VECTOR")
	if out == "" {
		t.Skip("set PUSH_VECTOR=file to write a sample for tests/push-check.py")
	}
	b := newTestBrowser(t)
	e := base64.RawURLEncoding
	sub := pushSub{P: e.EncodeToString(b.key.PublicKey().Bytes()), A: e.EncodeToString(b.auth)}
	body, err := encryptPush(sub, []byte("When I grow up, I want to be a watermelon"))
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(map[string]string{"priv": e.EncodeToString(b.key.Bytes()), "pub": sub.P, "auth": sub.A, "body": e.EncodeToString(body)})
	os.WriteFile(out, j, 0o600)
}

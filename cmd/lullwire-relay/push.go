// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Web Push, for apps that turn on "notifications when closed" (Go relay).
//
// A browser can't keep a connection open while its app is closed, so the only way
// to wake it is the browser maker's push service (Apple, Google, Mozilla,
// Microsoft). The app hands the relay a push subscription for its mailbox; when mail
// arrives and the app isn't connected, the relay sends that service a tiny,
// encrypted signal with nothing in it but "there's mail", and the app's service
// worker shows "New message". The push service learns when a device gets mail and
// this relay's address, never who from or what; it's off unless the person turns it
// on, and off by default on onion relays (it would reveal the server).
//
//	RFC 8030  the push protocol       RFC 8291  payload encryption (aes128gcm)
//	RFC 8292  VAPID (the relay signs each request with its own key, data/vapid.pem)
//
// Subscriptions: data/push/<box>.json, at most 3 per mailbox; renewed by the app on
// every start, dropped after 60 days without renewal, when the push service says
// they're gone, and when the owner removes the member. The relay only ever talks to
// the push services' own hosts, so a made-up subscription can't make it call
// anything else.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxPushPerBox = 3                   // devices per mailbox
	maxPushBoxes  = 20000               // mailboxes with push
	pushQuiet     = 10 * time.Minute    // at most one push per mailbox this often until it fetches its mail
	pushTTL       = 24 * 60 * 60        // seconds a push service may hold a signal
	pushKeep      = 60 * 24 * time.Hour // subscriptions nobody renewed are dropped
	pushParallel  = 8                   // signals in flight at once
)

// pushPayload is all a signal says. The app shows "New message" for it.
var pushPayload = []byte(`{"t":"m"}`)

// pushHostOK limits the relay to the push services' own hosts (a variable for tests).
var pushHostOK = func(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	h := strings.ToLower(u.Hostname())
	switch h {
	case "fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com":
		return true
	}
	for _, suffix := range []string{".push.apple.com", ".notify.windows.com", ".push.services.mozilla.com"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

type pushSub struct {
	E string `json:"e"` // endpoint
	P string `json:"p"` // the browser's public key (p256dh), base64url
	A string `json:"a"` // its auth secret, base64url
	T int64  `json:"t"` // last renewed
}

type pushState struct {
	key     *ecdsa.PrivateKey
	pub     string // VAPID public key, base64url, for the app's applicationServerKey
	contact string // VAPID "sub": a URL or mailto: for the push services
	dir     string
	client  *http.Client
	sem     chan struct{}

	mu   sync.Mutex
	last map[string]time.Time // mailbox -> last signal, until it fetches its mail
}

// EnablePush turns Web Push on, loading or creating the relay's VAPID key.
func (r *Relay) EnablePush(contact string) error {
	keyPath := filepath.Join(r.data, "vapid.pem")
	var key *ecdsa.PrivateKey
	if b, err := os.ReadFile(keyPath); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			key, _ = x509.ParseECPrivateKey(blk.Bytes)
		}
	}
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		if err := atomicWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
			return err
		}
		key = k
	}
	pub, err := key.PublicKey.ECDH()
	if err != nil {
		return err
	}
	dir := filepath.Join(r.data, "push")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	r.push = &pushState{
		key: key, pub: base64.RawURLEncoding.EncodeToString(pub.Bytes()), contact: contact, dir: dir,
		client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		sem:    make(chan struct{}, pushParallel), last: map[string]time.Time{},
	}
	return nil
}

func b64urlBytes(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// pushAPI handles POST ?a=push: {"s", "sub": {"endpoint", "keys": {"p256dh", "auth"}}}
// to subscribe or renew, {"s", "off": true, "endpoint"?} to stop.
func (r *Relay) pushAPI(w http.ResponseWriter, req *http.Request, box string, in map[string]any) {
	p := r.push
	if p == nil {
		fail(w, 404, "push is off on this relay")
		return
	}
	r.mu.Lock()
	member := r.members[box]
	r.mu.Unlock()
	if r.inviteOnly() && !member {
		fail(w, 403, "not a member")
		return
	}
	key, _ := r.clientKey(req)
	if !r.allow("push", key, time.Hour, 60) {
		fail(w, 429, "too many requests")
		return
	}
	file := filepath.Join(p.dir, box+".json")
	unlock := r.lockBox(box)
	defer unlock()
	var subs []pushSub
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &subs)
	}
	if off, _ := in["off"].(bool); off {
		endpoint, _ := in["endpoint"].(string)
		kept := subs[:0]
		for _, s := range subs {
			if endpoint != "" && s.E != endpoint {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			_ = os.Remove(file)
		} else if b, err := json.Marshal(kept); err == nil {
			_ = atomicWrite(file, b)
		}
		okJSON(w)
		return
	}
	sub, err := parseSubscription(in["sub"])
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if len(subs) == 0 {
		if entries, _ := os.ReadDir(p.dir); len(entries) >= maxPushBoxes {
			fail(w, 507, "relay full")
			return
		}
	}
	sub.T = r.now().Unix()
	kept := []pushSub{sub}
	for _, s := range subs {
		if s.E != sub.E && len(kept) < maxPushPerBox {
			kept = append(kept, s)
		}
	}
	b, _ := json.Marshal(kept)
	if err := atomicWrite(file, b); err != nil {
		fail(w, 500, "storage error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func parseSubscription(v any) (pushSub, error) {
	m, _ := v.(map[string]any)
	endpoint, _ := m["endpoint"].(string)
	keys, _ := m["keys"].(map[string]any)
	p256dh, _ := keys["p256dh"].(string)
	auth, _ := keys["auth"].(string)
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 1024 || !pushHostOK(u) {
		return pushSub{}, errors.New("not a known push service")
	}
	pk, err := b64urlBytes(p256dh)
	if err != nil {
		return pushSub{}, errors.New("bad key")
	}
	if _, err := ecdh.P256().NewPublicKey(pk); err != nil {
		return pushSub{}, errors.New("bad key")
	}
	if a, err := b64urlBytes(auth); err != nil || len(a) != 16 {
		return pushSub{}, errors.New("bad auth")
	}
	return pushSub{E: endpoint, P: base64.RawURLEncoding.EncodeToString(pk), A: strings.TrimRight(auth, "=")}, nil
}

// pushWake signals a mailbox's devices that mail arrived, unless its app is
// connected right now or was signalled recently and hasn't fetched since.
func (r *Relay) pushWake(box string) {
	p := r.push
	if p == nil {
		return
	}
	r.mu.Lock()
	connected := len(r.mailConns[box]) > 0
	r.mu.Unlock()
	if connected {
		return
	}
	now := r.now()
	p.mu.Lock()
	if t, ok := p.last[box]; ok && now.Sub(t) < pushQuiet {
		p.mu.Unlock()
		return
	}
	b, err := os.ReadFile(filepath.Join(p.dir, box+".json"))
	var subs []pushSub
	if err != nil || json.Unmarshal(b, &subs) != nil || len(subs) == 0 {
		p.mu.Unlock()
		return
	}
	if len(p.last) < maxCounters {
		p.last[box] = now
	}
	p.mu.Unlock()
	for _, s := range subs {
		select {
		case p.sem <- struct{}{}:
			go func(s pushSub) {
				defer func() { <-p.sem }()
				if gone := p.send(s, now); gone {
					r.dropSub(box, s.E)
				}
			}(s)
		default: // busy: this one is skipped; the app still gets its mail when it opens
		}
	}
}

// pushFetched notes that a mailbox's app fetched its mail, so the next arrival may
// signal again.
func (r *Relay) pushFetched(box string) {
	if p := r.push; p != nil {
		p.mu.Lock()
		delete(p.last, box)
		p.mu.Unlock()
	}
}

func (r *Relay) dropSub(box, endpoint string) {
	p := r.push
	file := filepath.Join(p.dir, box+".json")
	unlock := r.lockBox(box)
	defer unlock()
	var subs []pushSub
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &subs)
	}
	kept := subs[:0]
	for _, s := range subs {
		if s.E != endpoint {
			kept = append(kept, s)
		}
	}
	if len(kept) == 0 {
		_ = os.Remove(file)
	} else if b, err := json.Marshal(kept); err == nil {
		_ = atomicWrite(file, b)
	}
}

// removePush deletes a mailbox's subscriptions (the owner removed the member).
func (r *Relay) removePush(box string) {
	if p := r.push; p != nil {
		_ = os.Remove(filepath.Join(p.dir, box+".json"))
	}
}

// sweepPush drops subscriptions nobody renewed, and those of non-members.
func (r *Relay) sweepPush() {
	p := r.push
	if p == nil {
		return
	}
	entries, _ := os.ReadDir(p.dir)
	cutoff := r.now().Add(-pushKeep)
	for _, e := range entries {
		box := strings.TrimSuffix(e.Name(), ".json")
		info, err := e.Info()
		r.mu.Lock()
		gone := r.inviteOnly() && !r.members[box]
		r.mu.Unlock()
		if !isHex(box, 32) || err != nil || gone || info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(p.dir, e.Name()))
		}
	}
	p.mu.Lock()
	for box, t := range p.last {
		if r.now().Sub(t) > pushQuiet {
			delete(p.last, box)
		}
	}
	p.mu.Unlock()
}

// send delivers one signal; it reports whether the subscription is gone for good.
func (p *pushState) send(s pushSub, now time.Time) bool {
	u, err := url.Parse(s.E)
	if err != nil || !pushHostOK(u) {
		return true
	}
	body, err := encryptPush(s, pushPayload)
	if err != nil {
		return true
	}
	jwt, err := p.vapidJWT(u.Scheme+"://"+u.Host, now)
	if err != nil {
		return false
	}
	req, err := http.NewRequest(http.MethodPost, s.E, bytes.NewReader(body))
	if err != nil {
		return true
	}
	req.Header.Set("TTL", "86400")
	req.Header.Set("Urgency", "high")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Authorization", "vapid t="+jwt+", k="+p.pub)
	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone
}

// vapidJWT signs {aud, exp, sub} with the relay's key (ES256, RFC 8292).
func (p *pushState) vapidJWT(aud string, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	head := enc.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, _ := json.Marshal(map[string]any{"aud": aud, "exp": now.Add(12 * time.Hour).Unix(), "sub": p.contact})
	signing := head + "." + enc.EncodeToString(claims)
	h := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + enc.EncodeToString(sig), nil
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// encryptPush encrypts a payload for one subscription (RFC 8291, aes128gcm, one record).
func encryptPush(s pushSub, payload []byte) ([]byte, error) {
	uaBytes, err := b64urlBytes(s.P)
	if err != nil {
		return nil, err
	}
	auth, err := b64urlBytes(s.A)
	if err != nil {
		return nil, err
	}
	ua, err := ecdh.P256().NewPublicKey(uaBytes)
	if err != nil {
		return nil, err
	}
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	asPub := as.PublicKey().Bytes()
	// IKM = HKDF(auth, ecdh_secret, "WebPush: info" 0x00 ua_public as_public, 32)
	prkKey := hmacSHA256(auth, shared)
	ikm := hmacSHA256(prkKey, []byte("WebPush: info\x00"), uaBytes, asPub, []byte{1})
	prk := hmacSHA256(salt, ikm)
	cek := hmacSHA256(prk, []byte("Content-Encoding: aes128gcm\x00"), []byte{1})[:16]
	nonce := hmacSHA256(prk, []byte("Content-Encoding: nonce\x00"), []byte{1})[:12]
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain := append(append([]byte(nil), payload...), 0x02) // last record, no padding
	header := make([]byte, 0, 16+4+1+len(asPub))
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, 4096)
	header = append(header, byte(len(asPub)))
	header = append(header, asPub...)
	return gcm.Seal(header, nonce, plain, nil), nil
}

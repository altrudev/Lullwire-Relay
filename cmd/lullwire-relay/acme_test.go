// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCA is a small ACME server that behaves like Let's Encrypt for IP certificates: it
// checks every JWS (signature, nonce, url), validates tls-alpn-01 by connecting to the
// relay's listener, and issues short-lived certificates from its own root.
type fakeCA struct {
	t        *testing.T
	srv      *httptest.Server
	target   string // where to connect for tls-alpn-01 (the relay's listener)
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	mu       sync.Mutex
	nonces   map[string]bool
	accounts map[string]*ecdsa.PublicKey
	orders   map[string]*fakeOrder
	n        int
	profile  string // the profile the last order asked for
	refuse   bool   // fail validation (as when port 443 can't be reached)
	lifetime time.Duration
}

type fakeOrder struct {
	ip, token, status string
	acct              *ecdsa.PublicKey
	cert              []byte
}

func newFakeCA(t *testing.T) *fakeCA {
	ca := &fakeCA{t: t, nonces: map[string]bool{}, accounts: map[string]*ecdsa.PublicKey{}, orders: map[string]*fakeOrder{}, lifetime: 160 * time.Hour}
	ca.rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake ACME Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ca.rootKey.PublicKey, ca.rootKey)
	ca.root, _ = x509.ParseCertificate(der)
	ca.srv = httptest.NewServer(http.HandlerFunc(ca.serve))
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeCA) url(p string) string { return ca.srv.URL + p }

func (ca *fakeCA) newNonce(w http.ResponseWriter) {
	ca.n++
	n := fmt.Sprintf("nonce-%d", ca.n)
	ca.nonces[n] = true
	w.Header().Set("Replay-Nonce", n)
}

func (ca *fakeCA) problem(w http.ResponseWriter, code int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": code})
}

// verify checks a JWS request and returns the payload and the account key.
func (ca *fakeCA) verify(r *http.Request) (payload []byte, acct *ecdsa.PublicKey, newKey bool, err error) {
	var jws struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return nil, nil, false, err
	}
	pj, _ := b64u.DecodeString(jws.Protected)
	var prot struct {
		Alg, Nonce, URL, Kid string
		JWK                  map[string]string
	}
	if err := json.Unmarshal(pj, &prot); err != nil || prot.Alg != "ES256" {
		return nil, nil, false, fmt.Errorf("bad protected header %s", pj)
	}
	if !ca.nonces[prot.Nonce] {
		return nil, nil, false, fmt.Errorf("badNonce")
	}
	delete(ca.nonces, prot.Nonce)
	if prot.URL != ca.url(r.URL.Path) {
		return nil, nil, false, fmt.Errorf("url %q signed for %q", prot.URL, r.URL.Path)
	}
	switch {
	case prot.Kid != "" && prot.JWK == nil:
		acct = ca.accounts[prot.Kid]
	case prot.Kid == "" && prot.JWK != nil:
		x, _ := b64u.DecodeString(prot.JWK["x"])
		y, _ := b64u.DecodeString(prot.JWK["y"])
		acct = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		newKey = true
	}
	if acct == nil {
		return nil, nil, false, fmt.Errorf("unknown account")
	}
	sig, _ := b64u.DecodeString(jws.Signature)
	h := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	if len(sig) != 64 || !ecdsa.Verify(acct, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, nil, false, fmt.Errorf("bad signature")
	}
	payload, _ = b64u.DecodeString(jws.Payload)
	return payload, acct, newKey, nil
}

func thumb(k *ecdsa.PublicKey) string {
	x := b64u.EncodeToString(k.X.FillBytes(make([]byte, 32)))
	y := b64u.EncodeToString(k.Y.FillBytes(make([]byte, 32)))
	h := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return b64u.EncodeToString(h[:])
}

func (ca *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if r.URL.Path == "/dir" {
		_ = json.NewEncoder(w).Encode(map[string]any{"newNonce": ca.url("/nonce"), "newAccount": ca.url("/acct"), "newOrder": ca.url("/order"),
			"meta": map[string]any{"profiles": map[string]string{"classic": "", "shortlived": ""}}})
		return
	}
	ca.newNonce(w)
	if r.URL.Path == "/nonce" {
		return
	}
	payload, acct, newKey, err := ca.verify(r)
	if err != nil {
		if err.Error() == "badNonce" {
			ca.problem(w, 400, "badNonce", "bad nonce")
		} else {
			ca.problem(w, 400, "malformed", err.Error())
		}
		return
	}
	switch p := r.URL.Path; {
	case p == "/acct":
		var req struct{ TermsOfServiceAgreed bool }
		_ = json.Unmarshal(payload, &req)
		if !newKey || !req.TermsOfServiceAgreed {
			ca.problem(w, 400, "malformed", "new accounts must agree to the terms and use jwk")
			return
		}
		kid := ca.url(fmt.Sprintf("/acct/%d", len(ca.accounts)+1))
		ca.accounts[kid] = acct
		w.Header().Set("Location", kid)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"status":"valid"}`))
	case p == "/order":
		var req struct {
			Identifiers []struct{ Type, Value string }
			Profile     string
		}
		_ = json.Unmarshal(payload, &req)
		if newKey || len(req.Identifiers) != 1 || req.Identifiers[0].Type != "ip" || net.ParseIP(req.Identifiers[0].Value) == nil {
			ca.problem(w, 400, "malformed", "one ip identifier, from a registered account")
			return
		}
		ca.profile = req.Profile
		id := fmt.Sprint(len(ca.orders) + 1)
		ca.orders[id] = &fakeOrder{ip: req.Identifiers[0].Value, token: "tok" + id, status: "pending", acct: acct}
		w.Header().Set("Location", ca.url("/order/"+id))
		w.WriteHeader(201)
		ca.writeOrder(w, id)
	case strings.HasPrefix(p, "/order/"):
		ca.writeOrder(w, strings.TrimPrefix(p, "/order/"))
	case strings.HasPrefix(p, "/authz/"):
		o := ca.orders[strings.TrimPrefix(p, "/authz/")]
		st := map[string]string{"pending": "pending", "processing": "pending", "valid": "valid", "invalid": "invalid", "ready": "valid"}[o.status]
		_ = json.NewEncoder(w).Encode(map[string]any{"status": st, "identifier": map[string]string{"type": "ip", "value": o.ip},
			"challenges": []map[string]string{{"type": "http-01", "url": ca.url("/nope"), "token": "x", "status": "pending"},
				{"type": "tls-alpn-01", "url": ca.url("/chall/" + strings.TrimPrefix(p, "/authz/")), "token": o.token, "status": st}}})
	case strings.HasPrefix(p, "/chall/"):
		id := strings.TrimPrefix(p, "/chall/")
		o := ca.orders[id]
		if err := ca.validate(o); err != nil || ca.refuse {
			ca.t.Logf("tls-alpn-01 validation: %v (refuse=%v)", err, ca.refuse)
			o.status = "invalid"
		} else {
			o.status = "ready"
		}
		_, _ = w.Write([]byte(`{"status":"processing"}`))
	case strings.HasPrefix(p, "/finalize/"):
		id := strings.TrimPrefix(p, "/finalize/")
		o := ca.orders[id]
		var req struct{ CSR string }
		_ = json.Unmarshal(payload, &req)
		der, _ := b64u.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if o.status != "ready" || err != nil || csr.CheckSignature() != nil || len(csr.IPAddresses) != 1 || csr.IPAddresses[0].String() != o.ip {
			ca.problem(w, 403, "badCSR", "csr must name exactly the order's ip")
			return
		}
		notBefore := time.Now()
		if ca.lifetime > time.Hour {
			notBefore = notBefore.Add(-time.Minute) // like a real CA, a little backdated for clock skew
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: notBefore,
			NotAfter: time.Now().Add(ca.lifetime), IPAddresses: csr.IPAddresses, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage: x509.KeyUsageDigitalSignature}
		leaf, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.root, csr.PublicKey, ca.rootKey)
		o.cert = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})...)
		o.status = "processing" // the client must poll the order until it is valid
		ca.writeOrder(w, id)
		o.status = "valid"
	case strings.HasPrefix(p, "/cert/"):
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(ca.orders[strings.TrimPrefix(p, "/cert/")].cert)
	default:
		ca.problem(w, 404, "malformed", "no such resource "+p)
	}
}

func (ca *fakeCA) writeOrder(w http.ResponseWriter, id string) {
	o := ca.orders[id]
	m := map[string]any{"status": o.status, "authorizations": []string{ca.url("/authz/" + id)}, "finalize": ca.url("/finalize/" + id)}
	if o.status == "valid" {
		m["certificate"] = ca.url("/cert/" + id)
	}
	_ = json.NewEncoder(w).Encode(m)
}

// validate does what the CA does for tls-alpn-01 (RFC 8737, RFC 8738): connect with only
// "acme-tls/1" offered, and the reverse-DNS name of the IP as SNI; the certificate must
// name the IP, and carry the critical acmeIdentifier extension with SHA-256 of the key
// authorization.
func (ca *fakeCA) validate(o *fakeOrder) error {
	ip := net.ParseIP(o.ip).To4()
	sni := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip[3], ip[2], ip[1], ip[0])
	conn, err := tls.Dial("tcp", ca.target, &tls.Config{NextProtos: []string{acmeALPN}, ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if st.NegotiatedProtocol != acmeALPN || len(st.PeerCertificates) != 1 {
		return fmt.Errorf("not an acme-tls/1 answer")
	}
	c := st.PeerCertificates[0]
	if len(c.IPAddresses) != 1 || !c.IPAddresses[0].Equal(net.ParseIP(o.ip)) {
		return fmt.Errorf("challenge certificate names %v", c.IPAddresses)
	}
	want := sha256.Sum256([]byte(o.token + "." + thumb(o.acct)))
	for _, e := range c.Extensions {
		if e.Id.Equal(oidACMEIdentifier) {
			var got []byte
			if _, err := asn1.Unmarshal(e.Value, &got); err != nil || !e.Critical || !bytes.Equal(got, want[:]) {
				return fmt.Errorf("acmeIdentifier wrong")
			}
			return nil
		}
	}
	return fmt.Errorf("no acmeIdentifier")
}

// A relay listener that serves through the certStore, like -public does.
func tlsRelay(t *testing.T, s *certStore) (addr string, hits *int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n++; _, _ = io.WriteString(w, "relay here") }),
		TLSConfig: &tls.Config{GetCertificate: s.GetCertificate, NextProtos: []string{"h2", "http/1.1", acmeALPN}}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), &n
}

func TestACMEObtainsIPCertificate(t *testing.T) {
	ca := newFakeCA(t)
	dir := t.TempDir()
	s, _ := newCertStore(dir, ca.url("/dir"), nil)
	addr, hits := tlsRelay(t, s)
	ca.target = addr
	ip := net.ParseIP("127.0.0.1")
	if !s.needsRenewal(ip) {
		t.Fatal("no certificate yet, so renewal is needed")
	}
	if err := s.renew(context.Background(), ip); err != nil {
		t.Fatal(err)
	}
	if ca.profile != "shortlived" {
		t.Errorf("IP certificates need the shortlived profile, order asked for %q", ca.profile)
	}
	// A browser (trusting the CA's root) now gets the relay over HTTPS at the IP.
	pool := x509.NewCertPool()
	pool.AddCert(ca.root)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal("HTTPS to the IP with the new certificate:", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "relay here" || *hits != 1 {
		t.Fatalf("got %q", b)
	}
	// The challenge certificate is no longer served once done.
	if _, err := tls.Dial("tcp", addr, &tls.Config{NextProtos: []string{acmeALPN}, InsecureSkipVerify: true}); err == nil {
		t.Error("acme-tls/1 still answered after the challenge finished")
	}
	if s.needsRenewal(ip) {
		t.Error("a fresh certificate shouldn't need renewal")
	}
	if s.needsRenewal(net.ParseIP("127.0.0.1")) || !s.needsRenewal(net.ParseIP("127.0.0.2")) {
		t.Error("a new public address needs a new certificate")
	}
	// Saved: a restart reuses it, and the same account key.
	s2, _ := newCertStore(dir, ca.url("/dir"), nil)
	if !s2.load(ip) || s2.needsRenewal(ip) {
		t.Fatal("saved certificate not reused after a restart")
	}
	// Renewing again (as at half-life) works with the saved account key.
	if err := s.renew(context.Background(), ip); err != nil {
		t.Fatal("second renewal:", err)
	}
}

func TestACMERenewsAtHalfLife(t *testing.T) {
	ca := newFakeCA(t)
	ca.lifetime = 10 * time.Second // issuing takes ~2 s of polling; half-life is at 5 s
	s, _ := newCertStore(t.TempDir(), ca.url("/dir"), nil)
	ca.target, _ = tlsRelay(t, s)
	ip := net.ParseIP("127.0.0.1")
	if err := s.renew(context.Background(), ip); err != nil {
		t.Fatal(err)
	}
	if s.needsRenewal(ip) {
		t.Fatal("renewal wanted right after issuance")
	}
	time.Sleep(time.Until(s.leaf.NotBefore.Add(5*time.Second + 300*time.Millisecond)))
	if !s.needsRenewal(ip) {
		t.Fatal("renewal not wanted past half the certificate's life")
	}
}

func TestACMEUnreachableIsExplained(t *testing.T) {
	ca := newFakeCA(t)
	ca.refuse = true
	s, _ := newCertStore(t.TempDir(), ca.url("/dir"), nil)
	ca.target, _ = tlsRelay(t, s)
	err := s.renew(context.Background(), net.ParseIP("127.0.0.1"))
	if err == nil || !strings.Contains(err.Error(), "port 443") {
		t.Fatalf("want an explanation about port 443, got %v", err)
	}
}

func TestACMERetriesBadNonce(t *testing.T) {
	ca := newFakeCA(t)
	s, _ := newCertStore(t.TempDir(), ca.url("/dir"), nil)
	ca.target, _ = tlsRelay(t, s)
	key, _ := s.accountKey()
	c, err := newACME(ca.url("/dir"), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.nonces = []string{"stale-nonce"} // the CA doesn't know it: badNonce, then a retry
	if err := c.register(); err != nil {
		t.Fatal("badNonce not retried:", err)
	}
}

func TestChallengeCertificate(t *testing.T) {
	c, err := challengeCert(net.ParseIP("203.0.113.7"), "token.thumb")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	want := sha256.Sum256([]byte("token.thumb"))
	found := false
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidACMEIdentifier) {
			var got []byte
			_, _ = asn1.Unmarshal(e.Value, &got)
			found = e.Critical && bytes.Equal(got, want[:])
		}
	}
	if !found || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "203.0.113.7" {
		t.Fatal("challenge certificate doesn't follow RFC 8737/8738")
	}
}

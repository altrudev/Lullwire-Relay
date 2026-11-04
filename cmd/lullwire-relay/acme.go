// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// A small ACME client (RFC 8555) that gets a browser-trusted certificate for this
// computer's public IP address (RFC 8738) from Let's Encrypt, proving control with the
// tls-alpn-01 challenge (RFC 8737): the CA connects to port 443 and asks for the
// "acme-tls/1" protocol, and the relay answers with a one-off certificate. That is the
// only challenge that needs nothing but the HTTPS port. Let's Encrypt issues IP address
// certificates only in its short-lived profile (about 6 days), so they are renewed
// automatically. Standard library only.

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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	letsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"
	acmeALPN    = "acme-tls/1"
)

// id-pe-acmeIdentifier (RFC 8737): carries SHA-256 of the key authorization.
var oidACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

var b64u = base64.RawURLEncoding

type acmeClient struct {
	dir     string // directory URL
	http    *http.Client
	key     *ecdsa.PrivateKey // account key
	kid     string            // account URL, once registered
	urls    struct{ NewNonce, NewAccount, NewOrder string }
	profile bool // the CA offers the "shortlived" profile
	nonces  []string
	mu      sync.Mutex
}

type acmeProblem struct {
	Type, Detail string
	Status       int
}

func (p *acmeProblem) Error() string { return fmt.Sprintf("%s (%s)", p.Detail, p.Type) }

func newACME(dir string, key *ecdsa.PrivateKey, hc *http.Client) (*acmeClient, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	c := &acmeClient{dir: dir, http: hc, key: key}
	resp, err := hc.Get(dir)
	if err != nil {
		return nil, fmt.Errorf("can't reach the certificate authority: %w", err)
	}
	defer resp.Body.Close()
	var d struct {
		NewNonce, NewAccount, NewOrder string
		Meta                           struct {
			Profiles map[string]any `json:"profiles"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil || d.NewOrder == "" {
		return nil, fmt.Errorf("unexpected ACME directory at %s", dir)
	}
	c.urls.NewNonce, c.urls.NewAccount, c.urls.NewOrder = d.NewNonce, d.NewAccount, d.NewOrder
	_, c.profile = d.Meta.Profiles["shortlived"]
	return c, nil
}

func (c *acmeClient) jwk() map[string]string {
	p := c.key.PublicKey
	return map[string]string{"crv": "P-256", "kty": "EC",
		"x": b64u.EncodeToString(p.X.FillBytes(make([]byte, 32))),
		"y": b64u.EncodeToString(p.Y.FillBytes(make([]byte, 32)))}
}

// thumbprint is the RFC 7638 JWK thumbprint (members in lexicographic order).
func (c *acmeClient) thumbprint() string {
	j := c.jwk()
	h := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + j["x"] + `","y":"` + j["y"] + `"}`))
	return b64u.EncodeToString(h[:])
}

func (c *acmeClient) nonce() (string, error) {
	c.mu.Lock()
	if n := len(c.nonces); n > 0 {
		v := c.nonces[n-1]
		c.nonces = c.nonces[:n-1]
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()
	resp, err := c.http.Head(c.urls.NewNonce)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if v := resp.Header.Get("Replay-Nonce"); v != "" {
		return v, nil
	}
	return "", errors.New("no nonce from the certificate authority")
}

// post sends a JWS-signed request. payload nil means POST-as-GET (empty payload).
func (c *acmeClient) post(url string, payload any, out any) (*http.Response, []byte, error) {
	for attempt := 0; ; attempt++ {
		n, err := c.nonce()
		if err != nil {
			return nil, nil, err
		}
		prot := map[string]any{"alg": "ES256", "nonce": n, "url": url}
		if c.kid != "" {
			prot["kid"] = c.kid
		} else {
			prot["jwk"] = c.jwk()
		}
		pj, _ := json.Marshal(prot)
		body := ""
		if payload != nil {
			b, _ := json.Marshal(payload)
			body = b64u.EncodeToString(b)
		}
		signing := b64u.EncodeToString(pj) + "." + body
		h := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, c.key, h[:])
		if err != nil {
			return nil, nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		jws, _ := json.Marshal(map[string]string{"protected": b64u.EncodeToString(pj), "payload": body, "signature": b64u.EncodeToString(sig)})
		resp, err := c.http.Post(url, "application/jose+json", bytes.NewReader(jws))
		if err != nil {
			return nil, nil, err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if v := resp.Header.Get("Replay-Nonce"); v != "" {
			c.mu.Lock()
			c.nonces = append(c.nonces, v)
			c.mu.Unlock()
		}
		if resp.StatusCode >= 400 {
			p := &acmeProblem{Status: resp.StatusCode}
			_ = json.Unmarshal(data, p)
			if p.Type == "urn:ietf:params:acme:error:badNonce" && attempt < 3 {
				continue
			}
			if p.Detail == "" {
				p.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
			}
			return resp, data, p
		}
		if out != nil && len(data) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return resp, data, fmt.Errorf("unexpected answer from the certificate authority: %w", err)
			}
		}
		return resp, data, nil
	}
}

func (c *acmeClient) register() error {
	resp, _, err := c.post(c.urls.NewAccount, map[string]any{"termsOfServiceAgreed": true}, nil)
	if err != nil {
		return fmt.Errorf("account: %w", err)
	}
	c.kid = resp.Header.Get("Location")
	if c.kid == "" {
		return errors.New("account: no account URL from the certificate authority")
	}
	return nil
}

type acmeOrder struct {
	Status         string
	Authorizations []string
	Finalize       string
	Certificate    string
	Error          *acmeProblem
}

type acmeAuthz struct {
	Status     string
	Challenges []struct{ Type, URL, Token, Status string }
}

// challengeCert builds the one-off tls-alpn-01 certificate for ip.
func challengeCert(ip net.IP, keyAuth string) (*tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(keyAuth))
	ext, _ := asn1.Marshal(sum[:])
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "acme-tls-alpn-01"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		IPAddresses:     []net.IP{ip},
		ExtraExtensions: []pkix.Extension{{Id: oidACMEIdentifier, Critical: true, Value: ext}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

// obtain gets a certificate for ip. present is called with the challenge certificate
// to serve on port 443 for "acme-tls/1" (nil to stop serving it).
func (c *acmeClient) obtain(ctx context.Context, ip net.IP, present func(*tls.Certificate)) (chainPEM, keyPEM []byte, err error) {
	if c.kid == "" {
		if err := c.register(); err != nil {
			return nil, nil, err
		}
	}
	req := map[string]any{"identifiers": []map[string]string{{"type": "ip", "value": ip.String()}}}
	if c.profile {
		req["profile"] = "shortlived" // Let's Encrypt issues IP certificates only in this profile
	}
	var o acmeOrder
	resp, _, err := c.post(c.urls.NewOrder, req, &o)
	if err != nil {
		return nil, nil, fmt.Errorf("order: %w", err)
	}
	orderURL := resp.Header.Get("Location")
	defer present(nil)
	for _, az := range o.Authorizations {
		var a acmeAuthz
		if _, _, err := c.post(az, nil, &a); err != nil {
			return nil, nil, fmt.Errorf("authorization: %w", err)
		}
		if a.Status == "valid" {
			continue
		}
		var url, token string
		for _, ch := range a.Challenges {
			if ch.Type == "tls-alpn-01" {
				url, token = ch.URL, ch.Token
			}
		}
		if url == "" {
			return nil, nil, errors.New("the certificate authority offered no tls-alpn-01 challenge")
		}
		cert, err := challengeCert(ip, token+"."+c.thumbprint())
		if err != nil {
			return nil, nil, err
		}
		present(cert)
		if _, _, err := c.post(url, map[string]any{}, nil); err != nil {
			return nil, nil, fmt.Errorf("challenge: %w", err)
		}
		if err := c.wait(ctx, az, &a, func() (string, *acmeProblem) {
			for _, ch := range a.Challenges {
				if ch.Type == "tls-alpn-01" && ch.Status == "invalid" {
					return "invalid", &acmeProblem{Detail: "the certificate authority couldn't reach this computer on port 443 at " + ip.String()}
				}
			}
			return a.Status, nil
		}); err != nil {
			return nil, nil, err
		}
		present(nil)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{IPAddresses: []net.IP{ip}}, k)
	if err != nil {
		return nil, nil, err
	}
	if _, _, err := c.post(o.Finalize, map[string]string{"csr": b64u.EncodeToString(csr)}, &o); err != nil {
		return nil, nil, fmt.Errorf("finalize: %w", err)
	}
	if o.Status != "valid" {
		if err := c.wait(ctx, orderURL, &o, func() (string, *acmeProblem) { return o.Status, o.Error }); err != nil {
			return nil, nil, err
		}
	}
	_, chain, err := c.post(o.Certificate, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("download: %w", err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	return chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

// wait polls url (POST-as-GET into out) until state() says valid, for up to 2 minutes.
func (c *acmeClient) wait(ctx context.Context, url string, out any, state func() (string, *acmeProblem)) error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		s, p := state()
		switch s {
		case "valid":
			return nil
		case "invalid":
			if p == nil {
				p = &acmeProblem{Detail: "the certificate authority refused the request"}
			}
			return p
		}
		if time.Now().After(deadline) {
			return errors.New("the certificate authority took too long")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		if _, _, err := c.post(url, nil, out); err != nil {
			return err
		}
	}
}

// ---- keeping a certificate for this computer's address ----

// certStore keeps the account key and the current certificate in dir (mode 0700),
// serves them over TLS, and renews before half the certificate's life has passed.
type certStore struct {
	dir, directory string
	hc             *http.Client
	mu             sync.RWMutex
	cert           *tls.Certificate
	leaf           *x509.Certificate
	challenge      *tls.Certificate
}

func newCertStore(dir, directory string, hc *http.Client) (*certStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &certStore{dir: dir, directory: directory, hc: hc}, nil
}

// GetCertificate answers the CA's tls-alpn-01 check while one is running, and serves
// the current certificate to everyone else.
func (s *certStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range hello.SupportedProtos {
		if p == acmeALPN {
			if s.challenge == nil {
				return nil, errors.New("no ACME challenge in progress")
			}
			return s.challenge, nil
		}
	}
	if s.cert == nil {
		return nil, errors.New("no certificate yet")
	}
	return s.cert, nil
}

func (s *certStore) present(c *tls.Certificate) { s.mu.Lock(); s.challenge = c; s.mu.Unlock() }

func (s *certStore) accountKey() (*ecdsa.PrivateKey, error) {
	p := filepath.Join(s.dir, "account.pem")
	if b, err := os.ReadFile(p); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			return x509.ParseECPrivateKey(blk.Bytes)
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	d, _ := x509.MarshalECPrivateKey(k)
	return k, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: d}), 0o600)
}

func certFile(dir string, ip net.IP) string {
	return filepath.Join(dir, strings.NewReplacer(":", "_", ".", "_").Replace(ip.String()))
}

// load uses a certificate saved earlier for ip, if it is still good for a while.
func (s *certStore) load(ip net.IP) bool {
	base := certFile(s.dir, ip)
	c, err := tls.LoadX509KeyPair(base+".crt", base+".key")
	if err != nil {
		return false
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil || !leaf.NotAfter.After(time.Now().Add(time.Hour)) {
		return false
	}
	s.set(&c, leaf)
	return true
}

func (s *certStore) set(c *tls.Certificate, leaf *x509.Certificate) {
	c.Leaf = leaf
	s.mu.Lock()
	s.cert, s.leaf = c, leaf
	s.mu.Unlock()
}

// needsRenewal is true without a certificate for ip, or once half its life has passed.
func (s *certStore) needsRenewal(ip net.IP) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.leaf == nil || len(s.leaf.IPAddresses) == 0 || !s.leaf.IPAddresses[0].Equal(ip) {
		return true
	}
	half := s.leaf.NotBefore.Add(s.leaf.NotAfter.Sub(s.leaf.NotBefore) / 2)
	return time.Now().After(half)
}

// renew gets a new certificate for ip and saves it.
func (s *certStore) renew(ctx context.Context, ip net.IP) error {
	key, err := s.accountKey()
	if err != nil {
		return err
	}
	c, err := newACME(s.directory, key, s.hc)
	if err != nil {
		return err
	}
	chain, keyPEM, err := c.obtain(ctx, ip, s.present)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	base := certFile(s.dir, ip)
	if err := atomicWrite(base+".key", keyPEM); err != nil {
		return err
	}
	_ = os.Chmod(base+".key", 0o600)
	if err := atomicWrite(base+".crt", chain); err != nil {
		return err
	}
	s.set(&cert, leaf)
	return nil
}

func (s *certStore) expires() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.leaf == nil {
		return time.Time{}
	}
	return s.leaf.NotAfter
}

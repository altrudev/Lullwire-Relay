// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// -public: run the relay on an ordinary computer and make it reachable from the
// internet on its own. The relay asks the home router to forward port 443 to it (UPnP or
// NAT-PMP), finds the network's public address, and gets a browser-trusted certificate
// for that address from Let's Encrypt, renewed automatically. No domain, proxy, tunnel
// or other program is involved. It can't work where the internet provider shares one
// address among many customers (carrier-grade NAT); the relay says so plainly.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"time"
)

const publicPort = 443 // tls-alpn-01, and https:// addresses without a port

type publicHost struct {
	certs    *certStore
	mapper   portMapper // nil when this computer has a public address itself
	local    netip.Addr
	internal int
	logf     func(string, ...any)
	mu       sync.Mutex
	ip       netip.Addr
}

// preparePublic finds the router and the public address and opens the port. It doesn't
// need the listener yet; getting the certificate does (see run).
func preparePublic(ctx context.Context, data, directory string, internal int, hc *http.Client, logf func(string, ...any)) (*publicHost, error) {
	certs, err := newCertStore(filepath.Join(data, "certs"), directory, hc)
	if err != nil {
		return nil, err
	}
	p := &publicHost{certs: certs, internal: internal, logf: logf}
	if p.local, err = localAddr(); err != nil {
		return nil, fmt.Errorf("this computer has no route to the internet: %w", err)
	}
	if ok, _ := reachableKind(p.local); ok {
		// A computer with a public address of its own (a VPS, or a direct connection).
		if internal != publicPort {
			return nil, fmt.Errorf("this computer has a public address (%s), so the relay must listen on port 443 itself: add -public-port 443 (on Linux, as root or with CAP_NET_BIND_SERVICE)", p.local)
		}
		p.ip = p.local
		return p, nil
	}
	p.mapper, err = findRouter(ctx, p.local)
	if err != nil {
		return nil, fmt.Errorf("%w. Turn on UPnP or NAT-PMP in the router's settings, or forward TCP port 443 to %s port %d yourself and run with -public-ip <your public address>", err, p.local, internal)
	}
	if p.ip, err = p.mapper.ExternalIP(ctx); err != nil {
		return nil, fmt.Errorf("the router (%s) didn't say this network's public address: %w", p.mapper.Name(), err)
	}
	if ok, why := reachableKind(p.ip); !ok {
		return nil, fmt.Errorf("this network can't host a relay: %s. Use the single-file relay (lullwire-relay.php) on web hosting, or a server, instead", why)
	}
	if err := p.mapPort(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// manualPublic is for a router set up by hand: port 443 already forwarded here.
func manualPublic(data, directory string, ip netip.Addr, internal int, hc *http.Client, logf func(string, ...any)) (*publicHost, error) {
	if ok, why := reachableKind(ip); !ok {
		return nil, fmt.Errorf("-public-ip %s: %s", ip, why)
	}
	certs, err := newCertStore(filepath.Join(data, "certs"), directory, hc)
	if err != nil {
		return nil, err
	}
	return &publicHost{certs: certs, internal: internal, logf: logf, ip: ip}, nil
}

func (p *publicHost) mapPort(ctx context.Context) error {
	if p.mapper == nil {
		return nil
	}
	got, err := p.mapper.Map(ctx, publicPort, p.internal, p.local, 2*time.Hour)
	if err != nil {
		return fmt.Errorf("the router (%s) wouldn't forward port 443 here: %w. If another device already uses port 443, free it, or forward it here by hand", p.mapper.Name(), err)
	}
	if got != publicPort {
		_ = p.mapper.Unmap(ctx, got, p.internal)
		return fmt.Errorf("the router (%s) offered port %d instead of 443, which certificates and https:// addresses need", p.mapper.Name(), got)
	}
	return nil
}

func (p *publicHost) addr() netip.Addr { p.mu.Lock(); defer p.mu.Unlock(); return p.ip }

// URL is the relay's public address.
func (p *publicHost) URL(base string) string {
	ip := p.addr()
	host := ip.String()
	if ip.Is6() {
		host = "[" + host + "]"
	}
	return "https://" + host + base
}

func (p *publicHost) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: p.certs.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acmeALPN},
	}
}

// ensureCert loads a saved certificate for the current address, or gets a new one. The
// TLS listener must already be running: the certificate authority connects to it.
func (p *publicHost) ensureCert(ctx context.Context) error {
	ip := p.addr()
	if p.certs.load(ip.AsSlice()) && !p.certs.needsRenewal(ip.AsSlice()) {
		return nil
	}
	p.logf("getting a certificate for %s from the certificate authority…", ip)
	if err := p.certs.renew(ctx, ip.AsSlice()); err != nil {
		var prob *acmeProblem
		if errors.As(err, &prob) && prob.Status == 0 {
			return err // our own explanation already
		}
		return fmt.Errorf("couldn't get a certificate for %s: %w", ip, err)
	}
	p.logf("certificate for %s ready, valid until %s (renewed automatically)", ip, p.certs.expires().Format("2006-01-02 15:04"))
	return nil
}

// maintain keeps the router mapping, the public address and the certificate current.
func (p *publicHost) maintain(ctx context.Context, base string) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if p.mapper != nil {
				uctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_ = p.mapper.Unmap(uctx, publicPort, p.internal)
				cancel()
			}
			return
		case <-t.C:
		}
		if p.mapper != nil {
			if err := p.mapPort(ctx); err != nil {
				p.logf("router: %v", err)
			}
			if ip, err := p.mapper.ExternalIP(ctx); err == nil && ip != p.addr() {
				if ok, why := reachableKind(ip); !ok {
					p.logf("the public address changed to %s, which can't be reached from the internet: %s", ip, why)
					continue
				}
				p.mu.Lock()
				old := p.ip
				p.ip = ip
				p.mu.Unlock()
				p.logf("the public address changed from %s to %s: the relay is now at %s (invites made before point at the old address)", old, ip, p.URL(base))
			}
		}
		if p.certs.needsRenewal(p.addr().AsSlice()) {
			if err := p.ensureCert(ctx); err != nil {
				p.logf("certificate: %v (will try again in 10 minutes; the current one is valid until %s)", err, p.certs.expires().Format("2006-01-02 15:04"))
			}
		}
	}
}

// listenPublic opens the TLS listener on all interfaces (the router forwards to this
// computer's home-network address).
func listenPublic(internal int) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", internal))
	if err != nil {
		return nil, fmt.Errorf("can't listen on port %d: %w", internal, err)
	}
	return ln, nil
}

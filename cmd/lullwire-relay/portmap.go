// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Asking the home router to forward a port to this computer, and to say what this
// network's public address is: UPnP IGD (most home routers) and NAT-PMP (Apple and
// many others). Standard library only. Neither protocol has any authentication: they
// only work from inside the home network, which is the point.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// A portMapper forwards an external TCP port on the router to a port on this computer.
type portMapper interface {
	Name() string
	ExternalIP(ctx context.Context) (netip.Addr, error)
	// Map forwards external -> local:internal for about lease, returning the external
	// port the router actually gave (NAT-PMP may pick another).
	Map(ctx context.Context, external, internal int, local netip.Addr, lease time.Duration) (int, error)
	Unmap(ctx context.Context, external, internal int) error
}

// ---- UPnP Internet Gateway Device ----

type upnpIGD struct {
	control, service string
}

func (u *upnpIGD) Name() string { return "UPnP" }

var ssdpTargets = []string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

// discoverUPnP looks for a router on the local network (SSDP multicast).
func discoverUPnP(ctx context.Context, wait time.Duration) (*upnpIGD, error) {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for _, st := range ssdpTargets {
		msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n"
		_, _ = conn.WriteTo([]byte(msg), dst)
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	seen := map[string]bool{}
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		loc := ssdpLocation(buf[:n])
		if loc == "" || seen[loc] {
			continue
		}
		seen[loc] = true
		if igd, err := upnpFromLocation(ctx, loc); err == nil {
			return igd, nil
		}
	}
	return nil, errors.New("no UPnP router answered")
}

// ssdpLocation reads the LOCATION header of an SSDP answer.
func ssdpLocation(b []byte) string {
	r := bufio.NewReader(bytes.NewReader(b))
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "HTTP/1.1 200") {
		return ""
	}
	for {
		line, err := r.ReadString('\n')
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "location") {
			return strings.TrimSpace(v)
		}
		if err != nil {
			return ""
		}
	}
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}
type upnpDevice struct {
	Services []upnpService `xml:"serviceList>service"`
	Devices  []upnpDevice  `xml:"deviceList>device"`
}

// upnpFromLocation reads the router's description and finds its WAN connection service.
func upnpFromLocation(ctx context.Context, loc string) (*upnpIGD, error) {
	base, err := url.Parse(loc)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errors.New("bad UPnP location")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var root struct {
		URLBase string     `xml:"URLBase"`
		Device  upnpDevice `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&root); err != nil {
		return nil, err
	}
	if root.URLBase != "" {
		if b, err := url.Parse(root.URLBase); err == nil {
			base = b
		}
	}
	var find func(d upnpDevice) *upnpService
	find = func(d upnpDevice) *upnpService {
		for i, s := range d.Services {
			if strings.Contains(s.ServiceType, ":WANIPConnection:") || strings.Contains(s.ServiceType, ":WANPPPConnection:") {
				return &d.Services[i]
			}
		}
		for _, c := range d.Devices {
			if s := find(c); s != nil {
				return s
			}
		}
		return nil
	}
	s := find(root.Device)
	if s == nil {
		return nil, errors.New("the router doesn't offer port forwarding over UPnP")
	}
	ctl, err := base.Parse(s.ControlURL)
	if err != nil {
		return nil, err
	}
	return &upnpIGD{control: ctl.String(), service: s.ServiceType}, nil
}

// soap calls an action on the router and returns the named result values.
func (u *upnpIGD) soap(ctx context.Context, action string, args [][2]string) (map[string]string, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	b.WriteString(`<u:` + action + ` xmlns:u="` + u.service + `">`)
	for _, a := range args {
		b.WriteString("<" + a[0] + ">")
		_ = xml.EscapeText(&b, []byte(a[1]))
		b.WriteString("</" + a[0] + ">")
	}
	b.WriteString(`</u:` + action + `></s:Body></s:Envelope>`)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.control, strings.NewReader(b.String()))
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+u.service+`#`+action+`"`)
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	out := map[string]string{}
	d := xml.NewDecoder(bytes.NewReader(body))
	var name string
	for {
		t, err := d.Token()
		if err != nil {
			break
		}
		switch t := t.(type) {
		case xml.StartElement:
			name = t.Name.Local
		case xml.CharData:
			if name != "" {
				out[name] += string(t)
			}
		case xml.EndElement:
			name = ""
		}
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("router refused %s: %s %s", action, out["errorCode"], strings.TrimSpace(out["errorDescription"]))
	}
	return out, nil
}

func (u *upnpIGD) ExternalIP(ctx context.Context) (netip.Addr, error) {
	r, err := u.soap(ctx, "GetExternalIPAddress", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(strings.TrimSpace(r["NewExternalIPAddress"]))
}

func (u *upnpIGD) Map(ctx context.Context, external, internal int, local netip.Addr, lease time.Duration) (int, error) {
	args := func(l int) [][2]string {
		return [][2]string{{"NewRemoteHost", ""}, {"NewExternalPort", strconv.Itoa(external)}, {"NewProtocol", "TCP"},
			{"NewInternalPort", strconv.Itoa(internal)}, {"NewInternalClient", local.String()}, {"NewEnabled", "1"},
			{"NewPortMappingDescription", "Lullwire Relay"}, {"NewLeaseDuration", strconv.Itoa(l)}}
	}
	_, err := u.soap(ctx, "AddPortMapping", args(int(lease/time.Second)))
	if err != nil && strings.Contains(err.Error(), " 725 ") { // OnlyPermanentLeasesSupported
		_, err = u.soap(ctx, "AddPortMapping", args(0))
	}
	if err != nil {
		return 0, err
	}
	return external, nil
}

func (u *upnpIGD) Unmap(ctx context.Context, external, _ int) error {
	_, err := u.soap(ctx, "DeletePortMapping", [][2]string{{"NewRemoteHost", ""}, {"NewExternalPort", strconv.Itoa(external)}, {"NewProtocol", "TCP"}})
	return err
}

// ---- NAT-PMP (RFC 6886) ----

type natPMP struct {
	gateway netip.AddrPort
}

func (n *natPMP) Name() string { return "NAT-PMP" }

func (n *natPMP) call(ctx context.Context, req []byte, want int) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(n.gateway))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	buf := make([]byte, 64)
	// Retransmit with doubling waits (250 ms, 500 ms, 1 s), as the RFC asks.
	for wait := 250 * time.Millisecond; wait <= time.Second && ctx.Err() == nil; wait *= 2 {
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		k, err := conn.Read(buf)
		if err != nil {
			continue
		}
		if k < want || buf[0] != 0 || buf[1] != req[1]+128 {
			continue
		}
		if code := binary.BigEndian.Uint16(buf[2:4]); code != 0 {
			return nil, fmt.Errorf("router refused (NAT-PMP result %d)", code)
		}
		return buf[:k], nil
	}
	return nil, errors.New("no NAT-PMP answer")
}

func (n *natPMP) ExternalIP(ctx context.Context) (netip.Addr, error) {
	r, err := n.call(ctx, []byte{0, 0}, 12)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4([4]byte(r[8:12])), nil
}

func (n *natPMP) Map(ctx context.Context, external, internal int, _ netip.Addr, lease time.Duration) (int, error) {
	req := make([]byte, 12)
	req[1] = 2 // map TCP
	binary.BigEndian.PutUint16(req[4:], uint16(internal))
	binary.BigEndian.PutUint16(req[6:], uint16(external))
	binary.BigEndian.PutUint32(req[8:], uint32(lease/time.Second))
	r, err := n.call(ctx, req, 16)
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(r[10:12])), nil
}

func (n *natPMP) Unmap(ctx context.Context, external, internal int) error {
	req := make([]byte, 12)
	req[1] = 2
	binary.BigEndian.PutUint16(req[4:], uint16(internal)) // lifetime 0 and external 0 delete it
	_, err := n.call(ctx, req, 16)
	return err
}

// ---- this computer's address on the home network ----

// localAddr is the address this computer uses to reach the internet. Connecting a UDP
// socket sends nothing; it only asks the system which route and address it would use.
func localAddr() (netip.Addr, error) {
	c, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1: never actually contacted
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

// gatewayGuesses: the default route on Linux; elsewhere, the usual router address in
// this computer's network (x.y.z.1), which is right for nearly every home router.
func gatewayGuesses(local netip.Addr) []netip.Addr {
	var out []netip.Addr
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) > 2 && f[1] == "00000000" {
				if v, err := strconv.ParseUint(f[2], 16, 32); err == nil && v != 0 {
					var a [4]byte
					binary.LittleEndian.PutUint32(a[:], uint32(v))
					out = append(out, netip.AddrFrom4(a))
				}
			}
		}
	}
	if local.Is4() {
		a := local.As4()
		a[3] = 1
		if g := netip.AddrFrom4(a); g != local && (len(out) == 0 || out[0] != g) {
			out = append(out, g)
		}
	}
	return out
}

// findRouter tries UPnP, then NAT-PMP at the likely router addresses.
func findRouter(ctx context.Context, local netip.Addr) (portMapper, error) {
	if igd, err := discoverUPnP(ctx, 3*time.Second); err == nil {
		return igd, nil
	}
	for _, g := range gatewayGuesses(local) {
		n := &natPMP{gateway: netip.AddrPortFrom(g, 5351)}
		if _, err := n.ExternalIP(ctx); err == nil {
			return n, nil
		}
	}
	return nil, errors.New("the router didn't answer UPnP or NAT-PMP")
}

// cgnat is the shared address space carriers use when many customers share one public
// address (RFC 6598). Nothing on the internet can connect to an address behind it.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// reachableKind explains whether addr can be reached from the internet.
func reachableKind(addr netip.Addr) (ok bool, why string) {
	switch {
	case !addr.IsValid() || addr.IsUnspecified():
		return false, "the router didn't report a public address"
	case cgnat.Contains(addr):
		return false, "your internet provider shares one public address among many customers (carrier-grade NAT), so nothing on the internet can connect to this network"
	case addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast():
		return false, "this router is itself behind another router (its outside address " + addr.String() + " is a private one)"
	}
	return true, ""
}

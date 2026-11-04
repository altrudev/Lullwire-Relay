// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIGD is a home router's UPnP interface: a device description (the WAN connection
// service nested two devices deep, as on real routers) and a SOAP control endpoint.
type fakeIGD struct {
	mu             sync.Mutex
	mappings       map[string]string // external port -> "internal client:port"
	permanentOnly  bool
	lastLease      string
	actions        []string
	soapActionHdrs []string
}

func (f *fakeIGD) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rootDesc.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/ctl/CmnIfCfg</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>
</serviceList></device></deviceList></device></deviceList></device></root>`)
	})
	mux.HandleFunc("/ctl/IPConn", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		b := string(body)
		f.soapActionHdrs = append(f.soapActionHdrs, r.Header.Get("SOAPAction"))
		arg := func(n string) string {
			_, rest, _ := strings.Cut(b, "<"+n+">")
			v, _, _ := strings.Cut(rest, "</"+n+">")
			return v
		}
		fault := func(code, desc string) {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError><errorCode>`+code+`</errorCode><errorDescription>`+desc+`</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`)
		}
		ok := func(inner string) {
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>`+inner+`</s:Body></s:Envelope>`)
		}
		switch {
		case strings.Contains(b, "<u:GetExternalIPAddress"):
			f.actions = append(f.actions, "GetExternalIPAddress")
			ok(`<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></u:GetExternalIPAddressResponse>`)
		case strings.Contains(b, "<u:AddPortMapping"):
			f.actions = append(f.actions, "AddPortMapping")
			f.lastLease = arg("NewLeaseDuration")
			if f.permanentOnly && f.lastLease != "0" {
				fault("725", "OnlyPermanentLeasesSupported")
				return
			}
			if arg("NewProtocol") != "TCP" || arg("NewPortMappingDescription") != "Lullwire Relay" {
				fault("402", "Invalid Args")
				return
			}
			f.mappings[arg("NewExternalPort")] = arg("NewInternalClient") + ":" + arg("NewInternalPort")
			ok(`<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>`)
		case strings.Contains(b, "<u:DeletePortMapping"):
			f.actions = append(f.actions, "DeletePortMapping")
			delete(f.mappings, arg("NewExternalPort"))
			ok(`<u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>`)
		default:
			fault("401", "Invalid Action")
		}
	})
	return mux
}

func TestUPnPRouter(t *testing.T) {
	f := &fakeIGD{mappings: map[string]string{}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	ctx := context.Background()
	igd, err := upnpFromLocation(ctx, srv.URL+"/rootDesc.xml")
	if err != nil {
		t.Fatal(err)
	}
	if igd.control != srv.URL+"/ctl/IPConn" || !strings.Contains(igd.service, "WANIPConnection:1") {
		t.Fatalf("found %+v", igd)
	}
	ip, err := igd.ExternalIP(ctx)
	if err != nil || ip.String() != "203.0.113.9" {
		t.Fatalf("external ip %v %v", ip, err)
	}
	local := netip.MustParseAddr("192.168.1.20")
	if got, err := igd.Map(ctx, 443, 8443, local, 2*time.Hour); err != nil || got != 443 || f.mappings["443"] != "192.168.1.20:8443" || f.lastLease != "7200" {
		t.Fatalf("map: %v %v %v lease %s", got, err, f.mappings, f.lastLease)
	}
	if h := f.soapActionHdrs[len(f.soapActionHdrs)-1]; h != `"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"` {
		t.Errorf("SOAPAction header %s", h)
	}
	if err := igd.Unmap(ctx, 443, 8443); err != nil || len(f.mappings) != 0 {
		t.Fatalf("unmap: %v %v", err, f.mappings)
	}
	// Routers that only allow permanent mappings answer 725; the relay retries with 0.
	f.permanentOnly = true
	if _, err := igd.Map(ctx, 443, 8443, local, 2*time.Hour); err != nil || f.lastLease != "0" {
		t.Fatalf("permanent-only router: %v lease %s", err, f.lastLease)
	}
}

func TestSSDPLocation(t *testing.T) {
	ans := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n"
	if got := ssdpLocation([]byte(ans)); got != "http://192.168.1.1:5000/rootDesc.xml" {
		t.Fatalf("got %q", got)
	}
	if got := ssdpLocation([]byte("NOTIFY * HTTP/1.1\r\nLOCATION: http://x/\r\n\r\n")); got != "" {
		t.Fatalf("a NOTIFY is not an answer, got %q", got)
	}
	if _, err := upnpFromLocation(context.Background(), "file:///etc/passwd"); err == nil {
		t.Fatal("non-http location accepted")
	}
}

// fakeNATPMP answers NAT-PMP on a UDP port, like an Apple or OpenWrt router.
func fakeNATPMP(t *testing.T, giveExternal uint16) (netip.AddrPort, *[]uint16) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var seen []uint16
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 2 || buf[0] != 0 {
				continue
			}
			switch buf[1] {
			case 0:
				resp := []byte{0, 128, 0, 0, 0, 0, 0, 1, 198, 51, 100, 4}
				_, _ = pc.WriteTo(resp, from)
			case 2:
				internal := binary.BigEndian.Uint16(buf[4:6])
				ext := binary.BigEndian.Uint16(buf[6:8])
				seen = append(seen, ext)
				if giveExternal != 0 && ext != 0 {
					ext = giveExternal
				}
				resp := make([]byte, 16)
				resp[1] = 130
				binary.BigEndian.PutUint16(resp[8:], internal)
				binary.BigEndian.PutUint16(resp[10:], ext)
				copy(resp[12:], buf[8:12])
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort(), &seen
}

func TestNATPMPRouter(t *testing.T) {
	ctx := context.Background()
	gw, seen := fakeNATPMP(t, 0)
	n := &natPMP{gateway: gw}
	ip, err := n.ExternalIP(ctx)
	if err != nil || ip.String() != "198.51.100.4" {
		t.Fatalf("external ip %v %v", ip, err)
	}
	if got, err := n.Map(ctx, 443, 8443, netip.Addr{}, time.Hour); err != nil || got != 443 {
		t.Fatalf("map %v %v", got, err)
	}
	if err := n.Unmap(ctx, 443, 8443); err != nil || (*seen)[len(*seen)-1] != 0 {
		t.Fatalf("unmap %v %v", err, *seen)
	}
	// A router that hands out another port than 443 can't be used: preparePublic
	// refuses, because certificates and https:// addresses need 443.
	gw2, _ := fakeNATPMP(t, 40443)
	p := &publicHost{mapper: &natPMP{gateway: gw2}, internal: 8443, local: netip.MustParseAddr("192.168.1.20")}
	if err := p.mapPort(ctx); err == nil || !strings.Contains(err.Error(), "40443") {
		t.Fatalf("other port not refused: %v", err)
	}
}

func TestReachable(t *testing.T) {
	for addr, want := range map[string]bool{
		"203.0.113.9": true, "8.8.8.8": true, "2001:db8::1": true,
		"100.64.0.1": false, "100.127.255.254": false, // carrier-grade NAT
		"192.168.0.10": false, "10.1.2.3": false, "172.16.5.4": false, // a router behind a router
		"127.0.0.1": false, "0.0.0.0": false, "fe80::1": false,
	} {
		if ok, why := reachableKind(netip.MustParseAddr(addr)); ok != want || (!ok && why == "") {
			t.Errorf("%s: reachable=%v (%s), want %v", addr, ok, why, want)
		}
	}
	if ok, why := reachableKind(netip.MustParseAddr("100.70.1.1")); ok || !strings.Contains(why, "carrier-grade NAT") {
		t.Errorf("CGNAT not explained: %s", why)
	}
}

func TestGatewayGuesses(t *testing.T) {
	g := gatewayGuesses(netip.MustParseAddr("192.168.1.20"))
	found := false
	for _, a := range g {
		found = found || a.String() == "192.168.1.1"
	}
	if !found {
		t.Fatalf("x.y.z.1 not among the guesses: %v", g)
	}
}

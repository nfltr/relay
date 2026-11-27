// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// fakeIGD is a UPnP InternetGatewayDevice on 127.0.0.1: an SSDP responder
// at its own port naming its description (location: the LOCATION it
// answers with, "" for its own), and the description and WANIPConnection
// control on an HTTP server. perm: it grants only permanent leases (725).
// ext: the external address it reports.
type fakeIGD struct {
	ssdp     int
	srv      *httptest.Server
	perm     bool
	ext      string
	location string
	mu       sync.Mutex
	calls    []string // "<action> <NewExternalPort> <NewInternalClient> <NewLeaseDuration>"
	http     int      // HTTP requests
}

func serveIGD(t *testing.T, perm bool, location string) *fakeIGD {
	t.Helper()
	g := &fakeIGD{perm: perm, location: location, ext: "127.0.0.1"}
	const st = "urn:schemas-upnp-org:service:WANIPConnection:1"
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.http++
		g.mu.Unlock()
		if r.Method == http.MethodGet {
			fmt.Fprintf(w, `<?xml version="1.0"?><root><device><serviceList>`+
				`<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3f</controlURL></service>`+
				`<service><serviceType>%s</serviceType><controlURL>/ctl?a=1&amp;b=2</controlURL></service>`+
				`</serviceList></device></root>`, st)
			return
		}
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		action := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("SOAPAction"), `"`+st+"#"), `"`)
		if r.URL.RawQuery != "a=1&b=2" || !strings.Contains(body, "<u:"+action+` xmlns:u="`+st+`">`) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		g.mu.Lock()
		g.calls = append(g.calls, strings.Join([]string{action, xmlText(body, "NewExternalPort"), xmlText(body, "NewInternalClient"), xmlText(body, "NewLeaseDuration")}, " "))
		g.mu.Unlock()
		if action == "AddPortMapping" && g.perm && xmlText(body, "NewLeaseDuration") != "0" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`)
			return
		}
		fmt.Fprintf(w, `<s:Envelope><s:Body><u:%sResponse xmlns:u="%s"><NewExternalIPAddress>%s</NewExternalIPAddress></u:%sResponse></s:Body></s:Envelope>`, action, st, g.ext, action)
	}))
	t.Cleanup(g.srv.Close)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	g.ssdp = pc.LocalAddr().(*net.UDPAddr).Port
	loc := g.location
	if loc == "" {
		loc = g.srv.URL + "/rootDesc.xml"
	}
	go func() {
		b := make([]byte, 1024)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			if strings.HasPrefix(string(b[:n]), "M-SEARCH * HTTP/1.1\r\n") && strings.Contains(string(b[:n]), "InternetGatewayDevice") {
				_, _ = pc.WriteTo([]byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLocation: "+loc+"\r\n\r\n"), from)
			}
		}
	}()
	return g
}

func (g *fakeIGD) record() ([]string, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.calls...), g.http
}

// upnpEndpoint is an endpoint whose gateway (127.0.0.1) answers neither
// PCP nor NAT-PMP, only g's UPnP.
func upnpEndpoint(t *testing.T, g *fakeIGD) *DirectEndpoint {
	t.Helper()
	ep, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	ep.loopback = true
	ep.gateway, ep.natpmp, ep.ssdp = localGateway, quietSSDP(t), g.ssdp
	return ep
}

// TestDirectPortMapUPnP: an IGD that speaks neither PCP nor NAT-PMP maps
// the socket's own port for portMapLifetime to this machine's LAN address;
// a renewal goes to the same service without discovery; Close deletes it.
func TestDirectPortMapUPnP(t *testing.T) {
	g := serveIGD(t, false, "")
	ep := upnpEndpoint(t, g)
	port := ep.pc.LocalAddr().(*net.UDPAddr).Port
	for range 2 {
		a, ok := ep.mapped()
		if !ok || a != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)) { // #nosec G115 -- a UDP port
			t.Fatalf("mapped %v %v, want 127.0.0.1:%d", a, ok, port)
		}
	}
	if err := ep.Close(); err != nil {
		t.Fatal(err)
	}
	calls, gets := g.record()
	add := fmt.Sprintf("AddPortMapping %d 127.0.0.1 %d", port, portMapLifetime)
	want := []string{add, "GetExternalIPAddress   ", add, "GetExternalIPAddress   ", fmt.Sprintf("DeletePortMapping %d  ", port)}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("IGD calls %q, want %q", calls, want)
	}
	if gets != len(want)+1 { // one description fetch: the renewal reuses the service
		t.Fatalf("%d HTTP requests, want %d", gets, len(want)+1)
	}
}

// TestDirectPortMapUPnPPermanentOnly: an IGD that grants only permanent
// leases (725) maps nothing, and nothing asks it for one
// (spec/PortMap.tla NoPermanent, mutant accept-permanent).
func TestDirectPortMapUPnPPermanentOnly(t *testing.T) {
	g := serveIGD(t, true, "")
	ep := upnpEndpoint(t, g)
	defer ep.Close() //nolint:errcheck
	if a, ok := ep.mapped(); ok {
		t.Fatalf("permanent-only IGD mapped %v", a)
	}
	calls, _ := g.record()
	for _, c := range calls {
		if strings.HasPrefix(c, "AddPortMapping") && strings.HasSuffix(c, " 0") {
			t.Fatalf("asked for a permanent mapping: %q", calls)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("IGD calls %q, want the one leased ask", calls)
	}
}

// TestDirectPortMapUPnPNoExternalAddress: an IGD that maps but reports no
// external address (miniupnpd 2.3.9 on a private WAN under
// ext_allow_private_ipv4 answers "") maps nothing, the error says so, and
// its mapping is deleted, not left behind.
func TestDirectPortMapUPnPNoExternalAddress(t *testing.T) {
	g := serveIGD(t, false, "")
	g.ext = ""
	ep := upnpEndpoint(t, g)
	defer ep.Close() //nolint:errcheck
	port := ep.pc.LocalAddr().(*net.UDPAddr).Port
	_, _, err := ep.askUPnP(netip.MustParseAddr("127.0.0.1"), upnpCtl{}, portMapLifetime)
	if err == nil || !strings.Contains(err.Error(), "no external address") {
		t.Fatalf("askUPnP error %v, want one naming no external address", err)
	}
	calls, _ := g.record()
	want := []string{fmt.Sprintf("AddPortMapping %d 127.0.0.1 %d", port, portMapLifetime), "GetExternalIPAddress   ", fmt.Sprintf("DeletePortMapping %d  ", port)}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("IGD calls %q, want %q", calls, want)
	}
}

// TestDirectPortMapUPnPOtherHost: an SSDP answer whose description is on
// another host than the gateway's address is not fetched.
func TestDirectPortMapUPnPOtherHost(t *testing.T) {
	g := serveIGD(t, false, "")
	g.location = strings.Replace(g.srv.URL, "127.0.0.1", "localhost", 1) + "/rootDesc.xml"
	other := serveIGD(t, false, g.location)
	ep := upnpEndpoint(t, other)
	defer ep.Close() //nolint:errcheck
	if a, ok := ep.mapped(); ok {
		t.Fatalf("mapped %v through a description off the gateway", a)
	}
	if _, n := g.record(); n != 0 {
		t.Fatalf("%d HTTP requests to a host the gateway is not", n)
	}
}

func TestXMLText(t *testing.T) {
	for _, c := range []struct{ s, name, want string }{
		{"<a><NewExternalIPAddress> 1.2.3.4 </NewExternalIPAddress></a>", "NewExternalIPAddress", "1.2.3.4"},
		{"<m:controlURL>/c?x=1&amp;y=2</m:controlURL>", "controlURL", "/c?x=1&y=2"},
		{"</errorCode><XerrorCode>1</XerrorCode><errorCode>725</errorCode>", "errorCode", "725"},
		{"<serviceType>", "controlURL", ""},
	} {
		if got := xmlText(c.s, c.name); got != c.want {
			t.Errorf("xmlText(%q, %q) = %q, want %q", c.s, c.name, got, c.want)
		}
	}
}

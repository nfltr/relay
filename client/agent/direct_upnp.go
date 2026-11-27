// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// UPnP-IGD port mapping of the direct socket's UDP port, asked when the
// gateway maps with neither PCP nor NAT-PMP (nfltr
// docs/decisions/hardnat-2026-11-25.md; spec/PortMap.tla Mapped,
// NotMapped): SSDP M-SEARCH for an InternetGatewayDevice, its
// description's WANIPConnection or WANPPPConnection control URL,
// AddPortMapping with a lease, GetExternalIPAddress. Every URL must be on
// the gateway's own address (a LAN answer naming another host is
// ignored), and only a leased mapping is taken: an IGD that grants only
// permanent ones (error 725) gets none (spec/PortMap.tla NoPermanent).
// The XML is matched for the few elements read, never evaluated.

import (
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

const (
	// upnpBound bounds SSDP discovery and each HTTP request to the IGD.
	upnpBound = time.Second
	ssdpPort  = 1900
	upnpDesc  = "nfltr"
	upnpMax   = 64 << 10 // the most read of a description or an answer
	protoUPnP = "upnp"
)

// ssdpGroup is SSDP's multicast address. Only a test package's init
// clears it: no test sends a multicast M-SEARCH to the machine's LAN.
var ssdpGroup = netip.MustParseAddrPort("239.255.255.250:1900")

// upnpCtl is an IGD's port mapping service: its control URL (on the
// gateway's address) and service type, and this machine's LAN address
// toward the gateway (the mapping's internal client).
type upnpCtl struct {
	url  string
	st   string
	self netip.Addr
}

// askUPnP maps this endpoint's UDP port at gw for life seconds through
// ctl (the zero one: discovered first): the mapped address and the
// service used.
func (e *DirectEndpoint) askUPnP(gw netip.Addr, ctl upnpCtl, life uint32) (netip.AddrPort, upnpCtl, error) {
	ua, ok := e.pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, ctl, net.UnknownNetworkError("udp")
	}
	if ctl.url == "" {
		var err error
		if ctl, err = e.discoverIGD(gw); err != nil {
			return netip.AddrPort{}, ctl, err
		}
	}
	port := ua.Port
	_, err := ctl.soap("AddPortMapping", fmt.Sprintf("<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort>"+
		"<NewProtocol>UDP</NewProtocol><NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient>"+
		"<NewEnabled>1</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration>",
		port, port, ctl.self, upnpDesc, life))
	if err != nil {
		return netip.AddrPort{}, ctl, err
	}
	b, err := ctl.soap("GetExternalIPAddress", "")
	var ext netip.AddrPort
	if ip := xmlText(b, "NewExternalIPAddress"); err == nil && ip == "" {
		// IGDv2 2.3.13: "" when the gateway has no usable external address
		// (miniupnpd on a private WAN): the mapping is of no use
		err = errors.New("upnp: the gateway reports no external address")
	} else if err == nil {
		ext, err = e.candidate(ip + ":" + strconv.Itoa(port))
	}
	if err != nil {
		ctl.unmapUPnP(port)
		return netip.AddrPort{}, ctl, err
	}
	return ext, ctl, nil
}

// unmapUPnP deletes the mapping of port (best effort, bounded).
func (ctl upnpCtl) unmapUPnP(port int) {
	_, _ = ctl.soap("DeletePortMapping", fmt.Sprintf("<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>UDP</NewProtocol>", port))
}

// discoverIGD finds gw's InternetGatewayDevice: an M-SEARCH to gw's SSDP
// port (and the SSDP group), the first answer from gw whose description
// has a WAN connection service. errNoAnswer: no answer from gw within
// upnpBound.
func (e *DirectEndpoint) discoverIGD(gw netip.Addr) (upnpCtl, error) {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return upnpCtl{}, err
	}
	defer c.Close() //nolint:errcheck
	port := e.ssdp
	if port == 0 {
		port = ssdpPort
	}
	self, err := localAddrToward(netip.AddrPortFrom(gw, uint16(port))) // #nosec G115 -- a UDP port
	if err != nil {
		return upnpCtl{}, err
	}
	msg := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"MAN: \"ssdp:discover\"\r\nMX: 1\r\n\r\n")
	if _, err := c.WriteToUDPAddrPort(msg, netip.AddrPortFrom(gw, uint16(port))); err != nil { // #nosec G115 -- a UDP port
		return upnpCtl{}, err
	}
	if e.ssdp == 0 && ssdpGroup.IsValid() {
		_, _ = c.WriteToUDPAddrPort(msg, ssdpGroup) // some IGDs answer only the group
	}
	end := time.Now().Add(upnpBound)
	if err := c.SetReadDeadline(end); err != nil {
		return upnpCtl{}, err
	}
	b := make([]byte, 2048)
	var errs []error
	for {
		n, from, err := c.ReadFromUDPAddrPort(b)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if len(errs) > 0 {
				return upnpCtl{}, errors.Join(errs...)
			}
			return upnpCtl{}, fmt.Errorf("upnp: %w", errNoAnswer)
		}
		if err != nil {
			return upnpCtl{}, err
		}
		if from.Addr().Unmap() != gw {
			continue
		}
		ctl, err := igdService(gw, ssdpLocation(string(b[:n])), end)
		if err == nil {
			ctl.self = self
			return ctl, nil
		}
		errs = append(errs, err)
	}
}

// localAddrToward is this machine's address on the route to at (no
// packet sent).
func localAddrToward(at netip.AddrPort) (netip.Addr, error) {
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(at))
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close() //nolint:errcheck
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

// ssdpLocation is an SSDP answer's LOCATION header.
func ssdpLocation(answer string) string {
	for line := range strings.SplitSeq(answer, "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "location") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// igdService reads the description at loc (on gw) for its first
// WANIPConnection or WANPPPConnection service.
func igdService(gw netip.Addr, loc string, end time.Time) (upnpCtl, error) {
	u, err := onGateway(gw, nil, loc)
	if err != nil {
		return upnpCtl{}, err
	}
	resp, err := upnpClient(time.Until(end)).Get(u.String())
	if err != nil {
		return upnpCtl{}, fmt.Errorf("upnp: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	b, err := io.ReadAll(io.LimitReader(resp.Body, upnpMax))
	if err != nil || resp.StatusCode != http.StatusOK {
		return upnpCtl{}, fmt.Errorf("upnp: description %s: HTTP %d %v", u, resp.StatusCode, err)
	}
	for _, svc := range strings.Split(string(b), "<service>")[1:] {
		svc, _, _ = strings.Cut(svc, "</service>")
		st := xmlText(svc, "serviceType")
		if !strings.Contains(st, ":WANIPConnection:") && !strings.Contains(st, ":WANPPPConnection:") {
			continue
		}
		cu, err := onGateway(gw, u, xmlText(svc, "controlURL"))
		if err != nil {
			return upnpCtl{}, err
		}
		return upnpCtl{url: cu.String(), st: st}, nil
	}
	return upnpCtl{}, fmt.Errorf("upnp: %s has no WAN connection service", u)
}

// onGateway parses ref (relative to base, if any): an http URL on gw.
func onGateway(gw netip.Addr, base *url.URL, ref string) (*url.URL, error) {
	u, err := url.Parse(ref)
	if err == nil && base != nil {
		u = base.ResolveReference(u)
	}
	if err != nil || u.Scheme != "http" || u.Hostname() != gw.String() {
		return nil, fmt.Errorf("upnp: %q is not an http URL on the gateway %s", ref, gw)
	}
	return u, nil
}

// soap calls action on ctl's service with args (XML elements): the
// answer's body. An error answer (HTTP 500) names its UPnP errorCode.
func (ctl upnpCtl) soap(action, args string) (string, error) {
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + ctl.st + `">` +
		args + `</u:` + action + `></s:Body></s:Envelope>`
	req, err := http.NewRequest(http.MethodPost, ctl.url, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+ctl.st+"#"+action+`"`)
	resp, err := upnpClient(upnpBound).Do(req)
	if err != nil {
		return "", fmt.Errorf("upnp %s: %w", action, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	b, err := io.ReadAll(io.LimitReader(resp.Body, upnpMax))
	if err != nil {
		return "", fmt.Errorf("upnp %s: %w", action, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upnp %s: HTTP %d, error %s %s", action, resp.StatusCode, xmlText(string(b), "errorCode"), xmlText(string(b), "errorDescription"))
	}
	return string(b), nil
}

// upnpClient is an HTTP client for the LAN's IGD: no proxy, no redirect,
// bounded by d.
func upnpClient(d time.Duration) *http.Client {
	return &http.Client{
		Timeout:       d,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// xmlText is the text of s's first <name> element (a namespace prefix
// allowed), &amp; unescaped; "" when absent.
func xmlText(s, name string) string {
	for i := 0; ; {
		k := strings.Index(s[i:], name+">")
		if k < 0 {
			return ""
		}
		k += i
		i = k + len(name) + 1
		open := strings.LastIndexByte(s[:k], '<')
		if open < 0 {
			continue
		}
		// "" or "prefix:" opens the element; "/..." closes one, anything else is another name
		if tag := s[open+1 : k]; tag != "" && (!strings.HasSuffix(tag, ":") || strings.ContainsAny(tag, " /<>")) {
			continue
		}
		v, _, ok := strings.Cut(s[i:], "<")
		if !ok {
			return ""
		}
		return strings.TrimSpace(strings.ReplaceAll(v, "&amp;", "&"))
	}
}

// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
)

// Peer-reflexive candidates (nfltr docs/decisions/nat-symmetric-lan-2026-11-16.md,
// spec/DirectPunch.tla; ICE, RFC 8445 sections 7.2.5.3.1 and 7.3.1.3). The
// agent's probes carry a tag only the two ends of the control exchange
// can make; a client that hears one from an address it does not dial
// dials that address too. An agent behind an endpoint-dependent NAT
// probes from a fresh mapping toward the client, which its offer could
// not name and only the client's answer there passes.

// directProbeLabel is the probe tag's exporter of the control session's
// TLS. Not a binding of who answers (the certificate check and the path
// tokens are): it keeps an off-path sender from aiming the client's QUIC
// Initials at a third party.
const directProbeLabel = "EXPORTER-nfltr-direct-probe"

// probeLen is a probe's size: a zero byte, which a QUIC endpoint takes
// for no QUIC packet (quic-go hands it to ReadNonQUICPacket or drops
// it), then the tag.
const probeLen = 17

// probeTag is the exchange's probe tag: an exporter of the control
// session's TLS (c's, when it is a TLS connection).
func probeTag(c any) []byte {
	s, ok := c.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		return nil
	}
	cs := s.ConnectionState()
	tag, err := cs.ExportKeyingMaterial(directProbeLabel, nil, probeLen-1)
	if err != nil {
		return nil
	}
	return tag
}

// probe sends one probe from the endpoint to each candidate: tagged, or
// the zero byte alone without a tag.
func (e *DirectEndpoint) probe(cands []netip.AddrPort, tag []byte) error {
	if len(cands) > quiclink.MaxCandidates {
		return fmt.Errorf("direct path: probe: %d candidates (at most %d)", len(cands), quiclink.MaxCandidates)
	}
	b := append([]byte{0}, tag...)
	var errs []error
	for _, a := range cands {
		if _, err := e.tr.WriteTo(b, net.UDPAddrFromAddrPort(a)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// probeWaiters routes the endpoint's tagged probes to the punch whose
// exchange made the tag; one reader per endpoint, from its first listen
// until the socket closes.
type probeWaiters struct {
	once sync.Once
	mu   sync.Mutex
	by   map[string]chan netip.AddrPort
}

// listen registers tag: the sources of probes carrying it arrive on the
// channel (at most quiclink.MaxCandidates queued, the rest dropped) until
// stop.
func (e *DirectEndpoint) listen(tag []byte) (<-chan netip.AddrPort, func()) {
	w := &e.probes
	w.once.Do(func() { go e.readProbes() })
	ch := make(chan netip.AddrPort, quiclink.MaxCandidates)
	k := string(tag)
	w.mu.Lock()
	if w.by == nil {
		w.by = map[string]chan netip.AddrPort{}
	}
	w.by[k] = ch
	w.mu.Unlock()
	return ch, func() {
		w.mu.Lock()
		delete(w.by, k)
		w.mu.Unlock()
	}
}

func (e *DirectEndpoint) readProbes() {
	b := make([]byte, 64)
	for {
		n, from, err := e.tr.ReadNonQUICPacket(context.Background(), b)
		if err != nil {
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if n != probeLen || b[0] != 0 || !ok {
			continue
		}
		e.probes.mu.Lock()
		ch := e.probes.by[string(b[1:n])]
		e.probes.mu.Unlock()
		if ch == nil {
			continue
		}
		select {
		case ch <- ua.AddrPort():
		default:
		}
	}
}

// lanGrace is how long the LAN dials outlive a non-LAN win: a LAN
// handshake (and the agent's first probe from a LAN address) ends well
// within it (DirectPunch.tla Settle, its Reach assumption).
// ponytail: fixed; measure per-pair LAN RTT if 100 ms ever cuts a slow
// LAN (Wi-Fi under load) or shows in the time to direct.
const lanGrace = 100 * time.Millisecond

func (e *DirectEndpoint) lanGrace() time.Duration {
	if e.grace > 0 {
		return e.grace
	}
	return lanGrace
}

// isLAN: a private or link-local address, a path that stays on the LAN.
func (e *DirectEndpoint) isLAN(a netip.AddrPort) bool {
	if e.lan != nil {
		return e.lan(a)
	}
	return a.Addr().IsPrivate() || a.Addr().IsLinkLocalUnicast()
}

// punch dials cands at once (quiclink.Punch) and every address a probe
// on learned names that it does not dial yet, at most
// quiclink.MaxCandidates dials in all and none once one won. It keeps the
// first connection whose handshake passes tc's check, unless a LAN one
// passes later: a LAN path replaces a non-LAN winner, the LAN dials
// outlive a non-LAN win by lanGrace and a LAN probe is still dialled in
// it (owner 2026-11-16: a LAN path first, then the lowest handshake RTT;
// DirectPunch.tla PreferLan). It closes every other connection and
// returns once no dial of it is left (OneConnection). ctx bounds it.
func (e *DirectEndpoint) punch(ctx context.Context, cands []netip.AddrPort, learned <-chan netip.AddrPort, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
	pubCtx, cancelPub := context.WithCancel(ctx)
	defer cancelPub()
	lanCtx, cancelLAN := context.WithCancel(ctx)
	defer cancelLAN()
	type result struct {
		a   netip.AddrPort
		q   *quic.Conn
		err error
	}
	ch := make(chan result, quiclink.MaxCandidates)
	var dialled []netip.AddrPort
	running := 0
	start := func(a netip.AddrPort) {
		dialled = append(dialled, a)
		running++
		c := pubCtx
		if e.isLAN(a) {
			c = lanCtx
		}
		go func() {
			q, err := quiclink.Punch(c, e.tr, []netip.AddrPort{a}, tc, qc)
			ch <- result{a, q, err}
		}()
	}
	var lan []string
	for _, a := range cands {
		if e.isLAN(a) {
			lan = append(lan, a.String())
		}
	}
	tr := tracePunch(addrStrings(cands), lan)
	for _, a := range cands {
		start(a)
	}
	var won *quic.Conn
	var wonAt netip.AddrPort
	var grace <-chan time.Time // the LAN grace after a non-LAN win
	var errs []error
	done := ctx.Done()
	// Until no dial runs, and then until one won or the bound, and through
	// the grace: a probe may still name the address that answers after
	// every offered one failed, or a LAN one.
	for running > 0 || won == nil && done != nil || grace != nil {
		select {
		case <-done:
			done, grace = nil, nil
		case <-grace:
			grace = nil
			tr.settle()
			cancelLAN()
		case a := <-learned:
			a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
			_, bad := e.candidate(a.String())
			isLAN := e.isLAN(a)
			dial := (won == nil || grace != nil && isLAN) && ctx.Err() == nil && len(dialled) < quiclink.MaxCandidates && !slices.Contains(dialled, a) && bad == nil
			tr.learn(a.String(), isLAN, dial)
			if dial {
				start(a)
			}
		case r := <-ch:
			running--
			switch {
			case r.err != nil:
				tr.fail(r.a.String())
				errs = append(errs, r.err)
			case won == nil || e.isLAN(r.a) && !e.isLAN(wonAt):
				tr.up(r.a.String(), true)
				if won != nil {
					tr.closeLoser(wonAt.String())
					_ = won.CloseWithError(quiclink.CodeDone, "a LAN candidate won")
				}
				won, wonAt = r.q, r.a
				cancelPub() // the dials still running give up: the non-LAN ones now,
				if e.isLAN(r.a) {
					cancelLAN() // the LAN ones too once a LAN one won
					grace = nil
				} else if done != nil {
					grace = time.After(e.lanGrace()) // else after the grace
				}
			default:
				tr.up(r.a.String(), false)
				_ = r.q.CloseWithError(quiclink.CodeDone, "another candidate won")
			}
		}
	}
	wonStr := ""
	if won != nil {
		wonStr = wonAt.String()
	}
	tr.end(wonStr)
	if won == nil {
		return nil, fmt.Errorf("direct path: punch: no candidate answered: %w", errors.Join(errs...))
	}
	return won, nil
}

func addrStrings(as []netip.AddrPort) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

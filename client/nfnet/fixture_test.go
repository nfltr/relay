// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/client/relaytrust"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// serverTLS is the agent's TLS of organisation mode for m: allow group
// db, negotiating protos.
func serverTLS(m *orgid.Identity, protos ...string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true, NextProtos: protos,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return m.Certificate() },
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := m.CheckClient(cs.PeerCertificates, []string{"db"}, time.Now())
			return err
		}}
}

// relayOrg is the stand-in's organisation: the agent's machines web and
// eve, and the clients cli (group db) and ops (group ci).
type relayOrg struct {
	o                  *testOrg
	web, eve, cli, ops *orgid.Identity
}

func newRelayOrg(t *testing.T) relayOrg {
	o := newTestOrg(t)
	return relayOrg{o: o, web: o.machine(t, "web", "web"), eve: o.machine(t, "eve", "web"), cli: o.machine(t, "cli", "db"), ops: o.machine(t, "ops", "ci")}
}

// dataRelay is a relay stand-in for data connections that plays the agent
// too: each session's open is answered link's own way, then served by its
// service:
//
//	"echo"     echo, passing the client's half close on
//	"speak"    write "hello", half-close, report what arrives after on late
//	"cut"      accept, write "hello", reset the session
//	"refused"  refuse TARGET_REFUSED from the agent (one hop beyond)
//	"offline"  refuse AGENT_OFFLINE until online is set, then echo
//	"draining" refuse with link's draining code
//	"strip"    accept and echo plain bytes even to an E2EE open (a relay
//	           that drops the encryption)
//	"peek"     read the client's first bytes before the answer, then
//	           accept and echo them and the rest
//	"peekref"  read the client's first bytes, then refuse TARGET_REFUSED
//	"plainsvc" refuse an E2EE open E2EE_UNAVAILABLE, echo a plain one
//
// A group open that excludes an instance is refused AGENT_OFFLINE: web is
// the only one.
// An E2EE open is the organisation's TLS of machine web (allow group db),
// then the echo; "eve" is the same served by machine eve.
type dataRelay struct {
	srv    *httptest.Server
	conns  atomic.Int64
	muxes  chan *dataplane.Mux // every data connection, in order
	late   chan int64
	opens  chan *pb.TCPData // every open, in order
	online atomic.Bool
	org    relayOrg
	mu     sync.Mutex // guards closed and wg's Go against its Wait
	closed bool
	wg     sync.WaitGroup
}

func newDataRelay(t *testing.T, useTLS bool) *dataRelay {
	t.Helper()
	r := &dataRelay{late: make(chan int64, 8), muxes: make(chan *dataplane.Mux, 8), opens: make(chan *pb.TCPData, 64), org: newRelayOrg(t)}
	r.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("X-API-Key") != "key" && (req.TLS == nil || len(req.TLS.PeerCertificates) == 0) {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if !dataplane.IsUpgrade(req) {
			http.Error(w, "usage", http.StatusBadRequest)
			return
		}
		nc, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer nc.Close() //nolint:errcheck
		m, err := dataplane.Accept(req.Context(), nc, 4<<20, "allow")
		if err != nil {
			return
		}
		select {
		case r.muxes <- m:
		default:
		}
		_ = m.Serve(func(open *pb.TCPData, s *dataplane.Session) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.closed {
				_ = s.Reset()
				return
			}
			r.wg.Go(func() { r.serveSession(open, s) })
		})
	}))
	r.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			r.conns.Add(1)
		}
	}
	if useTLS {
		r.srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
		r.srv.StartTLS()
	} else {
		r.srv.Start()
	}
	t.Cleanup(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		r.srv.CloseClientConnections()
		r.srv.Close()
		r.wg.Wait()
	})
	return r
}

func (r *dataRelay) addr() string { return r.srv.Listener.Addr().String() }

// config is a Config for the stand-in: key "key", the relay pinned.
func (r *dataRelay) config(useTLS bool) Config {
	cfg := Config{Relay: r.addr(), APIKey: "key", Plaintext: !useTLS}
	if useTLS {
		cfg.RelayTLS = relaytrust.WithPin(&tls.Config{ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}, relaytrust.Fingerprint(r.srv.Certificate().Raw))
	}
	return cfg
}

// dialer is a Dialer of cfg, closed at the test's end.
func dialer(t *testing.T, cfg Config) *Dialer {
	t.Helper()
	d, err := NewDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func (r *dataRelay) serveSession(open *pb.TCPData, s *dataplane.Session) {
	defer s.Close() //nolint:errcheck
	select {
	case r.opens <- open:
	default:
	}
	refuse := func(a *link.Abort) { _ = s.AbortWith(a) }
	var c net.Conn = s
	srv := r.org.web
	if len(open.GetExclude()) > 0 { // the only instance, web, excluded
		refuse(dataplane.Refusal(relayv1.ErrorReason_ERROR_REASON_AGENT_OFFLINE, "no instance left"))
		return
	}
	switch open.GetTargetAddr() {
	case "plainsvc":
		if open.GetE2Ee() {
			refuse(dataplane.Refusal(relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE, "the service is not end-to-end encrypted"))
			return
		}
	case "eve":
		srv = r.org.eve
	case "offline":
		if !r.online.Load() {
			refuse(dataplane.Refusal(relayv1.ErrorReason_ERROR_REASON_AGENT_OFFLINE, "agent offline"))
			return
		}
	case "refused":
		a := dataplane.Refusal(relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED, "dial tcp 127.0.0.1:9: connection refused")
		a.Hops = 1
		refuse(a)
		return
	case "draining":
		refuse(&link.Abort{Refused: true, Code: link.CodeDraining, Msg: "draining"})
		return
	case "strip":
		if s.Accept() == nil {
			_, _ = io.Copy(s, s)
		}
		return
	case "peek", "peekref":
		first := make([]byte, 1)
		if _, err := io.ReadFull(s, first); err != nil {
			return
		}
		if open.GetTargetAddr() == "peekref" {
			refuse(dataplane.Refusal(relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED, "refused after the first byte"))
			return
		}
		if s.Accept() != nil {
			return
		}
		if _, err := s.Write(first); err != nil {
			return
		}
		_, _ = io.Copy(s, s)
		_ = s.CloseWrite()
		return
	case "cut": // accepted, a first reply, then reset mid-stream
		if s.Accept() == nil {
			_, _ = s.Write([]byte("hello"))
			_ = s.Reset()
		}
		return
	case "speak":
		if s.Accept() != nil {
			return
		}
		_, _ = s.Write([]byte("hello"))
		_ = s.CloseWrite()
		n, _ := io.Copy(io.Discard, s)
		r.late <- n
		return
	}
	if s.Accept() != nil {
		return
	}
	if open.GetE2Ee() {
		proto := agent.MachineALPN(open.GetAgentId(), open.GetTargetAddr())
		if svc, group, ok := strings.Cut(open.GetAgentId(), "@"); ok { // a group dial
			proto = agent.GroupALPN(svc, group)
		}
		tc := tls.Server(s, serverTLS(srv, proto))
		if tc.Handshake() != nil {
			return
		}
		c = tc
	}
	_, _ = io.Copy(c, c)
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, c)
}

// web is machine web's service svc.
func web(svc string) Target { return Target{Kind: AgentTarget, Agent: "web", Service: svc} }

// dial opens t within 5 s.
func dial(t *testing.T, d *Dialer, target Target, o DialOptions) (*Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.DialTarget(ctx, target, o)
}

// echoAndHalfClose writes msg, half-closes and wants msg back then EOF.
func echoAndHalfClose(t *testing.T, c *Conn, msg string) {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(c); string(got) != msg || err != nil {
		t.Fatalf("after our half close read %q (%v), want %q", got, err, msg)
	}
}

// codeOf wants err an *Error of code (and reason, when not "").
func wantCode(t *testing.T, what string, err error, code Code, reason string) *Error {
	t.Helper()
	e, ok := errors.AsType[*Error](err)
	if !ok || e.Code != code || (reason != "" && e.Reason != reason) {
		t.Fatalf("%s: %v (%#v), want %s %s", what, err, err, code, reason)
	}
	return e
}

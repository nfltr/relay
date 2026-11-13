// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// chanStream is a tcpStream fed by the test: frames from the relay on in,
// frames the agent sends on out.
type chanStream struct {
	in   chan *pb.TCPData
	out  chan *pb.TCPData
	once sync.Once
}

func (s *chanStream) Send(f *pb.TCPData) error { s.out <- f; return nil }
func (s *chanStream) Recv() (*pb.TCPData, error) {
	f, ok := <-s.in
	if !ok {
		return nil, io.EOF
	}
	return f, nil
}

func TestNewServiceTableValidates(t *testing.T) {
	for name, svcs := range map[string][]Service{
		"none":           nil,
		"bad name":       {{Name: "5432", Kind: agentservices.TCP, Target: "localhost:5432"}},
		"duplicate":      {{Name: "db", Kind: agentservices.TCP, Target: "a:1"}, {Name: "db", Kind: agentservices.TCP, Target: "a:2"}},
		"tcp no port":    {{Name: "db", Kind: agentservices.TCP, Target: "localhost"}},
		"http not a URL": {{Name: "web", Kind: agentservices.HTTP, Target: "localhost:3000"}},
		"http ftp":       {{Name: "web", Kind: agentservices.HTTP, Target: "ftp://x/"}},
		"unknown kind":   {{Name: "x", Kind: "udp", Target: "a:1"}},
		"unix relative":  {{Name: "db", Kind: agentservices.TCP, Target: "unix:db.sock"}},
		"public default": {{Name: "mc", Kind: agentservices.TCP, Target: "a:1", Public: true}},
		"public e2ee":    {{Name: "mc", Kind: agentservices.TCP, E2EE: agentservices.E2EEOn, Target: "a:1", Public: true}},
		"public http":    {{Name: "mc", Kind: agentservices.HTTP, E2EE: agentservices.E2EEOff, Target: "http://a:1", Public: true}},
	} {
		if _, err := NewServiceTable(svcs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tab, err := NewServiceTable([]Service{{Name: "web", Kind: agentservices.HTTP, Target: "http://127.0.0.1:3000"}, {Name: "db", Kind: agentservices.TCP, Target: "127.0.0.1:5432"}})
	if err != nil || agentservices.Format(tab.decls) != "web=http,db=tcp" {
		t.Fatalf("%v %v", err, tab.decls)
	}
	pub, err := NewServiceTable([]Service{{Name: "mc", Kind: agentservices.TCP, E2EE: agentservices.E2EEOff, Target: "127.0.0.1:25565", Public: true}})
	if err != nil || agentservices.Format(pub.decls) != "mc=tcp+plain;public" {
		t.Fatalf("public: %v %v", err, pub.decls)
	}
	if err := tab.RequireSharePolicy("db", "swift-bay", SharePolicy{BasicAuth: "a:b"}); err == nil {
		t.Error("share policy on a tcp service accepted")
	}
	if err := tab.RequireSharePolicy("nope", "swift-bay", SharePolicy{BasicAuth: "a:b"}); err == nil {
		t.Error("share policy on an unknown service accepted")
	}
	if err := tab.RequireSharePolicy("web", "swift-bay", SharePolicy{}); err == nil || len(tab.shareCodes()) != 0 {
		t.Error("an invalid policy was installed")
	}
}

// The service table is the agent's only set of targets: a session that
// names an unknown service, a raw host:port, a service of the wrong kind or
// the single-agent E2EE marker is closed and counted, and nothing is
// dialled; a declared tcp service reaches its own target only.
func TestServiceTableIsTheOnlyTargets(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close() //nolint:errcheck
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	tab, err := NewServiceTable([]Service{
		{Name: "db", Kind: agentservices.TCP, Target: target.Addr().String()},
		{Name: "web", Kind: agentservices.HTTP, Target: "http://" + target.Addr().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := newChanStream(t, 8, 8)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveTCPStream(ctx, st, sessionTargets{services: tab}, nil, nil, slog.New(slog.DiscardHandler), nil, nil)
	}()

	refused := []*pb.TCPData{
		{SessionId: "s1", Open: true, TargetAddr: "nope"},                     // unknown service
		{SessionId: "s2", Open: true, TargetAddr: target.Addr().String()},     // raw host:port injection
		{SessionId: "s3", Open: true, TargetAddr: "localhost:5432"},           // today's port target
		{SessionId: "s4", Open: true, TargetAddr: "web"},                      // http service as raw TCP
		{SessionId: "s5", Open: true, TargetAddr: "db", E2Ee: true},           // tcp service as E2EE
		{SessionId: "s6", Open: true, TargetAddr: "web", E2Ee: true},          // E2EE, agent terminates none
		{SessionId: "s7", Open: true, TargetAddr: "__e2ee__", E2Ee: true},     // single-agent E2EE marker
		{SessionId: "s8", Open: true, TargetAddr: "other-agent.db"},           // another agent's service
		{SessionId: "s9", Open: true, TargetAddr: ""},                         // nothing named
		{SessionId: "s10", Open: true, TargetAddr: "db\x00x"},                 // not a name
		{SessionId: "s11", Open: true, TargetAddr: "../db"},                   // not a name
		{SessionId: "s12", Open: true, TargetAddr: "DB"},                      // names are exact
		{SessionId: "s13", Open: true, TargetAddr: "db:5432"},                 // service plus port
		{SessionId: "s14", Open: true, TargetAddr: "[::1]:5432", E2Ee: false}, // IPv6 literal
	}
	for _, f := range refused {
		st.in <- f
		select {
		case got := <-st.out:
			if got.SessionId != f.SessionId || !got.Close {
				t.Fatalf("%q: agent sent %+v, want a close", f.TargetAddr, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%q: no close", f.TargetAddr)
		}
	}
	if n := tab.Refused(); n != uint64(len(refused)) {
		t.Fatalf("refused %d, want %d", n, len(refused))
	}
	select {
	case c := <-accepted:
		_ = c.Close()
		t.Fatal("a refused session dialled the target")
	case <-time.After(100 * time.Millisecond):
	}

	st.in <- &pb.TCPData{SessionId: "ok", Open: true, TargetAddr: "db"}
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the declared tcp service was not dialled")
	}
	st.closeIn()
	<-done
}

// A tcp service's target may be a unix socket: the session dials that
// path; a raw session that names a unix: address is still refused.
func TestServiceUnixSocketTarget(t *testing.T) {
	// A unix socket path is at most 104 bytes on macOS (108 on Linux): a
	// node's TMPDIR can be longer, /tmp is not.
	dir, err := os.MkdirTemp("/tmp", "us")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	target, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close() //nolint:errcheck
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := target.Accept(); err == nil {
			accepted <- c
		}
	}()
	tab, err := NewServiceTable([]Service{{Name: "db", Kind: agentservices.TCP, Target: "unix:" + sock}})
	if err != nil {
		t.Fatal(err)
	}
	st := newChanStream(t, 4, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveTCPStream(ctx, st, sessionTargets{services: tab}, nil, nil, slog.New(slog.DiscardHandler), nil, nil)
	}()
	st.in <- &pb.TCPData{SessionId: "raw", Open: true, TargetAddr: "unix:" + sock}
	if got := <-st.out; got.SessionId != "raw" || !got.Close {
		t.Fatalf("raw unix: address: agent sent %+v, want a close", got)
	}
	st.in <- &pb.TCPData{SessionId: "ok", Open: true, TargetAddr: "db"}
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the unix socket service was not dialled")
	}
	st.closeIn()
	<-done
}

// Each service's share policy guards that service's E2EE sessions only:
// web's credentials are required on web and never on api, and api's open
// service does not lend web's sessions a way around them. The agent names
// every protected service's share on its streams.
func TestServiceSharePolicyPerService(t *testing.T) {
	tab, err := NewServiceTable([]Service{
		{Name: "web", Kind: agentservices.HTTP, Target: "http://127.0.0.1:1"},
		{Name: "api", Kind: agentservices.HTTP, Target: "http://127.0.0.1:2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tab.RequireSharePolicy("web", "swift-bay", SharePolicy{BasicAuth: "bob:pw"}); err != nil {
		t.Fatal(err)
	}
	if got := tab.shareCodes(); !slices.Equal(got, []string{"swift-bay"}) {
		t.Fatalf("share codes %q", got)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	status := func(svc string, auth bool) int {
		e, err := tab.resolve(svc, true, true, false)
		if err != nil {
			t.Fatal(err)
		}
		var h http.Handler = ok
		if e.wrap != nil {
			h = e.wrap(ok)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if auth {
			r.SetBasicAuth("bob", "pw")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if s := status("web", false); s != 401 {
		t.Errorf("web without credentials: %d", s)
	}
	if s := status("web", true); s != 200 {
		t.Errorf("web with credentials: %d", s)
	}
	if s := status("api", false); s != 200 {
		t.Errorf("api (no policy): %d", s)
	}
}

// newChanStream is a chanStream whose input ends with the test, so the
// serveTCPStream goroutine reading it returns (the package's leak check).
func newChanStream(t *testing.T, in, out int) *chanStream {
	st := &chanStream{in: make(chan *pb.TCPData, in), out: make(chan *pb.TCPData, out)}
	t.Cleanup(st.closeIn)
	return st
}

func (s *chanStream) closeIn() { s.once.Do(func() { close(s.in) }) }

// An http service's own certificate (Service.Cert) ends its E2EE share
// sessions; a service without one takes the tunnel's, and with no tunnel
// certificate only a service with its own terminates E2EE: two shares,
// one with the tunnel's (ACME) certificate, under one identity.
func TestServiceOwnCertificate(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	tunnel, err := NewE2EESetup("home", "", "", logger)
	if err != nil {
		t.Fatal(err)
	}
	own, err := NewE2EESetup("home", "", "", logger)
	if err != nil {
		t.Fatal(err)
	}
	tab, err := NewServiceTable([]Service{
		{Name: "db", Kind: agentservices.HTTP, Target: "http://127.0.0.1:5432", Cert: own},
		{Name: "web", Kind: agentservices.HTTP, Target: "http://127.0.0.1:3000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets := sessionTargets{services: tab}
	db := &pb.TCPData{Open: true, TargetAddr: "db", E2Ee: true}
	web := &pb.TCPData{Open: true, TargetAddr: "web", E2Ee: true}
	for _, tc := range []struct {
		name   string
		open   *pb.TCPData
		tunnel *E2EESetup
		want   *E2EESetup // nil: refused
		kind   sessionKind
	}{
		{"own certificate", db, tunnel, own, sessionE2EE},
		{"http service, the tunnel's", web, tunnel, tunnel, sessionE2EE},
		{"own certificate, no tunnel's", db, nil, own, sessionE2EE},
		{"no certificate at all", web, nil, nil, 0},
	} {
		var cfg *e2eeTLSConfig
		if tc.tunnel != nil {
			cfg = tc.tunnel.cfg
		}
		p, err := planSession(tc.open, targets, cfg)
		switch {
		case tc.want == nil && err == nil:
			t.Errorf("%s: accepted", tc.name)
		case tc.want == nil:
		case err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case p.e2ee != tc.want.cfg || p.kind != tc.kind:
			t.Errorf("%s: certificate %s kind %d, want %s kind %d", tc.name, p.e2ee.Fingerprint(), p.kind, tc.want.Fingerprint(), tc.kind)
		}
	}
}

// The caller the relay names on an open reaches OnSession with the admitted
// session; an open without one (a share visitor's, an older relay's) has no
// caller, and a refused session is never reported.
func TestServiceSessionReportsCaller(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close() //nolint:errcheck
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	tab, err := NewServiceTable([]Service{{Name: "db", Kind: agentservices.TCP, Target: target.Addr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan Session, 4)
	tab.OnSession(func(s Session) { got <- s })
	st := newChanStream(t, 8, 8)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveTCPStream(ctx, st, sessionTargets{services: tab}, nil, nil, slog.New(slog.DiscardHandler), nil, nil)
	}()
	want := Caller{Machine: "m-aaaaaaaaaaaaaaaaaaaaaaaaaa", Group: "g1", Account: "acct", MachineName: "box"}
	st.in <- &pb.TCPData{SessionId: "refused", Open: true, TargetAddr: "nope"}
	st.in <- &pb.TCPData{SessionId: "a", Open: true, TargetAddr: "db", Caller: &pb.CallerIdentity{
		MachineId: want.Machine, GroupId: want.Group, Account: want.Account, MachineName: want.MachineName}}
	st.in <- &pb.TCPData{SessionId: "b", Open: true, TargetAddr: "db"}
	for _, wantOK := range []bool{true, false} {
		select {
		case s := <-got:
			c, ok := s.Caller()
			if s.Service != "db" || ok != wantOK || (ok && c != want) {
				t.Fatalf("session = %+v caller %+v %v, want db caller %+v %v", s, c, ok, want, wantOK)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no session reported")
		}
	}
	select {
	case s := <-got:
		t.Fatalf("extra session reported: %+v", s)
	default:
	}
	cancel()
	st.closeIn()
	<-done
}

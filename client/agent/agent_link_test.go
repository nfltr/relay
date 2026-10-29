// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/link/peerlink/peerlinktest"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc/metadata"
)

const testLinkToken = "tok-agent-link"

// fakeLinkRelay is the relay's side of the agent link as nfltr-relay
// runs it: a peerlink.Node taking TCP connections that start with the
// magic, and a quiclink.Node naming peers by their hello; both open
// sessions on the connections the agent dialled.
type fakeLinkRelay struct {
	tcp         *peerlink.Node
	quic        *quiclink.Node
	tcpAddr     string
	udpAddr     *net.UDPAddr
	clientTC    *tls.Config
	accepted    atomic.Int32 // agent-link connections taken, both transports
	refuse      atomic.Int32 // QUIC connections still to refuse, as another replica does
	slowRefusal atomic.Int64 // how long a refusal takes, as a loaded machine's does

	refuseTCP atomic.Bool // TCP connections are refused, as another replica does
	tcpMu     sync.Mutex
	tcpConns  []net.Conn // the TCP connections taken
}

// cutTCP closes every TCP agent-link connection the relay took, as a lost
// connection (the relay's replica leaving, the network) ends it.
func (r *fakeLinkRelay) cutTCP() {
	r.tcpMu.Lock()
	defer r.tcpMu.Unlock()
	for _, c := range r.tcpConns {
		_ = c.Close()
	}
	r.tcpConns = nil
}

// chanListener hands route's connections to the TCP Node.
type chanListener struct {
	conns chan net.Conn
	addr  net.Addr
	done  chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { close(l.done); return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

type tokenVerifier struct{}

func (tokenVerifier) Hello(context.Context, tls.ConnectionState) (byte, []byte, error) {
	return 0, nil, errors.New("not dialled")
}
func (tokenVerifier) Verify(_ context.Context, _ tls.ConnectionState, m byte, p []byte) (link.Identity, error) {
	if m != link.MethodToken || string(p) != testLinkToken {
		return link.Identity{}, errors.New("unknown token")
	}
	return link.Identity{Subject: "agent"}, nil
}

func newFakeLinkRelay(t *testing.T) *fakeLinkRelay {
	t.Helper()
	cert, _, err := generateSelfSignedCert("relay.test")
	if err != nil {
		t.Fatal(err)
	}
	stc := &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	r := &fakeLinkRelay{clientTC: &tls.Config{RootCAs: pool, ServerName: leaf.DNSNames[0], MinVersion: tls.VersionTLS13}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", stc)
	if err != nil {
		t.Fatal(err)
	}
	r.tcpAddr = ln.Addr().String()
	cl := &chanListener{conns: make(chan net.Conn), addr: ln.Addr(), done: make(chan struct{})}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				magic := make([]byte, len(dataplane.AgentLinkMagic))
				if _, err := io.ReadFull(c, magic); err != nil || string(magic) != dataplane.AgentLinkMagic {
					_ = c.Close()
					return
				}
				if r.refuseTCP.Load() {
					_ = c.Close()
					return
				}
				r.accepted.Add(1)
				r.tcpMu.Lock()
				r.tcpConns = append(r.tcpConns, c)
				r.tcpMu.Unlock()
				select {
				case cl.conns <- c:
				case <-cl.done:
					_ = c.Close()
				}
			}()
		}
	}()
	r.tcp = mustNode(peerlink.New(peerlink.Config{Listener: cl, Link: link.Config{Auth: tokenVerifier{}}}))

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r.udpAddr = pc.LocalAddr().(*net.UDPAddr)
	qtc := stc.Clone()
	qtc.NextProtos = dataplane.AgentLinkALPNs()
	r.quic = mustNode(quiclink.New(quiclink.Config{PacketConn: pc, TLS: qtc, ServedPeer: func(q *quic.Conn) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		st, err := q.AcceptStream(ctx)
		if err != nil {
			return "", err
		}
		defer st.Close() //nolint:errcheck
		tok, err := dataplane.ReadLinkHello(st)
		if err == nil && r.refuse.Add(-1) >= 0 {
			time.Sleep(time.Duration(r.slowRefusal.Load()))
			_ = q.CloseWithError(0x2, "no tcp stream of this agent to bind to")
			return "", errors.New("refused")
		}
		ok := err == nil && tok == testLinkToken
		_ = dataplane.AnswerLinkHello(st, ok)
		if !ok {
			return "", errors.New("unknown token")
		}
		r.accepted.Add(1)
		return "agent", nil
	}}))
	go func() { _ = r.tcp.Serve(func(_ string, _ []byte, s peerlink.Session) { _ = s.Close() }) }()
	go func() { _ = r.quic.Serve(func(_ string, _ []byte, s peerlink.Session) { _ = s.Close() }) }()
	t.Cleanup(func() {
		done, cancel := context.WithCancel(context.Background())
		cancel()
		_ = r.tcp.Drain(done)
		_ = r.quic.Drain(done)
		_ = ln.Close()
	})
	return r
}

// dialer is the agent's RelayDialer toward r, QUIC at quicPort.
func (r *fakeLinkRelay) dialer(transport string) RelayDialer {
	return RelayDialer{
		Data: func(ctx context.Context) (net.Conn, error) {
			return (&tls.Dialer{Config: r.clientTC}).DialContext(ctx, "tcp", r.tcpAddr)
		},
		QUIC:      &QUICDialer{Host: "127.0.0.1", TLS: r.clientTC},
		Transport: transport,
		Liveness:  link.LivenessFast,
	}
}

// won returns the Link the agent's link is up on, waiting for it: a
// TransportAuto agent races QUIC and TCP, and either wins under load. TCP
// is asked first: only a winning TCP connection says its hello, while a
// losing QUIC one is accepted until the agent closes it.
func (r *fakeLinkRelay) won(t *testing.T) peerlink.Link {
	t.Helper()
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "x:1"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, node := range []peerlink.Link{r.tcp, r.quic} {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			s, err := node.Open(ctx, "agent", h)
			cancel()
			if err == nil {
				_ = s.Close()
				return node
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent's link is up on neither transport")
		}
	}
}

// open opens a session to the agent on whichever Link has its connection.
func (r *fakeLinkRelay) open(t *testing.T, node peerlink.Link, open *pb.TCPData) net.Conn {
	t.Helper()
	h, err := dataplane.OpenHeader(open)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := node.Open(ctx, "agent", h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) // a refused one too (link debug mode reports it)
	return s
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// wsBackend answers an upgrade with 101 and echoes the switched bytes.
func wsBackend(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			_, _ = io.WriteString(w, "plain "+r.URL.Path)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		_, _ = io.Copy(conn, brw)
	}))
	t.Cleanup(s.Close)
	return s
}

// TestAgentLinkSessions: on each transport the relay's sessions reach a raw
// target, the HTTP tunnel, and a WebSocket through it.
func TestAgentLinkSessions(t *testing.T) {
	echo := echoServer(t)
	ws := wsBackend(t)
	h, err := NewTunnelHandler(Config{AgentID: "agent", Routes: []Route{{Backend: ws.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{TransportTCP, TransportQUIC, TransportAuto} {
		t.Run(transport, func(t *testing.T) {
			r := newFakeLinkRelay(t)
			offer := dataplane.AgentLinkOffer{TCP: true, QUIC: true, QUICPort: r.udpAddr.Port}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ls := &linkSessions{ctx: ctx, targets: sessionTargets{forwardAddr: echo, http: h}, logger: slog.Default()}
			served := make(chan bool, 1)
			go func() { served <- runAgentLink(ctx, r.dialer(transport), testLinkToken, offer, ls, slog.Default()) }()
			node := r.won(t)
			s := r.open(t, node, &pb.TCPData{TargetAddr: "ignored:1"})
			if _, err := s.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("raw echo %q %v", buf, err)
			}
			_ = s.Close()

			s = r.open(t, node, &pb.TCPData{TargetAddr: dataplane.HTTPSessionTarget})
			_, _ = io.WriteString(s, "GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
			br := bufio.NewReader(s)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "plain /x" {
				t.Fatalf("http body %q", body)
			}
			_, _ = io.WriteString(s, "GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			resp, err = http.ReadResponse(br, nil)
			if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade: %v %v", resp, err)
			}
			_, _ = io.WriteString(s, "frame")
			buf = make([]byte, 5)
			if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "frame" {
				t.Fatalf("ws echo %q %v", buf, err)
			}
			_ = s.Close()

			cancel()
			select {
			case ok := <-served:
				if !ok {
					t.Fatal("the agent link never connected")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("runAgentLink did not return after its primary ended")
			}
		})
	}
}

// TestAgentLinkUDPBlocked: auto with QUIC black-holed takes TCP after the
// head start, and remembers the network's failure.
func TestAgentLinkUDPBlocked(t *testing.T) {
	r := newFakeLinkRelay(t)
	hole := peerlinktest.NewUDPProxy(t, r.udpAddr.String())
	hole.BlackHole()
	_, port, _ := net.SplitHostPort(hole.Addr())
	p, _ := strconv.Atoi(port)
	offer := dataplane.AgentLinkOffer{TCP: true, QUIC: true, QUICPort: p}
	key := networkKey("127.0.0.1", p)
	udpFailures.Delete(key)
	t.Cleanup(func() { udpFailures.Delete(key) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ls := &linkSessions{ctx: ctx, targets: sessionTargets{forwardAddr: echoServer(t)}, logger: slog.Default()}
	start := time.Now()
	go runAgentLink(ctx, r.dialer(TransportAuto), testLinkToken, offer, ls, slog.Default())
	s := r.open(t, r.tcp, &pb.TCPData{TargetAddr: "x:1"})
	if d := time.Since(start); d < quicHeadStart {
		t.Errorf("TCP up after %s, before the head start", d)
	}
	_, _ = s.Write([]byte("ok"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(dataHelloTimeout + 5*time.Second)
	for !udpFailedRecently(key) {
		if time.Now().After(deadline) {
			t.Fatal("the QUIC failure was not remembered")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if q, tc := r.dialer(TransportAuto).linkPlan(offer); !q || !tc {
		t.Fatalf("plan %v %v", q, tc)
	}
}

// TestAgentLinkQUICRefusedRedials: QUIC connections refused by a relay
// replica that does not hold the agent's primary (behind a load balancer)
// are redialled until one binds, and the network's UDP is not marked
// failed. TCP waits for the redials only when the first refusal came
// within QUIC's head start; under load it may already race, and win.
func TestAgentLinkQUICRefusedRedials(t *testing.T) {
	// slow: the refusals outlast QUIC's head start, so TCP races and wins.
	for name, slow := range map[string]time.Duration{"fast": 0, "slow": quicHeadStart + 50*time.Millisecond} {
		t.Run(name, func(t *testing.T) { testQUICRefusedRedials(t, slow) })
	}
}

func testQUICRefusedRedials(t *testing.T, slow time.Duration) {
	r := newFakeLinkRelay(t)
	r.refuse.Store(5)
	r.slowRefusal.Store(int64(slow))
	offer := dataplane.AgentLinkOffer{TCP: true, QUIC: true, QUICPort: r.udpAddr.Port}
	key := networkKey("127.0.0.1", r.udpAddr.Port)
	udpFailures.Delete(key)
	t.Cleanup(func() { udpFailures.Delete(key) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ls := &linkSessions{ctx: ctx, targets: sessionTargets{forwardAddr: echoServer(t)}, logger: slog.Default()}
	go runAgentLink(ctx, r.dialer(TransportAuto), testLinkToken, offer, ls, slog.Default())
	node := r.won(t)
	s := r.open(t, node, &pb.TCPData{TargetAddr: "x:1"})
	_, _ = s.Write([]byte("ok"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatal(err)
	}
	// A QUIC loser keeps redialling until one binds, then lost the race; a
	// TCP loser's connection is taken too when TCP had started.
	want := int32(1)
	if node == r.tcp {
		want = 2
	}
	deadline := time.Now().Add(10 * time.Second)
	for r.accepted.Load() < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := r.refuse.Load(); n >= 0 {
		t.Fatalf("%d refusals left", n+1)
	}
	if udpFailedRecently(key) {
		t.Fatal("a refusal was remembered as a UDP failure")
	}
	if n := r.accepted.Load(); n < want || n > 2 {
		t.Fatalf("%d agent-link connections taken, want %d to 2", n, want)
	}
}

// TestAgentLinkQUICRebind: a session on QUIC survives the agent's address
// changing mid-session (a NAT rebinding).
func TestAgentLinkQUICRebind(t *testing.T) {
	r := newFakeLinkRelay(t)
	px := peerlinktest.NewUDPProxy(t, r.udpAddr.String())
	_, port, _ := net.SplitHostPort(px.Addr())
	p, _ := strconv.Atoi(port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ls := &linkSessions{ctx: ctx, targets: sessionTargets{forwardAddr: echoServer(t)}, logger: slog.Default()}
	go runAgentLink(ctx, r.dialer(TransportQUIC), testLinkToken, dataplane.AgentLinkOffer{QUIC: true, QUICPort: p}, ls, slog.Default())
	s := r.open(t, r.quic, &pb.TCPData{TargetAddr: "x:1"})
	buf := make([]byte, 64<<10)
	for i := range 6 {
		if i == 3 {
			px.Rebind()
		}
		if _, err := s.Write(buf); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := io.ReadFull(s, buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	_ = s.Close()
}

func TestParseTransport(t *testing.T) {
	for in, want := range map[string]string{"": TransportTCP, "tcp": "tcp", "quic": "quic", "auto": "auto"} {
		if got, err := ParseTransport(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := ParseTransport("udp"); err == nil {
		t.Error("udp accepted")
	}
}

// TestLazyAgentLink: on each transport the agent dials its link only when
// the relay asks (concurrent asks: one dial), the relay's sessions ride
// it, the agent closes it when the relay retires it, and a later ask
// dials it again.
func TestLazyAgentLink(t *testing.T) {
	echo := echoServer(t)
	for _, transport := range []string{TransportTCP, TransportQUIC, TransportAuto} {
		t.Run(transport, func(t *testing.T) {
			r := newFakeLinkRelay(t)
			md := metadata.Pairs(tcpBindHeader, testLinkToken, dataplane.AgentLinkHeader, "tcp,quic",
				dataplane.AgentLinkQUICHeader, strconv.Itoa(r.udpAddr.Port))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ls := &linkSessions{ctx: ctx, targets: sessionTargets{forwardAddr: echo}, logger: slog.Default()}
			z := newLazyLink(ctx, r.dialer(transport), func() (metadata.MD, error) { return md, nil }, ls, slog.Default())
			time.Sleep(200 * time.Millisecond)
			if n := r.accepted.Load(); n != 0 {
				t.Fatalf("%d agent-link connections before the relay asked", n)
			}
			for round := range 2 {
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() { z.control(dataplane.AgentLinkDial) })
				}
				wg.Wait()
				node := r.won(t)
				s := r.open(t, node, &pb.TCPData{TargetAddr: "x:1"})
				_, _ = s.Write([]byte("ping"))
				buf := make([]byte, 4)
				if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "ping" {
					t.Fatalf("round %d: echo %q %v", round, buf, err)
				}
				_ = s.Close()
				// auto's race may also take its loser's connection.
				if n, want := r.accepted.Load(), int32(round+1); n < want || n > want && (transport != TransportAuto || n > 2*want) {
					t.Fatalf("round %d: %d agent-link connections, want one per ask", round, n)
				}
				z.control(dataplane.AgentLinkClose)
				deadline := time.Now().Add(5 * time.Second)
				for {
					octx, ocancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
					h, _ := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "x:1"})
					s, err := node.Open(octx, "agent", h)
					ocancel()
					if err != nil {
						break
					}
					_ = s.Close()
					if time.Now().After(deadline) {
						t.Fatalf("round %d: the agent kept its link after the relay retired it", round)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
		})
	}
}

// mustNode panics on a node configuration the test got wrong.
func mustNode[N any](n N, err error) N {
	if err != nil {
		panic(err)
	}
	return n
}

// TestAgentLinkUpOnlyWhileBound: the agent counts its link up (and leaves
// the relay's heartbeats unanswered: the relay takes its liveness from the
// link, agentwire.LinkLivenessKey) only while the relay has a connection
// of it bound, as the relay counts it (nfltr-relay's TCPDispatcher.LinkUp).
// A link whose connections the relay refuses (one dialled through a load
// balancer to another replica, which holds no stream of the agent) or cut
// while the Node redials is down: before the fix the agent took the Node
// serving for the link up, answered no heartbeat, and the relay ended the
// agent at its receive threshold (the kind soak's heartbeat timeout, whose
// stream loss ended a held session).
func TestAgentLinkUpOnlyWhileBound(t *testing.T) {
	up := func(g *tcpStreamGrowth) bool { return g.linkUp() }
	waitUp := func(t *testing.T, g *tcpStreamGrowth, want bool, why string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for up(g) != want {
			if time.Now().After(deadline) {
				t.Fatalf("link up = %v, want %v: %s", !want, want, why)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	start := func(t *testing.T, r *fakeLinkRelay, token string) *tcpStreamGrowth {
		md := metadata.Pairs(tcpBindHeader, token, dataplane.AgentLinkHeader, "tcp")
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		g := &tcpStreamGrowth{}
		ls := &linkSessions{ctx: ctx, targets: sessionTargets{forwardAddr: echoServer(t)}, logger: slog.Default(), growth: g}
		z := newLazyLink(ctx, r.dialer(TransportTCP), func() (metadata.MD, error) { return md, nil }, ls, slog.Default())
		z.control(dataplane.AgentLinkDial)
		return g
	}
	t.Run("refused", func(t *testing.T) {
		g := start(t, newFakeLinkRelay(t), "another-replicas-token")
		time.Sleep(time.Second) // the Node's handshakes refused, redialling
		if up(g) {
			t.Fatal("link up while the relay refuses every connection of it")
		}
	})
	t.Run("cut", func(t *testing.T) {
		r := newFakeLinkRelay(t)
		g := start(t, r, testLinkToken)
		waitUp(t, g, true, "the relay bound the link")
		r.refuseTCP.Store(true)
		r.cutTCP()
		waitUp(t, g, false, "the relay's connection was cut and redials are refused")
		r.refuseTCP.Store(false)
		waitUp(t, g, true, "the Node redialled and the relay bound it")
	})
}

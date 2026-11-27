// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
)

// The tests stand in for the browser bundle (BP4) with a pion offerer on
// loopback: the page's control session (ClientTLS, the offer, the answer)
// and its streams (a data channel each, nf1.Handshake on it).

func loopbackOnly(ip net.IP) bool { return ip.IsLoopback() }

// bpAgent is an agent serving one address with b; its streams echo.
type bpAgent struct {
	b      *BrowserDirect
	l      *nf1.Listener
	key    ed25519.PrivateKey
	served atomic.Int32
}

func newBPAgent(t *testing.T, b *BrowserDirect) *bpAgent {
	t.Helper()
	l, key, err := nf1.Mint("relay.example")
	if err != nil {
		t.Fatal(err)
	}
	b.ipFilter = loopbackOnly
	return &bpAgent{b: b, l: l, key: key}
}

// control starts ServeBrowser on one end of a pipe and returns the other
// (the visitor's, the answer and mark already past) and a channel closed
// when ServeBrowser returned.
func (a *bpAgent) control(t *testing.T) (net.Conn, <-chan struct{}) {
	t.Helper()
	agent, visitor := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.b.ServeBrowser(context.Background(), agent, a.l, func(_ context.Context, tc net.Conn) {
			a.served.Add(1)
			_, _ = io.Copy(tc, tc)
			_ = tc.Close()
		})
	}()
	t.Cleanup(func() {
		_ = visitor.Close()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("ServeBrowser did not return")
		}
	})
	return visitor, done
}

// bpVisitor is the page: its connection and its first stream's channel
// (an offer needs one).
type bpVisitor struct {
	pc    *webrtc.PeerConnection
	first *webrtc.DataChannel
}

func newBPVisitor(t *testing.T) *bpVisitor {
	t.Helper()
	se := webrtc.SettingEngine{}
	se.DetachDataChannels()
	se.SetIncludeLoopbackCandidate(true)
	se.SetNetworkTypes(rtcNetworkTypes)
	se.SetIPFilter(loopbackOnly)
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled
	se.LoggerFactory = lf
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	first, err := pc.CreateDataChannel(BrowserDCLabel, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &bpVisitor{pc: pc, first: first}
}

// signal runs the control session's exchange on tc: the offer, then the
// agent's answer (nil: no direct path now).
func (v *bpVisitor) signal(t *testing.T, tc net.Conn) *webrtc.SessionDescription {
	t.Helper()
	offer, err := v.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(v.pc)
	if err := v.pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-gathered
	if err := writeSignal(tc, v.pc.LocalDescription()); err != nil {
		t.Fatal(err)
	}
	answer, err := readSignal(tc)
	if err != nil {
		t.Fatal(err)
	}
	if answer != nil {
		if err := v.pc.SetRemoteDescription(*answer); err != nil {
			t.Fatal(err)
		}
	}
	return answer
}

// admitted is the page's control session: TLS, proof, verdict, then the
// exchange; it fails the test unless the agent answered.
func (v *bpVisitor) admitted(t *testing.T, ctl net.Conn, addr capaddr.Address) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tc, err := nf1.ClientTLS(ctx, ctl, addr)
	if err != nil {
		t.Fatal(err)
	}
	if v.signal(t, tc) == nil {
		t.Fatal("no answer")
	}
	return tc
}

// open waits for d to open and returns its byte stream, no handshake run.
func openDC(t *testing.T, d *webrtc.DataChannel) *bpConn {
	t.Helper()
	opened := make(chan *bpConn, 1)
	d.OnOpen(func() {
		rwc, err := d.DetachWithDeadline()
		if err != nil {
			close(opened)
			return
		}
		opened <- newBPConn(rwc, d)
	})
	select {
	case c := <-opened:
		if c == nil {
			t.Fatal("detach failed")
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(15 * time.Second):
		t.Fatal("data channel did not open")
	}
	return nil
}

// stream opens a new stream (the first channel when first) and runs its
// nf1 handshake.
func (v *bpVisitor) stream(t *testing.T, addr capaddr.Address, first bool) (net.Conn, error) {
	t.Helper()
	d := v.first
	if !first {
		var err error
		if d, err = v.pc.CreateDataChannel(BrowserDCLabel, nil); err != nil {
			t.Fatal(err)
		}
	}
	c := openDC(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return nf1.Handshake(ctx, c, addr)
}

func echo(t *testing.T, c net.Conn, msg string) error {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != msg {
		t.Fatalf("echo %q, want %q", b, msg)
	}
	return nil
}

func TestBrowserDirectServesStreamsOnDataChannels(t *testing.T) {
	a := newBPAgent(t, &BrowserDirect{})
	ctl, done := a.control(t)
	v := newBPVisitor(t)
	tc := v.admitted(t, ctl, a.l.Address())
	if err := writeSignal(tc, nil); err != nil { // the page's keepalive
		t.Fatal(err)
	}
	for i, first := range []bool{true, false} {
		c, err := v.stream(t, a.l.Address(), first)
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		if err := echo(t, c, "hello"); err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		_ = c.Close()
	}
	if n := a.served.Load(); n != 2 {
		t.Fatalf("served %d streams, want 2", n)
	}
	_ = tc.Close()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the control session's end did not end ServeBrowser")
	}
	if n := a.b.peers.Load(); n != 0 {
		t.Fatalf("%d connections held after the control session ended", n)
	}
}

// A channel past MaxDC is closed; once a stream ends, a new one is served.
func TestBrowserDirectCapsDataChannels(t *testing.T) {
	a := newBPAgent(t, &BrowserDirect{MaxDC: 1})
	ctl, _ := a.control(t)
	v := newBPVisitor(t)
	v.admitted(t, ctl, a.l.Address())
	c1, err := v.stream(t, a.l.Address(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(t, c1, "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.stream(t, a.l.Address(), false); err == nil {
		t.Fatal("a second channel past MaxDC 1 was served")
	}
	_ = c1.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c3, err := v.stream(t, a.l.Address(), false)
		if err == nil {
			if err := echo(t, c3, "three"); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) { // the agent frees the slot once the first stream's end reached it
			t.Fatalf("no stream after the first ended: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The control session's end reaps the connection: its open streams fail.
func TestBrowserDirectReapsWithTheControlSession(t *testing.T) {
	a := newBPAgent(t, &BrowserDirect{})
	ctl, done := a.control(t)
	v := newBPVisitor(t)
	tc := v.admitted(t, ctl, a.l.Address())
	c, err := v.stream(t, a.l.Address(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(t, c, "before"); err != nil {
		t.Fatal(err)
	}
	_ = tc.Close()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the control session's end did not reap its connection and streams")
	}
	start := time.Now()
	_ = c.SetDeadline(start.Add(10 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("a stream outlived its control session: %v after %v", err, time.Since(start))
	}
}

// Past MaxPeers a control session gets an empty answer: no connection.
func TestBrowserDirectCapsConnections(t *testing.T) {
	a := newBPAgent(t, &BrowserDirect{MaxPeers: 1})
	ctl1, _ := a.control(t)
	newBPVisitor(t).admitted(t, ctl1, a.l.Address())
	ctl2, _ := a.control(t)
	tc2, err := nf1.ClientTLS(context.Background(), ctl2, a.l.Address())
	if err != nil {
		t.Fatal(err)
	}
	if ans := newBPVisitor(t).signal(t, tc2); ans != nil {
		t.Fatal("a second connection past MaxPeers 1")
	}
	if n := a.b.offers.Load(); n != 1 {
		t.Fatalf("%d connections made, want 1", n)
	}
}

// A visitor that closes its connection: the agent's streams on it end and
// the control session with it (PCFail, Reap, Break in the trace).
func TestBrowserDirectVisitorConnectionGone(t *testing.T) {
	a := newBPAgent(t, &BrowserDirect{})
	ctl, done := a.control(t)
	v := newBPVisitor(t)
	v.admitted(t, ctl, a.l.Address())
	c, err := v.stream(t, a.l.Address(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(t, c, "x"); err != nil {
		t.Fatal(err)
	}
	_ = v.pc.Close()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the agent kept the connection after the visitor closed it")
	}
}

// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package mailboxclient

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	mailboxv1 "github.com/nfltr/relay/proto/nfltr/mailbox/v1"
)

// A NAT that lost its mapping of a parked long-poll's connection (a router
// change, a conntrack flush) holds the relay's answer until this side sends
// a packet on it. The client's HTTP/2 health check is that packet: the
// answer of an append arrives within the ping's interval, not when TCP's
// keepalive (30 s idle) or the pull's own deadline (its wait plus 30 s)
// happens to send one. Without the health check the answer stays held
// (the control). Lane REVOKEWAKE, docs/decisions/direct-paths-2026-11-11.md
// (nfltr/nfltr): the first revoke after an agent started took 33-35 s.
func TestLongPollAnswerCrossesALostNATMapping(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ping  bool
		bound time.Duration
	}{{"health check", true, 3 * time.Second}, {"no health check", false, 2 * time.Second}} {
		t.Run(tc.name, func(t *testing.T) {
			parked, answer := make(chan struct{}), make(chan struct{})
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body) // the request has crossed: the pull is parked
				close(parked)
				<-answer // the append that wakes the pull
				data, _ := protojson.Marshal(&mailboxv1.PullMessagesResponse{Envelopes: []*mailboxv1.Envelope{{Seq: 7}}})
				_, _ = w.Write(data)
			}))
			srv.EnableHTTP2 = true
			srv.StartTLS()
			defer srv.Close()
			defer close(answer)
			n := newNAT(t, srv.Listener.Addr().String())
			base := srv.Client().Transport.(*http.Transport).Clone()
			base.TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
			hc := &http.Client{Transport: base}
			if tc.ping {
				hc = healthChecked(base, time.Second, 2*time.Second)
			}
			c := Client{ProxyURL: "https://" + n.addr, HTTP: hc}
			ctx, cancel := context.WithCancel(context.Background())
			got := make(chan error, 1)
			defer func() { // the pull ends (and with it the connection) before the server
				cancel()
				select {
				case <-got:
				case <-time.After(5 * time.Second):
					t.Error("the pull did not end with its context")
				}
				hc.CloseIdleConnections()
			}()
			go func() {
				envs, _, err := c.Pull(ctx, "inbox", 0, 0, 20*time.Second)
				if err == nil && (len(envs) != 1 || envs[0].Seq != 7) {
					err = io.ErrUnexpectedEOF
				}
				got <- err
			}()
			<-parked
			n.flushWhenQuiet(200 * time.Millisecond) // the connection's start-up frames have crossed
			answer <- struct{}{}
			sent := time.Now()
			select {
			case err := <-got:
				got <- err // for the deferred wait
				if !tc.ping {
					t.Fatalf("the answer crossed the lost mapping without a packet from this side (%v): the control proves nothing", err)
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("the answer crossed after %s", time.Since(sent).Round(time.Millisecond))
			case <-time.After(tc.bound):
				if tc.ping {
					t.Fatalf("the relay's answer was still held by the NAT after %s", tc.bound)
				}
			}
		})
	}
}

// The client a Client without its own uses pings a silent connection well
// inside one long-poll (the relay holds one at most 25 s).
func TestDefaultClientHealthChecks(t *testing.T) {
	tr, ok := relayHTTP().Transport.(*http.Transport)
	if !ok || tr.HTTP2 == nil || tr.HTTP2.SendPingTimeout <= 0 || tr.HTTP2.SendPingTimeout > 25*time.Second/2 {
		t.Fatalf("default transport's HTTP/2 health check: %+v", tr.HTTP2)
	}
}

// nat forwards one TCP connection to target; flush drops its mapping:
// bytes from target are held from then until the client sends again (a
// cone NAT re-makes the mapping on the next outgoing packet and the
// relay's retransmission goes through).
type nat struct {
	addr    string
	mu      sync.Mutex
	cond    *sync.Cond
	lost    bool
	lastOut time.Time
}

func newNAT(t *testing.T, target string) *nat {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	n := &nat{addr: ln.Addr().String()}
	n.cond = sync.NewCond(&n.mu)
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				_ = in.Close()
				return
			}
			t.Cleanup(func() { _ = in.Close(); _ = out.Close() })
			go n.pipe(out, in, true)
			go n.pipe(in, out, false)
		}
	}()
	return n
}

// flushWhenQuiet drops the mapping once the client sent nothing for d.
func (n *nat) flushWhenQuiet(d time.Duration) {
	for {
		n.mu.Lock()
		if time.Since(n.lastOut) >= d {
			n.lost = true
			n.mu.Unlock()
			return
		}
		n.mu.Unlock()
		time.Sleep(d / 4)
	}
}

// pipe copies src to dst; outgoing (client to relay) bytes re-make a lost
// mapping, incoming ones wait for it.
func (n *nat) pipe(dst, src net.Conn, outgoing bool) {
	buf := make([]byte, 32<<10)
	for {
		k, err := src.Read(buf)
		if err != nil {
			_ = dst.Close()
			n.mu.Lock()
			n.lost = false // a closed connection holds nothing back
			n.cond.Broadcast()
			n.mu.Unlock()
			return
		}
		n.mu.Lock()
		if outgoing {
			n.lastOut = time.Now()
			n.lost = false
			n.cond.Broadcast()
		}
		for !outgoing && n.lost {
			n.cond.Wait()
		}
		n.mu.Unlock()
		if _, err := dst.Write(buf[:k]); err != nil {
			return
		}
	}
}

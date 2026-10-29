// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

// dialTimeout is the per-candidate TCP dial timeout.
const dialTimeout = 10 * time.Second

// authTimeout is the maximum time allowed for the HMAC handshake after TCP
// connects.
const authTimeout = 5 * time.Second

// ErrNoRoute is returned when all P2P connection attempts fail and no relay
// fallback is configured.
var ErrNoRoute = errors.New("p2p: could not establish direct connection (all candidates failed)")

// GatherCandidates opens a TCP listener on an OS-assigned port, gathers all
// local (host) candidates and the STUN server-reflexive candidate, and returns
// the listener together with the deduplicated candidate list.
//
// The caller is responsible for closing the listener after negotiation.
func GatherCandidates(_ context.Context) (*net.TCPListener, []string, error) {
	ln, candidates, err := ListenHostCandidates()
	if err != nil {
		return nil, nil, err
	}
	// Server-reflexive candidate via STUN.
	srAddr, err := DiscoverExternalAddr(ln.Addr().(*net.TCPAddr).Port)
	if err == nil && srAddr != "" {
		candidates = dedupAppend(candidates, srAddr)
	}
	return ln, candidates, nil
}

// ListenHostCandidates is GatherCandidates without the STUN probe: the
// listener and its host candidates only. Calls and file transfers use it for
// the direct TCP channel, which only connects where host addresses reach
// (ICE covers NATs), so they never wait for STUN (up to 4 s when UDP to the
// STUN server is blocked).
func ListenHostCandidates() (*net.TCPListener, []string, error) {
	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("p2p: open listener: %w", err)
	}
	return ln.(*net.TCPListener), GatherHostCandidates(ln.Addr().(*net.TCPAddr).Port), nil
}

// ConnID identifies an authenticated direct connection: a hash of both
// handshake challenges, the same on both ends whatever a NAT did to the
// addresses. "" for any other conn.
func ConnID(c net.Conn) string {
	if e, ok := c.(*encryptedConn); ok {
		return e.id
	}
	return ""
}

// dialAndAccept dials every candidate and accepts on ln at once; each
// connection that passes the mutual HMAC handshake goes to emit, which owns
// it. It returns, closing ln, once ctx has ended and every attempt finished.
func dialAndAccept(ctx context.Context, ln *net.TCPListener, theirCandidates []string,
	token []byte, sessionID string, emit func(net.Conn),
) {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	defer ln.Close() //nolint:errcheck
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				if ec, err := handshake(conn, token, sessionID, false); err == nil {
					emit(ec)
				} else {
					conn.Close() //nolint:errcheck // could be an unrelated scanner
				}
			})
		}
	})
	for _, addr := range theirCandidates {
		wg.Go(func() {
			dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp4", addr)
			if err != nil {
				return // expected for unreachable candidates
			}
			if ec, err := handshake(conn, token, sessionID, true); err == nil {
				emit(ec)
			} else {
				conn.Close() //nolint:errcheck
			}
		})
	}
	wg.Wait()
}

// Connect establishes a peer-to-peer TCP connection using the exchanged
// candidates. Both sides run it concurrently with the listener from
// GatherCandidates, the peer's candidates, the shared secret (E2E.DirectToken) and
// the session ID (HMAC context); role ("initiator"/"responder") names the
// side. Several connections can authenticate (several host IPs), so the two
// sides must keep the same one: the dialing side (AnnounceConn) keeps the
// highest ConnID it saw within a short window of the first and tells the
// other side (AwaitConn), which keeps exactly that connection. A side given
// neither option, or whose peer announces nothing (a peer that predates
// SignalSelect), keeps the highest ConnID it saw within that window, which
// two loaded peers can pick differently. myListener is closed before
// returning.
func Connect(
	ctx context.Context,
	myListener *net.TCPListener,
	theirCandidates []string,
	token []byte,
	sessionID string,
	_ string,
	opts ...ConnectOption,
) (net.Conn, error) {
	var cfg connectConfig
	for _, o := range opts {
		o(&cfg)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	results := make(chan net.Conn)
	go func() {
		defer close(results)
		dialAndAccept(ctx, myListener, theirCandidates, token, sessionID, func(c net.Conn) {
			select {
			case results <- c:
			case <-ctx.Done():
				c.Close() //nolint:errcheck
			}
		})
	}()
	conn, err := pick(results, cfg.await)
	cancel()
	go func() { // late results
		for c := range results {
			c.Close() //nolint:errcheck
		}
	}()
	if err == nil && cfg.announce != nil {
		_ = cfg.announce(ConnID(conn)) // unsent: the peer keeps its own pick
	}
	return conn, err
}

// collectWindow is how long a side without an announced choice waits, after
// the first authenticated connection, for others before keeping the highest
// ConnID.
const collectWindow = 50 * time.Millisecond

// pick returns the connection to keep from results and closes every other
// one it received. With await (the other side's announced ConnID), it keeps
// that connection, waiting for it to authenticate here; when await fails
// without ErrPeerRelay, or names a connection that never arrives, it keeps
// the highest ConnID seen within collectWindow of the first.
func pick(results <-chan net.Conn, await func() (string, error)) (net.Conn, error) {
	type choice struct {
		id  string
		err error
	}
	var chosen chan choice
	if await != nil {
		chosen = make(chan choice, 1)
		go func() {
			id, err := await()
			chosen <- choice{id, err}
		}()
	}
	held := map[string]net.Conn{}
	keep := func(k net.Conn, err error) (net.Conn, error) {
		for _, c := range held {
			if c != k {
				c.Close() //nolint:errcheck
			}
		}
		return k, err
	}
	var best net.Conn
	var timer <-chan time.Time
	want, windowOver := "", false
	for results != nil || chosen != nil {
		if c, ok := held[want]; ok && want != "" {
			return keep(c, nil)
		}
		if chosen == nil && want == "" && windowOver {
			break
		}
		select {
		case c, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			held[ConnID(c)] = c
			if best == nil || ConnID(c) > ConnID(best) {
				best = c
			}
			if timer == nil {
				timer = time.After(collectWindow)
			}
		case <-timer:
			windowOver = true
		case ch := <-chosen:
			chosen = nil
			if errors.Is(ch.err, ErrPeerRelay) {
				return keep(nil, ErrPeerRelay)
			}
			want = ch.id
		}
	}
	if best == nil {
		return nil, ErrNoRoute
	}
	return keep(best, nil)
}

// handshake performs mutual HMAC-SHA256 authentication over a raw TCP
// connection and upgrades it to AES-256-CTR encrypted transport.
//
// Protocol (4 steps, each side runs concurrently):
//  1. Each side sends 32 random challenge bytes.
//  2. Each side reads the other's 32 challenge bytes.
//  3. Each side sends HMAC-SHA256(token, sessionID + ":" + myChallenge + theirChallenge)[:16].
//  4. Each side reads and verifies the other's response.
//
// After authentication, both sides derive a shared AES-256 key and
// direction-specific IVs from the token, session ID, and both challenges.
// The returned net.Conn transparently encrypts all writes and decrypts all
// reads using AES-256-CTR.
//
// isDialer distinguishes which side initiated the TCP connection; it
// determines the IV assignment so each direction uses a unique (key, IV) pair.
func handshake(conn net.Conn, token []byte, sessionID string, isDialer bool) (net.Conn, error) {
	_ = conn.SetDeadline(time.Now().Add(authTimeout))
	defer conn.SetDeadline(time.Time{}) //nolint:errcheck

	// Step 1 & 2: exchange 32-byte challenges concurrently.
	myChallenge := make([]byte, 32)
	if _, err := rand.Read(myChallenge); err != nil {
		return nil, fmt.Errorf("p2p auth: rand: %w", err)
	}

	type recvResult struct {
		data []byte
		err  error
	}
	theirChallengeC := make(chan recvResult, 1)

	go func() {
		buf := make([]byte, 32)
		_, err := io.ReadFull(conn, buf)
		theirChallengeC <- recvResult{buf, err}
	}()

	if _, err := conn.Write(myChallenge); err != nil {
		return nil, fmt.Errorf("p2p auth: send challenge: %w", err)
	}

	recv := <-theirChallengeC
	if recv.err != nil {
		return nil, fmt.Errorf("p2p auth: recv challenge: %w", recv.err)
	}
	theirChallenge := recv.data

	// Step 3 & 4: exchange HMAC responses concurrently.
	myResp := computeHMAC(token, sessionID, myChallenge, theirChallenge)

	theirRespC := make(chan recvResult, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := io.ReadFull(conn, buf)
		theirRespC <- recvResult{buf, err}
	}()

	if _, err := conn.Write(myResp); err != nil {
		return nil, fmt.Errorf("p2p auth: send response: %w", err)
	}

	recvResp := <-theirRespC
	if recvResp.err != nil {
		return nil, fmt.Errorf("p2p auth: recv response: %w", recvResp.err)
	}

	expectedTheirResp := computeHMAC(token, sessionID, theirChallenge, myChallenge)
	if !hmac.Equal(recvResp.data, expectedTheirResp) {
		return nil, errors.New("p2p auth: token mismatch — peer used a different shared secret")
	}

	// Derive per-session encryption key and upgrade to encrypted transport.
	key, writeIV, readIV := deriveSessionKey(token, sessionID, myChallenge, theirChallenge, isDialer)
	ec, err := newEncryptedConn(conn, key, writeIV, readIV)
	if err != nil {
		return nil, err
	}
	dialerC, accepterC := myChallenge, theirChallenge
	if !isDialer {
		dialerC, accepterC = theirChallenge, myChallenge
	}
	id := sha256.Sum256(append(append([]byte("nfltr-p2p-conn:"), dialerC...), accepterC...))
	ec.id = hex.EncodeToString(id[:16])
	return ec, nil
}

// computeHMAC returns HMAC-SHA256(token, sessionID+":"+ownChallenge+theirChallenge)[:16].
// Using the session ID in the HMAC input prevents cross-session replay attacks.
func computeHMAC(token []byte, sessionID string, ownChallenge, theirChallenge []byte) []byte {
	h := hmac.New(sha256.New, token)
	h.Write([]byte(sessionID))
	h.Write([]byte(":"))
	h.Write(ownChallenge)
	h.Write(theirChallenge)
	return h.Sum(nil)[:16]
}

// dedupAppend appends addr to slice if it is not already present.
func dedupAppend(slice []string, addr string) []string {
	if slices.Contains(slice, addr) {
		return slice
	}
	return append(slice, addr)
}

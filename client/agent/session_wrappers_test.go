// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net"
	"slices"
	"testing"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
)

// endRec is a link session as a wrapper sees it: it records which of its
// end methods were called.
type endRec struct {
	net.Conn
	calls []string
}

func (e *endRec) CloseWrite() error     { e.calls = append(e.calls, "CloseWrite"); return nil }
func (e *endRec) CloseWriteSync() error { e.calls = append(e.calls, "CloseWriteSync"); return nil }
func (e *endRec) Reset() error          { e.calls = append(e.calls, "Reset"); return nil }
func (e *endRec) CloseWriteSyncReceived(received func()) error {
	e.calls = append(e.calls, "CloseWriteSyncReceived")
	received()
	return nil
}

// endMethod calls end method m of c, false when c has none.
func endMethod(c net.Conn, m string) (func() error, bool) {
	switch m {
	case "CloseWrite":
		s, ok := c.(interface{ CloseWrite() error })
		return func() error { return s.CloseWrite() }, ok
	case "CloseWriteSync":
		s, ok := c.(interface{ CloseWriteSync() error })
		return func() error { return s.CloseWriteSync() }, ok
	case "CloseWriteSyncReceived":
		s, ok := c.(interface{ CloseWriteSyncReceived(func()) error })
		return func() error { return s.CloseWriteSyncReceived(func() {}) }, ok
	default:
		s, ok := c.(interface{ Reset() error })
		return func() error { return s.Reset() }, ok
	}
}

// TestSessionWrappersPassTheEndOn (lane ENDTRACE): every net.Conn wrapper
// of the relay client that sits over a link session (or a pathswitch
// stream over one) has exactly the end methods its session has and passes
// each on: tlsend finds a link session's half close, its end
// acknowledgement and its reset through it, and a wrapper hiding one
// turns them into a whole close (nf1.AnswerConn before lane PIPERESET:
// Close sent no FIN, Reset was a clean close; detachTap before lane
// ENDTRACE: an anonymous session's Reset was psConn's clean Close), while
// one claiming an end its session lacks breaks tlsend's direct-path
// exemption (a CloseWriteSync over a direct path's conn: Close waits
// EndBound). Not here: wrappers that embed a concrete type (nf1's conn,
// anonTarget: every method promoted), datagramTarget (a pipe), p2p's
// encryptedConn and secureConn (direct transports), tlsbatch (TCP to the
// relay) and tlsend's rawEnd (below crypto/tls: tlsend calls its conn's
// end methods itself). link's peerlink session: link's
// TestNodeSessionPassesTheEndOn.
func TestSessionWrappersPassTheEndOn(t *testing.T) {
	all := []string{"CloseWrite", "CloseWriteSync", "CloseWriteSyncReceived", "Reset"}
	for _, tc := range []struct {
		name string
		wrap func(net.Conn) net.Conn
		ends []string // the session's end methods (psConn's: CloseWrite, Reset)
	}{
		{"detachTap: an anonymous session's psConn", func(c net.Conn) net.Conn { return &detachTap{Conn: c} }, []string{"CloseWrite", "Reset"}},
		{"peekConn: a relayed nf1 session", func(c net.Conn) net.Conn { return &peekConn{Conn: c} }, all},
		{"pathStream: a pathswitch stream (pathswitch acknowledges its own END)", func(c net.Conn) net.Conn { return pathStream{Conn: c} }, []string{"CloseWrite", "Reset"}},
		{"nf1.AnswerConn: an early relayed session", func(c net.Conn) net.Conn { return nf1.EarlyAnswer(c, capaddr.Address{}, false, nil) }, []string{"CloseWrite", "CloseWriteSyncReceived", "Reset"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, m := range all {
				rec := &endRec{}
				call, has := endMethod(tc.wrap(rec), m)
				want := slices.Contains(tc.ends, m)
				switch {
				case has != want:
					t.Errorf("%s: has %v, want %v", m, has, want)
				case !has:
				case call() != nil:
					t.Errorf("%s: an error", m)
				case !slices.Equal(rec.calls, []string{m}):
					t.Errorf("%s passed on as %v", m, rec.calls)
				}
			}
		})
	}
	// A direct path's conn acknowledges no end: tlsend's Close takes none
	// on it (tlsend TestCloseOnADirectPathTakesNoEnd).
	for _, m := range []string{"CloseWriteSync", "CloseWriteSyncReceived"} {
		if _, has := endMethod(&psConn{}, m); has {
			t.Errorf("psConn has %s: tlsend's Close would wait EndBound on a direct path", m)
		}
	}
}

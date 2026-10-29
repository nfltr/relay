// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package dataplane carries a TCP tunnel's session frames (pb.TCPData)
// between an agent and its relay on a connection of their own, without gRPC
// or HTTP/2. The agent opens such a connection to the relay's gRPC port, where
// its first bytes (Magic) tell it apart from an HTTP/2 preface, and binds it
// to its authenticated ConnectTCP stream with that stream's bind token.
//
// The connection is a github.com/nfltr/link link of wire version 2 (its
// doc.go specifies the wire format; version 1 was removed with link
// v0.5.0); this package is its pb.TCPData adapter. A data frame carries a
// TCPData that is only a session id and data, raw; a message frame carries
// any other TCPData, protobuf-encoded (never empty). A session's open is
// an OPEN frame whose header is the open TCPData, protobuf-encoded without
// its session id and open flag, and a close that is only a session id and
// the flag is a CLOSE frame; the link runs the session's credit, and
// pings the connection with the agent's liveness.
//
// The relay advertises the versions it takes in the ConnectTCP response
// header Header, one value each: "2" (relays before nfltr-relay v0.14.0
// advertised "1" and "2"; one that advertises only "1" gets no data
// connection from this package, its tunnels stay on the gRPC stream). On
// a gRPC stream, where the link does not run,
// the two sides keep per-session credit themselves when both announce
// their window in CreditHeader (the agent in its request metadata, the
// relay in its response header): window updates travel as control frames
// (WindowFrame).
package dataplane

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/protobuf/proto"
)

// Header is the ConnectTCP response header in which the relay advertises
// data connections, one value per version it takes.
const Header = "x-nfltr-tcp-data"

// Versions are the data-connection versions this package speaks, as
// Header values, oldest first.
var Versions = []string{"2"}

// PickVersion is the highest version both this package and a relay that
// advertised values (Header) speak; 0 when none.
func PickVersion(values []string) int {
	best := 0
	for _, v := range values {
		v = strings.TrimSpace(v)
		if n, err := strconv.Atoi(v); err == nil && n > best && slices.Contains(Versions, v) {
			best = n
		}
	}
	return best
}

// CreditHeader carries a side's per-session window on a ConnectTCP gRPC
// stream: the agent's in its request metadata, the relay's in its
// response header. With both, the stream's sessions run on credit.
const CreditHeader = "x-nfltr-tcp-credit" // #nosec G101 -- a header name, not a credential

// HTTPSessionTarget is the target of a session that carries HTTP/1.1 to the
// agent's own HTTP server: the relay's reverse proxy writes requests into
// it and the agent serves them with net/http, in place of HTTP requests as
// ConnectHTTP messages (client generation 3).
const HTTPSessionTarget = "nfltr:http"

// HTTPSessionsHeader, "1" in an agent's ConnectTCP request metadata, says
// its TCP streams serve sessions to HTTPSessionTarget; the relay then sends
// the agent's HTTP requests there.
const HTTPSessionsHeader = "x-nfltr-http-sessions"

// WindowSID is the session id of the control frame that carries a window
// update on a gRPC stream (WindowFrame).
const WindowSID = "_window"

// WindowFrame is the control frame that grants n bytes of sid's credit on
// a gRPC stream.
func WindowFrame(sid string, n int) *pb.TCPData {
	return &pb.TCPData{SessionId: WindowSID, Data: link.AppendWindow(nil, sid, n)}
}

// ParseWindowFrame reads a WindowFrame's grant.
func ParseWindowFrame(f *pb.TCPData) (string, int, error) { return link.ParseWindow(f.GetData()) }

// ParseCreditHeader parses a CreditHeader value as a window.
func ParseCreditHeader(s string) (int, error) { return ParseWindow(s) }

// Dial binds nc (a TLS connection to the relay's gRPC port) as a data
// connection, authenticated with the primary stream's bind token. cfg sets
// the window and the liveness.
func Dial(ctx context.Context, nc net.Conn, token string, cfg link.Config) (*Conn, error) {
	cfg.Auth = bindToken(token)
	c, err := link.Client(ctx, nc, cfg)
	if err != nil {
		return nil, err
	}
	return Wrap(c), nil
}

// bindToken is the agent's credential on a data connection.
type bindToken string

func (t bindToken) Hello(context.Context, tls.ConnectionState) (byte, []byte, error) {
	return link.MethodToken, []byte(t), nil
}

func (bindToken) Verify(context.Context, tls.ConnectionState, byte, []byte) (link.Identity, error) {
	return link.Identity{}, errors.New("dataplane: a bind token is the agent's, not verified here")
}

// Wrap returns the TCPData adapter of a bound link connection.
func Wrap(c *link.Conn) *Conn { return &Conn{c} }

// The link's constants, as this package named them.
const (
	Magic       = link.Magic
	MaxChunk    = link.MaxChunk
	MaxSessions = link.MaxSessions
)

var (
	ErrRefused = link.ErrRefused
	ErrCredit  = link.ErrCredit
	ErrFull    = link.ErrFull
)

// emptyMsg is an all-default pb.TCPData as a non-empty body: field 1
// (session_id), length 0.
var emptyMsg = []byte{0x0a, 0x00}

// Conn sends and receives TCPData frames on a bound link connection. One
// goroutine Receives; Send, Flush and the credit calls (link.Conn's) are
// safe from any.
type Conn struct{ *link.Conn }

// isData reports whether f is a session id and data, nothing else.
func isData(f *pb.TCPData) bool {
	return len(f.GetData()) > 0 && len(f.GetSessionId()) <= link.MaxSID && f.GetAgentId() == "" && f.GetTargetAddr() == "" &&
		!f.GetOpen() && !f.GetClose() && !f.GetE2Ee() && len(f.ProtoReflect().GetUnknown()) == 0
}

// isClose reports whether f is a session id and the close flag (and the
// half flag of a half close), nothing else.
func isClose(f *pb.TCPData) bool {
	return f.GetClose() && len(f.GetData()) == 0 && f.GetAgentId() == "" && f.GetTargetAddr() == "" &&
		!f.GetOpen() && !f.GetE2Ee() && len(f.ProtoReflect().GetUnknown()) == 0
}

// marshal encodes f as a message frame's body.
func marshal(f *pb.TCPData) ([]byte, error) {
	b, err := proto.Marshal(f)
	if err == nil && len(b) == 0 {
		// An all-default TCPData encodes to nothing, and a frame's body
		// is never empty. An empty session_id field encodes the same
		// message.
		b = emptyMsg
	}
	return b, err
}

// Send buffers f; Flush, or a full buffer, writes it. The caller does not
// modify f afterwards and acquired credit for its data (Acquire).
func (c *Conn) Send(f *pb.TCPData) error {
	if isData(f) {
		return c.SendData(f.GetSessionId(), f.GetData())
	}
	if len(f.GetSessionId()) <= link.MaxSID && !strings.HasPrefix(f.GetSessionId(), "_") {
		switch {
		case f.GetOpen() && !f.GetClose() && len(f.GetData()) == 0:
			h := proto.CloneOf(f)
			h.SessionId, h.Open = "", false
			b, err := proto.Marshal(h)
			if err != nil {
				return err
			}
			return c.SendOpen(f.GetSessionId(), b)
		case isClose(f):
			return c.SendClose(f.GetSessionId(), f.GetHalf())
		}
	}
	b, err := marshal(f)
	if err != nil {
		return err
	}
	return c.SendMsg(b)
}

// Recv returns the next frame; it applies window frames itself. A peer
// that breaks the credit rules gets ErrCredit; the caller closes the
// connection on any error.
func (c *Conn) Recv() (*pb.TCPData, error) {
	f, err := c.Conn.Recv()
	for err == nil && f.Accept { // FeatureChain: a session's frames answer it in band
		f, err = c.Conn.Recv()
	}
	if err != nil {
		return nil, err
	}
	switch {
	case f.Open:
		m := &pb.TCPData{}
		if err := proto.Unmarshal(f.Header, m); err != nil || m.GetSessionId() != "" || m.GetOpen() || len(m.GetData()) > 0 {
			return nil, link.ErrFrame
		}
		m.SessionId, m.Open = f.SID, true
		return m, nil
	case f.Close: // a half close (TCPData.half) or a whole one; a reset reads as a close
		return &pb.TCPData{SessionId: f.SID, Close: true, Half: f.Half}, nil
	case f.Msg == nil:
		return &pb.TCPData{SessionId: f.SID, Data: f.Data}, nil
	}
	m := &pb.TCPData{}
	if err := proto.Unmarshal(f.Msg, m); err != nil {
		return nil, link.ErrFrame
	}
	if n := len(m.GetData()); n > 0 {
		if err := c.Credit().Received(m.GetSessionId(), n); err != nil {
			return nil, err
		}
	}
	return m, nil
}

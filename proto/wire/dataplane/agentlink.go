// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/protobuf/proto"
)

// The agent link: an agent's sessions on a github.com/nfltr/link/peerlink
// Link to its relay, which opens them on the connections the agent dialled
// (reverse direction): link over TLS/TCP on the relay's gRPC port, or QUIC
// (peerlink/quiclink) on its UDP port. A connection authenticates with the
// bind token of the agent's ConnectTCP primary stream and lives no longer
// than that stream. A session's header is its open TCPData without session
// id and open flag (OpenHeader), as on a data connection.
//
// The agent asks for it with AgentLinkHeader in its ConnectTCP request
// metadata (its transport: AgentLinkTCP, AgentLinkQUIC or "auto"); a relay
// that takes it answers with the same header in its response, one value
// per transport it takes, and AgentLinkQUICHeader its UDP port when it
// takes QUIC. A relay that answers neither leaves the agent on data
// connections and gRPC streams.
const (
	AgentLinkHeader     = "x-nfltr-agent-link"
	AgentLinkQUICHeader = "x-nfltr-agent-link-quic"
	AgentLinkTCP        = "tcp"
	AgentLinkQUIC       = "quic"
)

// The agent link is dialled lazily: an agent the relay offered it dials
// only when the relay asks, with a control frame on the primary stream
// (session id AgentLinkSID, data AgentLinkDial) when it needs a session for
// an agent with no agent-link connection; the relay retires a link that
// carried no session for a while and tells the agent (data AgentLinkClose),
// which then closes it. Frames whose session id starts with "_" belong to
// no session: an agent that does not know these ignores them.
const (
	AgentLinkSID   = "_link"
	AgentLinkDial  = "dial"
	AgentLinkClose = "close"
)

// AgentLinkMagic opens an agent-link connection on the relay's gRPC port,
// after TLS and before the link hello: a data connection starts with the
// link's Magic, gRPC with "PRI ".
const AgentLinkMagic = "NFAL"

// AgentLinkALPN is the agent link's application protocol on QUIC, for a
// connection whose sessions answer opens in band (a relay or agent before
// FeatureChain).
const AgentLinkALPN = "nfltr-agent-link/1"

// AgentLinkALPNs is what both ends of an agent-link QUIC connection offer,
// in order of preference: peerlink/quiclink's ALPNChain ("peerlink-chain",
// quiclink v0.4.0: sessions answer opens link's own way), then
// AgentLinkALPN. Each side with only AgentLinkALPN still connects.
func AgentLinkALPNs() []string { return []string{"peerlink-chain", AgentLinkALPN} }

// OpenHeader is a session's header for open: its fields without session id
// and open flag.
func OpenHeader(open *pb.TCPData) ([]byte, error) {
	h := proto.CloneOf(open)
	h.SessionId, h.Open = "", false
	return proto.Marshal(h)
}

// ParseOpenHeader reads a session's header (OpenHeader).
func ParseOpenHeader(header []byte) (*pb.TCPData, error) {
	f := &pb.TCPData{}
	return f, proto.Unmarshal(header, f)
}

// BindToken is an agent's credential on a link connection to its relay:
// the bind token of its primary stream (link.MethodToken).
func BindToken(token string) link.Authenticator { return bindToken(token) }

// Status bytes of the relay's answer to a LinkHello.
const (
	linkHelloBound   = 0
	linkHelloRefused = 1
)

// ErrLinkHelloRefused is the relay's refusal of a LinkHello.
var ErrLinkHelloRefused = errors.New("dataplane: the relay refused the agent link's token")

// WriteLinkHello sends the bind token on a QUIC agent-link connection's
// first stream (QUIC carries no link hello): AgentLinkMagic, the token's
// length (2 bytes, big endian), the token; then reads the relay's status.
func WriteLinkHello(rw io.ReadWriter, token string) error {
	if len(token) > link.MaxAuth {
		return fmt.Errorf("dataplane: token of %d bytes", len(token))
	}
	b := binary.BigEndian.AppendUint16([]byte(AgentLinkMagic), uint16(len(token))) // #nosec G115 -- len <= MaxAuth
	if _, err := rw.Write(append(b, token...)); err != nil {
		return err
	}
	var st [1]byte
	if _, err := io.ReadFull(rw, st[:]); err != nil {
		return err
	}
	if st[0] != linkHelloBound {
		return ErrLinkHelloRefused
	}
	return nil
}

// ReadLinkHello reads a LinkHello's token (WriteLinkHello).
func ReadLinkHello(r io.Reader) (string, error) {
	var b [len(AgentLinkMagic) + 2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	if string(b[:len(AgentLinkMagic)]) != AgentLinkMagic {
		return "", link.ErrFrame
	}
	n := int(binary.BigEndian.Uint16(b[len(AgentLinkMagic):]))
	if n > link.MaxAuth {
		return "", link.ErrFrame
	}
	token := make([]byte, n)
	if _, err := io.ReadFull(r, token); err != nil {
		return "", err
	}
	return string(token), nil
}

// AnswerLinkHello writes the relay's status for a LinkHello.
func AnswerLinkHello(w io.Writer, bound bool) error {
	st := byte(linkHelloRefused)
	if bound {
		st = linkHelloBound
	}
	_, err := w.Write([]byte{st})
	return err
}

// AgentLinkOffer is what a relay's ConnectTCP response header offers.
type AgentLinkOffer struct {
	TCP, QUIC bool
	QUICPort  int
}

// ParseAgentLinkOffer reads the offer from the response header's values of
// AgentLinkHeader and AgentLinkQUICHeader.
func ParseAgentLinkOffer(link, quicPort []string) AgentLinkOffer {
	var o AgentLinkOffer
	for _, v := range link {
		for t := range strings.SplitSeq(v, ",") {
			switch strings.TrimSpace(t) {
			case AgentLinkTCP:
				o.TCP = true
			case AgentLinkQUIC:
				o.QUIC = true
			}
		}
	}
	if len(quicPort) > 0 {
		if p, err := strconv.ParseUint(strings.TrimSpace(quicPort[0]), 10, 16); err == nil && p > 0 {
			o.QUICPort = int(p)
		}
	}
	o.QUIC = o.QUIC && o.QUICPort > 0
	return o
}

// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"net"
	"strings"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc"
)

// RelayDialer opens further connections to the relay for a busy TCP
// tunnel (as the relay asks, x-nfltr-tcp-streams). With neither function the tunnel's further
// streams share its gRPC connection.
type RelayDialer struct {
	// GRPC opens a gRPC connection for auxiliary ConnectTCP streams.
	GRPC func() (*grpc.ClientConn, error)
	// Data opens a connection to the relay's gRPC port, its TLS
	// handshake done (grpcclient.DialConn): the agent link over TCP. Nil
	// leaves the agent link to QUIC, else auxiliary gRPC connections.
	Data func(context.Context) (net.Conn, error)
	// Liveness is the agent link's: both ends ping it and end it once the
	// relay is silent for its interval plus timeout. Zero is
	// link.LivenessDefault; the agent passes its Config.Liveness.
	Liveness link.Liveness
	// Transport is the agent link's (TransportTCP, TransportQUIC,
	// TransportAuto; "" is TransportTCP): asked of a relay that takes the
	// agent link, the agent's sessions ride it. Without Data (and QUIC)
	// the agent asks for none.
	Transport string
	// QUIC reaches the relay over QUIC for TransportQUIC and
	// TransportAuto; nil: TCP only.
	QUIC *QUICDialer
	// park keeps the agent link of a primary that ended for the agent's
	// next primary to resume (linkPark); nil: a link ends with its
	// primary.
	park *linkPark
}

// tcpDataWindow is the agent's window per session on its agent link and
// its gRPC streams with credit: what it queues for one session's target at most (relay tcpDataWindow).
// A session that may go direct keeps the same window on both of its
// paths (pathswitch.Config.Window, the direct QUIC stream's window), so
// one transfer is never bounded at 1 MiB per round trip
// (TestDirectPathWindowIsTheDataWindow, docs/performance.md).
const tcpDataWindow = 16 << 20

// tcpDataMaxSessions is how many sessions the relay may have open on the
// agent link: the relay places them, so as many as the
// wire carries.
const tcpDataMaxSessions = 1 << 20

// dataHelloTimeout bounds opening and binding the agent link.
const dataHelloTimeout = 10 * time.Second

// isSessionData reports whether f carries a session's data, which a
// stream with credit sends only on credit (control frames carry none).
func isSessionData(f *pb.TCPData) bool {
	return len(f.GetData()) > 0 && !strings.HasPrefix(f.GetSessionId(), "_")
}

// sendData queues a session's data in chunks the relay has credit for,
// waiting for it. It fails once the session or the
// connection ended.
func (t *tcpTunnel) sendData(f *pb.TCPData) error {
	for data := f.GetData(); len(data) > 0; {
		n := min(len(data), dataplane.MaxChunk)
		if !t.cr.Acquire(f.GetSessionId(), n) {
			return io.ErrClosedPipe
		}
		chunk := f
		if n < len(f.GetData()) {
			chunk = &pb.TCPData{SessionId: f.GetSessionId(), Data: data[:n]}
		}
		if err := t.enqueue(chunk); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

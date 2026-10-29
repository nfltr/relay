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
// tunnel (tcpStreamGrowth). With neither function the tunnel's further
// streams share its gRPC connection.
type RelayDialer struct {
	// GRPC opens a gRPC connection for auxiliary ConnectTCP streams.
	GRPC func() (*grpc.ClientConn, error)
	// Data opens a connection to the relay's gRPC port, its TLS
	// handshake done (grpcclient.DialConn): a data connection. Nil, or a
	// relay that does not offer them, leaves auxiliary gRPC connections.
	Data func(context.Context) (net.Conn, error)
	// Liveness is a version-2 data connection's: both ends ping it and
	// end it once the relay is silent for its interval plus timeout. Zero
	// is link.LivenessDefault; the agent passes its Config.Liveness.
	Liveness link.Liveness
	// Transport is the agent link's (TransportTCP, TransportQUIC,
	// TransportAuto; "" is TransportTCP): asked of a relay that takes the
	// agent link, the agent's sessions ride it instead of data
	// connections. Without Data (and QUIC) the agent asks for none.
	Transport string
	// QUIC reaches the relay over QUIC for TransportQUIC and
	// TransportAuto; nil: TCP only.
	QUIC *QUICDialer
	// park keeps the agent link of a primary that ended for the agent's
	// next primary to resume (linkPark); nil: a link ends with its
	// primary.
	park *linkPark
}

// tcpDataWindow is the agent's window per session on a data connection:
// what it queues for one session's target at most (relay tcpDataWindow).
const tcpDataWindow = 16 << 20

// tcpDataMaxSessions is how many sessions the relay may have open on one
// data connection (version 2): the relay places them, so as many as the
// wire carries.
const tcpDataMaxSessions = 1 << 20

// dataHelloTimeout bounds opening and binding a data connection.
const dataHelloTimeout = 10 * time.Second

// serveDataConn opens a data connection with dial.Data, binds it to the primary stream with token and serves it
// until it ends or ctx (the primary's) is done. It fails when the
// connection or the binding fails.
// st, when set, counts it (Stats.DataConn).
func serveDataConn(ctx context.Context, dial RelayDialer, token string, serve func(tcpStream) error, st *stats) error {
	dctx, cancel := context.WithTimeout(ctx, dataHelloTimeout)
	defer cancel()
	nc, err := dial.Data(dctx)
	if err != nil {
		return err
	}
	defer nc.Close() //nolint:errcheck
	dc, err := dataplane.Dial(dctx, nc, token, link.Config{
		Window: tcpDataWindow, MaxSessions: tcpDataMaxSessions, Liveness: dial.Liveness,
		Observer: st.observer(ObserveDataConn, nil, nil, false),
	})
	if err != nil {
		return err
	}
	defer dc.Close() //nolint:errcheck
	tc := st.dataConnC()
	tc.conn(1)
	defer tc.conn(-1)
	defer tc.track(dc.Stats)()
	stop := context.AfterFunc(ctx, func() { _ = dc.Close() })
	defer stop()
	_ = serve(dc)
	return nil
}

// isSessionData reports whether f carries a session's data, which a data
// connection sends only on credit (control frames carry none).
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

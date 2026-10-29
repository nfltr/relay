// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"net/http"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/chunking"
)

// UpgradeVisitor returns the visitor's bytes of a relayed protocol upgrade
// (WebSocket; chunking.IsUpgrade): the streamed body of r (registered as q),
// which the relay sends after the backend's 101. Nil when r is not such an upgrade (or
// the relay predates them). The backend request of an upgrade carries no
// body (http.NoBody): its bytes follow the switch, through SpliceUpgrade.
func UpgradeVisitor(q *chunking.Request, r *pb.HTTPRequest) io.Reader {
	if q == nil || q.Body == nil || !chunking.IsUpgrade(r.GetHeaders()) {
		return nil
	}
	return q.Body
}

// SpliceUpgrade joins the backend connection of a 101 answer (resp.Body, an
// io.ReadWriteCloser) to the visitor: visitor's bytes are copied into it, and
// it is closed when that copy ends or ctx does, which ends the backend's
// bytes the agent streams back (chunking.ReadUpgradeChunksWithContext). A
// nil visitor (a relay that sends none) only closes it with ctx.
func SpliceUpgrade(ctx context.Context, resp *http.Response, visitor io.Reader) {
	conn, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		return
	}
	copied := make(chan struct{})
	if visitor != nil {
		go func() {
			defer close(copied)
			_, _ = io.Copy(conn, visitor)
		}()
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-copied:
		}
		_ = conn.Close()
	}()
}

// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc/metadata"
)

// labelStream runs processStream on a fake ConnectHTTP stream whose accept
// carries header; stop ends it and waits.
func labelStream(t *testing.T, a *agent, header metadata.MD) (sent chan *pb.HTTPProxyResponse, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &blockingStream{ctx: ctx, requests: make(chan *pb.HTTPProxyRequest), sent: make(chan *pb.HTTPProxyResponse, 8), header: header}
	routes, err := parseRoutes([]Route{{Backend: "http://127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{RequestTimeout: 5, Concurrency: 1, HeartbeatRecvThreshold: time.Hour}
	done := make(chan error, 1)
	go func() {
		done <- processStream(ctx, stream, "a", routes, cfg, newBackendClient(cfg), slog.New(slog.DiscardHandler), nil, nil, nil, &a.labelUpdates)
	}()
	synctest.Wait() // attached, blocked in Recv
	return stream.sent, func() { cancel(); <-done }
}

func gotLabels(t *testing.T, sent chan *pb.HTTPProxyResponse) map[string]string {
	t.Helper()
	select {
	case f := <-sent:
		if f.GetLabels() == nil || f.GetResponse() != nil {
			t.Fatalf("sent %v, want a label update frame", f)
		}
		return f.GetLabels().GetLabels()
	default:
		t.Fatal("no label update sent")
		return nil
	}
}

// SetLabels sends the whole set on the current stream, resends it first
// on the next one, sends nothing to a relay that applies none, and refuses
// labels past the bounds.
func TestSetLabels(t *testing.T) {
	synctest.Test(t, testSetLabels)
}

func testSetLabels(t *testing.T) {
	a := &agent{}
	applies := metadata.Pairs(agentwire.LabelUpdatesKey, "1")
	down := map[string]string{"nfltr.health.pg": "down"}

	if err := a.SetLabels(down); err != nil { // no stream yet: kept
		t.Fatalf("SetLabels before connect = %v", err)
	}
	sent, stop := labelStream(t, a, applies)
	if got := gotLabels(t, sent); !maps.Equal(got, down) {
		t.Fatalf("first frame = %v, want %v", got, down)
	}
	if err := a.SetLabels(nil); err != nil {
		t.Fatalf("SetLabels(nil) = %v", err)
	}
	if got := gotLabels(t, sent); len(got) != 0 {
		t.Fatalf("cleared set sent as %v", got)
	}
	if err := a.SetLabels(down); err != nil {
		t.Fatal(err)
	}
	gotLabels(t, sent)
	stop()

	// A reconnect: the set again, first.
	sent, stop = labelStream(t, a, applies)
	if got := gotLabels(t, sent); !maps.Equal(got, down) {
		t.Fatalf("after reconnect = %v, want %v", got, down)
	}
	stop()
	if err := a.SetLabels(down); err != nil { // between connections: kept
		t.Fatalf("SetLabels between connections = %v", err)
	}

	// A relay without label updates gets none.
	sent, stop = labelStream(t, a, nil)
	if err := a.SetLabels(down); !errors.Is(err, ErrLabelUpdatesUnsupported) {
		t.Fatalf("SetLabels on a relay without updates = %v, want ErrLabelUpdatesUnsupported", err)
	}
	select {
	case f := <-sent:
		t.Fatalf("sent %v to a relay without updates", f)
	default:
	}
	stop()

	if err := a.SetLabels(map[string]string{"k": strings.Repeat("x", agentwire.MaxLabelBytes+1)}); err == nil {
		t.Fatal("SetLabels past the bounds = nil")
	}
}

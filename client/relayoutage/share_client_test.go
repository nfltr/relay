// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relayoutage

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/client/relaytrust"
)

// The share client trusts a private relay's pinned certificate, as the
// gRPC connection does, and does not keep its connection: a share is issued
// once per agent, and an idle keep-alive connection held relay memory (2
// goroutines and about 16 KiB) for every agent until the relay's idle
// timeout.
func TestShareClientTrustsThePinAndClosesItsConnection(t *testing.T) {
	var closed atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"url":"https://swift-bay.example.com/"}`))
	}))
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			closed.Add(1)
		}
	}
	srv.StartTLS() // a certificate no system root signs: only the pin makes it trusted
	defer srv.Close()

	t.Setenv(relaytrust.PinEnv, relaytrust.Fingerprint(srv.Certificate().Raw))
	ShareClient = sync.OnceValue(newShareClient) // built after the pin is installed, as in main
	t.Cleanup(func() { ShareClient = sync.OnceValue(newShareClient) })

	resp, err := ShareClient().Post(srv.URL+"/api/v1/share", "", nil)
	if err != nil {
		t.Fatalf("share request to the pinned relay: %v", err)
	}
	_ = resp.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if closed.Load() != 1 {
		t.Fatal("the share request's connection stayed open after the share was issued")
	}
}

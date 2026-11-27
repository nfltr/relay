// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecert

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/relaytrust"
	"github.com/nfltr/relay/client/relaytrust/relaytrusttest"
)

// TestClientHonoursThePinFromItsFirstCall: every shape of Client its callers
// build reaches a relay with a pinned self-signed certificate on the first
// call (an enrolment, a service's or nfltr-send's and nfltr-pipe's renewal):
// Pin, else relaytrust.PinEnv, whether HTTP is nil or a client that sets
// only a timeout; without a pin the certificate is refused (lane PINENROL:
// HTTP with a timeout used Go's default transport, which trusts no pin).
func TestClientHonoursThePinFromItsFirstCall(t *testing.T) {
	set := relaytrusttest.New(t)
	var self relaytrusttest.Kind
	for _, k := range set.Kinds {
		if k.Name == "self-signed" {
			self = k
		}
	}
	srv := relaytrusttest.Serve(t, self.Cert)
	base := "https://" + relaytrusttest.Addr(srv)
	pin := relaytrust.Fingerprint(self.Cert.Leaf.Raw)
	timeout := func() *http.Client { return &http.Client{Timeout: time.Minute} }
	for _, tc := range []struct {
		name    string
		c       Client
		env     string
		reaches bool
	}{
		{"Pin", Client{BaseURL: base, Pin: pin}, "", true},
		{"Pin, HTTP with a timeout", Client{BaseURL: base, Pin: pin, HTTP: timeout()}, "", true},
		{"PinEnv", Client{BaseURL: base}, pin, true},
		{"PinEnv, HTTP with a timeout", Client{BaseURL: base, HTTP: timeout()}, pin, true},
		{"Pin over another PinEnv", Client{BaseURL: base, Pin: pin, HTTP: timeout()}, strings.Repeat("ab", 32), true},
		{"no pin", Client{BaseURL: base}, "", false},
		{"no pin, HTTP with a timeout", Client{BaseURL: base, HTTP: timeout()}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(relaytrust.PinEnv, tc.env)
			key, err := NewKey()
			if err != nil {
				t.Fatal(err)
			}
			_, err = tc.c.Enrol(context.Background(), "code", "", "", key)
			// The server answers 200 with no body: an error about the
			// answer means the request reached it.
			reached := err != nil && strings.Contains(err.Error(), "machinecert: the answer")
			if reached != tc.reaches {
				t.Fatalf("reached the relay %v, want %v: %v", reached, tc.reaches, err)
			}
		})
	}
	relaytrust.CloseIdleConnections()
}

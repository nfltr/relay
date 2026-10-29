// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/wire/agentwire"
)

// A client (tcp-connect) turns a TLS connection to the relay's HTTP port
// into a data connection with an HTTP/1.1 upgrade: the API key in the
// request is its credential, and a link hello (version 2, no credential:
// the request carried it) follows the 101. Clients before nfltr v2.0.0
// asked for "nfdp/1" (link version 1 without a hello), which a relay of
// this package answers with 426 (OldUpgradeToken).
const (
	UpgradePath     = "/connect/"
	UpgradeToken    = "nfdp/2"
	OldUpgradeToken = "nfdp/1"
)

// NoUpgradeError is a server's answer to the upgrade other than 101: it
// does not take data connections there (it predates them, a proxy in
// between refuses upgrades) or refused the request.
type NoUpgradeError struct{ Status int }

func (e *NoUpgradeError) Error() string {
	return fmt.Sprintf("dataplane: relay answered the upgrade with %d", e.Status)
}

// IsUpgrade reports whether r asks to upgrade to a data connection.
func IsUpgrade(r *http.Request) bool {
	return r.ProtoMajor == 1 && r.Method == http.MethodGet && strings.EqualFold(r.Header.Get("Upgrade"), UpgradeToken)
}

// IsOldUpgrade reports whether r asks for the data connection of clients
// before nfltr v2.0.0, which this package no longer speaks.
func IsOldUpgrade(r *http.Request) bool {
	return r.ProtoMajor == 1 && r.Method == http.MethodGet && strings.EqualFold(r.Header.Get("Upgrade"), OldUpgradeToken)
}

// ParseWindow parses a window announced in a header.
func ParseWindow(s string) (int, error) {
	w, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("dataplane: window %q: %w", s, err)
	}
	return link.CheckWindow(uint32(w))
}

// E2EEPolicyHeader is the header of a relay's 101 to a data connection
// upgrade that states its operator's end-to-end encryption policy for TCP
// sessions: "require", "allow" or "forbid".
const E2EEPolicyHeader = "X-Nfltr-E2EE-Policy"

// Upgrade asks the relay at host (nc: TLS done, or plain TCP to a
// plaintext relay) to make nc a data connection, with apiKey as the
// credential and window as this side's window, and binds the link; ctx
// bounds the whole exchange. It returns the relay's 101 header too
// (AnswerHeader, E2EEPolicyHeader).
func Upgrade(ctx context.Context, nc net.Conn, host, apiKey string, window int) (*Mux, http.Header, error) {
	req := "GET " + UpgradePath + " HTTP/1.1\r\nHost: " + host +
		"\r\nConnection: Upgrade\r\nUpgrade: " + UpgradeToken +
		"\r\nX-API-Key: " + apiKey +
		"\r\n" + agentwire.GenerationKey + ": " + strconv.Itoa(agentwire.Generation) + "\r\n\r\n"
	if _, err := nc.Write([]byte(req)); err != nil {
		return nil, nil, err
	}
	br := bufio.NewReaderSize(nc, 512)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), UpgradeToken) {
		return nil, nil, &NoUpgradeError{Status: resp.StatusCode}
	}
	if br.Buffered() > 0 { // the server waits for the hello
		return nil, nil, link.ErrFrame
	}
	c, err := link.Client(ctx, nc, link.Config{Window: window, Auth: link.NoAuth})
	if err != nil {
		return nil, nil, err
	}
	return NewMux(Wrap(c)), resp.Header, nil
}

// Accept answers an upgrade request on its hijacked connection nc with 101
// and binds the link (the request carried the credential), announcing
// window; ctx bounds the hello. The 101 says the relay answers sessions
// that ask (AnswerHeader: read by clients that answer in band, nfltr
// v2.1.6; a client with link.FeatureChain reads the answers link's own
// way) and states e2eePolicy (E2EEPolicyHeader).
func Accept(ctx context.Context, nc net.Conn, window int, e2eePolicy string) (*Mux, error) {
	resp := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + UpgradeToken +
		"\r\n" + AnswerHeader + ": 1\r\n" + E2EEPolicyHeader + ": " + e2eePolicy + "\r\n\r\n"
	if _, err := nc.Write([]byte(resp)); err != nil {
		return nil, err
	}
	c, _, err := link.Server(ctx, nc, link.Config{Window: window, Auth: link.NoAuth})
	if err != nil {
		return nil, err
	}
	return NewMux(Wrap(c)), nil
}

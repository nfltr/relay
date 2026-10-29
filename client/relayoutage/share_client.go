// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relayoutage

import (
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/nfltr/relay/client/relaytrust"
)

const (
	shareClientTimeout = 20 * time.Second
	shareHeaderTimeout = 8 * time.Second
)

// ShareClient is the HTTP client of a tunnel's share request (POST
// /api/v1/share; nfltr http/share/serve, pkg/agent, tunnel-agent). It resends
// a request the relay throttles (Throttled). It trusts a private relay's
// pinned certificate (relaytrust.PinEnv) as the gRPC connection does: it is
// built on first use, after the CLI's main installed the pin. It keeps no
// connection: a share is issued once per agent connection, and a kept one
// held relay memory for every agent (2 goroutines and about 16 KiB) until the
// relay's idle timeout.
var ShareClient = sync.OnceValue(newShareClient)

func newShareClient() *http.Client {
	return &http.Client{
		Timeout: shareClientTimeout,
		Transport: Throttled(&http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       relaytrust.WithPin(nil, os.Getenv(relaytrust.PinEnv)),
			ForceAttemptHTTP2:     true,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: shareHeaderTimeout,
		}),
	}
}

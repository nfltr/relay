// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

// backendIdleConnsPerHost is how many idle connections to its local backend
// an agent keeps. It is above the number of requests a tunnel serves at
// once (an HTTP tunnel's concurrency, an E2EE tunnel's open client
// connections), so a request reuses a connection instead of dialing one and
// leaving one in TIME_WAIT. Idle ones close after the idle timeout.
const backendIdleConnsPerHost = 1024

// NewBackendTransport is the transport an agent forwards requests to its
// local backend with: HTTP tunnels (both modes) and E2EE sessions share one
// configuration. tlsCfg is for an HTTPS backend (nil: the default);
// responseHeaderTimeout bounds the wait for the backend to start answering
// (0: none).
func NewBackendTransport(tlsCfg *tls.Config, responseHeaderTimeout time.Duration) *http.Transport {
	return &http.Transport{
		TLSClientConfig:       tlsCfg,
		ResponseHeaderTimeout: responseHeaderTimeout,
		MaxIdleConns:          backendIdleConnsPerHost,
		MaxIdleConnsPerHost:   backendIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		// ReadBufferSize stays at the 4 KiB default: a body read with a
		// buffer at least that large (the chunk reader, the E2EE proxy's
		// 32 KiB copy) bypasses it, so a bigger one only pinned memory on
		// every idle connection (256 KiB each before).
		// Video and audio are already compressed; disabling transport-level
		// decompression avoids redundant CPU work and preserves the
		// Content-Encoding header for the downstream client.
		DisableCompression: true,
	}
}

// e2eeBackendTransport carries every E2EE session's requests to its backend,
// so a session's requests, and the next session's, reuse its connections.
var e2eeBackendTransport = NewBackendTransport(nil, 0)

// proxyBufferPool lends the E2EE reverse proxy its 32 KiB copy buffers;
// without one it allocates a new buffer for every response it copies.
type proxyBufferPool struct{ p sync.Pool }

func (b *proxyBufferPool) Get() []byte {
	if buf, ok := b.p.Get().(*[]byte); ok {
		return *buf
	}
	return make([]byte, 32*1024)
}

// Put returns buf to the pool. allow:wrapper (implements httputil.BufferPool)
func (b *proxyBufferPool) Put(buf []byte) { b.p.Put(&buf) }

// e2eeProxyBuffers is shared by every E2EE session's reverse proxy.
var e2eeProxyBuffers = &proxyBufferPool{}

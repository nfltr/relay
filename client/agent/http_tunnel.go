// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nfltr/relay/proto/wire/agentservices"
)

// The HTTP tunnel's per-request forwarding, shared by both ways a request
// reaches the agent: as ConnectHTTP messages (processStream, client
// generation 2) and on a link session served with net/http
// (TunnelHandler, generation 3; dataplane.HTTPSessionTarget).

// newBackendClient is the client that forwards tunnel requests to the
// agent's backends.
func newBackendClient(cfg Config) *http.Client {
	var tlsCfg *tls.Config
	if cfg.SkipVerify {
		tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, dev only
	}
	return &http.Client{
		// No overall Timeout — large streaming responses (video, downloads)
		// would be killed before the body finishes. Per-request deadlines
		// are enforced via the server's request context instead.
		Transport: NewBackendTransport(tlsCfg, time.Duration(cfg.RequestTimeout)*time.Second),
		// Do not follow redirects — let the caller decide.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// skipRequestHeaders are the relay request headers not forwarded to the
// backend.
var skipRequestHeaders = map[string]bool{
	"Accept-Encoding":           true,
	"Host":                      true,
	"Content-Length":            true,
	"X-Browse-Prefix":           true,
	agentservices.RequestHeader: true, // the relay's routing, not the backend's
}

// AgentIDHeader carries the agent's identity to its backends.
const AgentIDHeader = "X-Tunnel-Agent-Id"

// Request is what the relay asked of a tunnel request, carried in the
// context of the request the agent sends its backend (RequestOf).
type Request struct {
	// URI is the path and query the visitor asked for, the route prefix
	// included, without the leading "/".
	URI string
	// TransactionID is the relay's ID of a request on the ConnectHTTP
	// stream; "" on a link session.
	TransactionID string
}

type requestKey struct{}

// RequestOf returns the tunnel request a backend request's context
// carries (WithBackendTransport).
func RequestOf(ctx context.Context) (Request, bool) {
	r, ok := ctx.Value(requestKey{}).(Request)
	return r, ok
}

func withRequest(ctx context.Context, r Request) context.Context {
	return context.WithValue(ctx, requestKey{}, r)
}

// errNoRoute answers a request that resolves to no backend (a services
// agent's request that names no service).
const errNoRoute = "not found"

// backendRequest builds the request to fwd's backend; contentLength -1 is
// unknown.
func backendRequest(ctx context.Context, method string, headers http.Header, body io.Reader, contentLength int64, fwd resolvedForward, agentID string) (*http.Request, error) {
	targetURL, err := TargetURL(fwd.targetBase, fwd.strippedPath)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if contentLength >= 0 {
		httpReq.ContentLength = contentLength
	}
	for name, values := range headers {
		if skipRequestHeaders[name] {
			continue
		}
		for _, v := range values {
			httpReq.Header.Add(name, v)
		}
	}
	httpReq.Header.Set(AgentIDHeader, agentID)
	// Origin, Referer and the relay's X-Forwarded-For/Host/Proto (set at its
	// edge, never the visitor's) go on as they came, as a reverse proxy sends
	// them; Host is the public host the visitor asked for unless the agent
	// rewrites it to the backend's (Config.RewriteHost).
	if h := headers.Get("X-Forwarded-Host"); h != "" && !fwd.rewriteHost {
		httpReq.Host = h
	}
	return httpReq, nil
}

// responseHeaders is the backend's response header as the visitor gets it:
// no CSP (the relay's pages frame it), no Content-Length (the body may be
// rewritten), Location relative to the tunnel.
func responseHeaders(h http.Header, fwd resolvedForward) http.Header {
	target := strings.TrimRight(fwd.targetBase, "/")
	out := make(http.Header, len(h))
	for name, values := range h {
		switch strings.ToLower(name) {
		case "content-security-policy", "content-security-policy-report-only", "content-length":
			continue
		case "location":
			rewritten := make([]string, len(values))
			for i, v := range values {
				rewritten[i] = strings.Replace(v, target+"/", "/", 1)
				rewritten[i] = strings.Replace(rewritten[i], target, "/", 1)
				if fwd.prefix != "" && len(rewritten[i]) > 0 && rewritten[i][0] == '/' {
					rewritten[i] = "/" + fwd.prefix + rewritten[i]
				}
			}
			out[name] = rewritten
		default:
			out[name] = values
		}
	}
	return out
}

// maxRewriteBody caps the text body responseBody buffers to rewrite.
const maxRewriteBody = 50 << 20

// responseBody is the backend's response body as the visitor gets it: a
// text body of at most maxRewriteBody with its absolute links to the
// backend made relative to the tunnel (rewritten), anything else, a longer
// text body included, whole as it comes. streaming is set for bodies that
// must never be buffered (SSE, NDJSON, media, chunked).
func responseBody(resp *http.Response, fwd resolvedForward, browsePrefix string) (body io.Reader, streaming, rewritten bool, err error) {
	streaming = isStreamingResponse(resp)
	if streaming || resp.StatusCode == http.StatusSwitchingProtocols || !isTextContent(resp.Header.Get("Content-Type")) {
		return resp.Body, streaming, false, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRewriteBody+1))
	if err != nil {
		return nil, false, false, fmt.Errorf("read response body: %w", err)
	}
	if len(b) > maxRewriteBody { // too long to buffer: every byte, unrewritten
		return io.MultiReader(bytes.NewReader(b), resp.Body), false, false, nil
	}
	return bytes.NewReader(rewriteLocalURLs(b, fwd.targetBase, fwd.prefix, browsePrefix)), false, true, nil
}

// TunnelHandler serves the agent's HTTP tunnel on link sessions (sessions
// to dataplane.HTTPSessionTarget): each request goes to the backend its
// route names, and its response comes back rewritten as processStream
// rewrites it.
type TunnelHandler struct {
	agentID atomic.Pointer[string]
	routes  routeTable
	client  *http.Client
	logger  *slog.Logger
	// rewriteHost is Config.RewriteHost.
	rewriteHost bool
}

// NewTunnelHandler returns the handler for cfg's routes (cfg as for New).
func NewTunnelHandler(cfg Config) (*TunnelHandler, error) {
	applyDefaults(&cfg)
	routes, err := parseRoutes(cfg.Routes)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return newTunnelHandler(cfg.AgentID, routes, newBackendClient(cfg), cfg.RewriteHost, logger), nil
}

func newTunnelHandler(agentID string, routes routeTable, client *http.Client, rewriteHost bool, logger *slog.Logger) *TunnelHandler {
	h := &TunnelHandler{routes: routes, client: client, rewriteHost: rewriteHost, logger: logger}
	h.setAgentID(agentID)
	return h
}

// setAgentID is the identity the relay resolved.
func (h *TunnelHandler) setAgentID(id string) { h.agentID.Store(&id) }

func (h *TunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uri := strings.TrimPrefix(r.URL.RequestURI(), "/")
	fwd := h.routes.forward(uri, r.Header.Values(agentservices.RequestHeader))
	fwd.rewriteHost = h.rewriteHost
	if fwd.targetBase == "" {
		http.Error(w, errNoRoute, http.StatusNotFound)
		return
	}
	ctx := withRequest(r.Context(), Request{URI: uri})
	req, err := backendRequest(ctx, r.Method, r.Header, r.Body, r.ContentLength, fwd, *h.agentID.Load())
	var resp *http.Response
	if err == nil {
		resp, err = h.client.Do(req) // #nosec G704 -- the backend is the agent's own route table, not the request
	}
	if err != nil {
		h.logger.Error("forward error", "url", r.URL.RequestURI(), "error", err)
		http.Error(w, fmt.Sprintf("tunnel forward error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusSwitchingProtocols {
		serveUpgrade(w, resp, responseHeaders(resp.Header, fwd))
		return
	}
	body, streaming, rewritten, err := responseBody(resp, fwd, r.Header.Get("X-Browse-Prefix"))
	if err != nil {
		http.Error(w, fmt.Sprintf("tunnel forward error: %v", err), http.StatusBadGateway)
		return
	}
	for name, values := range responseHeaders(resp.Header, fwd) {
		w.Header()[name] = values
	}
	if !rewritten && resp.ContentLength >= 0 { // its length stands
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(resp.StatusCode)
	if !streaming {
		if _, err := io.Copy(w, body); err != nil {
			panic(http.ErrAbortHandler) // cut: a truncated body must not end cleanly
		}
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.Flush() // the head now: the body may come much later (SSE, long poll)
	buf := make([]byte, 32<<10)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil { // nosemgrep: no-direct-write-to-responsewriter -- proxied backend bytes, as a reverse proxy writes them
				return
			}
			_ = rc.Flush()
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			// The backend's body failed (it died, or the agent is closing):
			// cut the session, so the relay sees an incomplete body rather
			// than the terminating chunk of a whole one.
			panic(http.ErrAbortHandler)
		}
	}
}

// serveUpgrade answers a request the backend switched protocols on
// (WebSocket): the 101 with header, then the bytes both ways between the
// session (taken over from the server) and the backend's connection,
// until either side ends.
func serveUpgrade(w http.ResponseWriter, resp *http.Response, header http.Header) {
	backend, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		http.Error(w, "tunnel forward error: the backend switched protocols without a connection", http.StatusBadGateway)
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("tunnel forward error: %v", err), http.StatusBadGateway)
		return
	}
	defer conn.Close() //nolint:errcheck
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_ = header.Write(brw)
	_, _ = brw.WriteString("\r\n")
	if brw.Flush() != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(backend, brw) // what the client sent after its request, then the rest
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, backend)
		done <- struct{}{}
	}()
	<-done // either side ended: the deferred closes end the other
}

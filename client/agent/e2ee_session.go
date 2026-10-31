// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"crypto/hmac"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nfltr/relay/client/internal/bytequeue"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"golang.org/x/net/http/httpguts"
)

// serveE2EE handles a single E2EE TLS passthrough session.
//
// The gRPC byte stream carries raw TLS records from the client via the server's
// SNI router. The session is a net.Conn (sessionConn) over its queue and the
// stream, wrapped in a TLS server that terminates the client's TLS. Then:
//
//   - stream path (the default): an HTTP/1 session to an http:// backend gets
//     its own TCP connection to the backend. Requests are read only to set
//     Host to the backend's, as the reverse proxy does; responses go back as
//     bytes (serveE2EEStream). A session of one request takes a pooled
//     connection instead;
//   - HTTP path: a feature that must read every request (RequireBasicAuth,
//     RequireSharePolicy),
//     an https:// backend, or an h2 client gets net/http and a reverse proxy.
//
// The session ends from either side: the agent closing the TLS conn sends the
// relay a close, and a close from the relay ends the conn's reads.
func (t *tcpTunnel) serveE2EE(sessionID string, q *bytequeue.Queue, e2eeCfg *e2eeTLSConfig, defaultBackend string, client netip.Addr, wrap func(http.Handler) http.Handler) {
	tlsSide := newSessionConn(t, sessionID, q)

	backend, err := url.Parse(defaultBackend)
	if err != nil || defaultBackend == "" {
		t.logger.Warn("e2ee: no valid backend for reverse proxy",
			"session", sessionID, "backend", defaultBackend)
		_ = tlsSide.Close()
		return
	}
	serveE2EEConn(tls.Server(tlsSide, e2eeCfg.tlsConfig), backend, e2eeCfg.rewriteHost, client, wrap, t.logger)
}

// e2eeHeaderTimeout bounds an E2EE session's TLS handshake and the headers of
// each request read here, and e2eeIdleTimeout the HTTP path's wait between
// requests: the relay's own HTTPS front uses the same bounds
// (http.server.read_header_timeout, http.server.idle_timeout), and E2EE
// moves that front to the agent.
var (
	e2eeHeaderTimeout = 10 * time.Second
	e2eeIdleTimeout   = 120 * time.Second
)

// serveE2EEConn serves one E2EE session's TLS conn on the stream path or the
// HTTP path (serveE2EE). client is the visitor's address the relay named
// (zero: none), its requests' X-Forwarded-For.
func serveE2EEConn(conn *tls.Conn, backend *url.URL, rewriteHost bool, client netip.Addr, wrap func(http.Handler) http.Handler, logger *slog.Logger) {
	host := "" // the client's
	if rewriteHost {
		host = backend.Host
	}
	// The HTTP path's server sets its own deadlines from here on.
	_ = conn.SetReadDeadline(time.Now().Add(e2eeHeaderTimeout))
	if wrap == nil && backend.Scheme == "http" {
		if err := conn.Handshake(); err != nil {
			_ = conn.Close()
			return
		}
		if p := conn.ConnectionState().NegotiatedProtocol; p == "" || p == "http/1.1" {
			serveE2EEStream(conn, backendAddr(backend), host, client, logger)
			return
		}
	}
	serveE2EEHTTP(conn, backend, host, client, wrap, logger)
}

// backendAddr is the backend URL's host:port.
func backendAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

// serveE2EEHTTP serves one TLS conn with net/http and a reverse proxy to
// backend, inside wrap when set.
func serveE2EEHTTP(conn *tls.Conn, backend *url.URL, host string, client netip.Addr, wrap func(http.Handler) http.Handler, logger *slog.Logger) {
	var handler http.Handler = &httputil.ReverseProxy{
		Transport:  e2eeBackendTransport,
		BufferPool: e2eeProxyBuffers,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = backend.Scheme
			pr.Out.URL.Host = backend.Host
			pr.Out.Host = backendHost(pr.In, host)
			setEdgeForwarded(pr.Out.Header, pr.In.Host, client)
		},
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
	if wrap != nil {
		handler = wrap(handler)
	}

	serveHTTPConn(conn, handler)
}

// serveHTTPConn serves one connection with h until either side closes it.
// The listener closes once the server is done with the conn, so Serve
// returns instead of waiting on a second Accept.
func serveHTTPConn(conn net.Conn, h http.Handler) {
	ln := &singleConnListener{conn: conn, done: make(chan struct{})}
	server := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: e2eeHeaderTimeout,
		IdleTimeout:       e2eeIdleTimeout,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				_ = ln.Close()
			}
		},
	}
	_ = server.Serve(ln)
}

// badGateway answers a request whose backend cannot be reached.
const badGateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nBad Gateway\n"

// serveE2EEStream carries one E2EE session's HTTP/1 requests to the backend
// at addr. Requests are parsed only to set Host (host, or the client's when
// "") and the forwarded headers (setEdgeForwarded); their line, other headers
// and body framing go on as the client sent them, over a connection of the session's own. Responses are
// copied back as bytes. The client's end of input half-closes the backend
// connection, whose remaining responses still reach the client; a session
// ends when the backend closes. An upgrade (WebSocket) or CONNECT turns the
// rest of the session into a byte copy.
//
// A session whose first request is also its last (Connection: close, no
// body) goes over the shared pool of backend connections instead
// (serveLastRequest): a connection dialed for one request costs a dial,
// an accept and a TIME_WAIT.
func serveE2EEStream(client net.Conn, addr, host string, visitor netip.Addr, logger *slog.Logger) {
	defer func() { _ = client.Close() }()
	br := bufio.NewReader(client)
	_ = client.SetReadDeadline(time.Now().Add(e2eeHeaderTimeout))
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	// The session has a request: from here the backend's own timeouts end
	// an idle session (closing the backend closes the client).
	_ = client.SetReadDeadline(time.Time{})
	if req.Close && req.ProtoAtLeast(1, 1) && req.Body == http.NoBody {
		serveLastRequest(client, req, addr, host, visitor, logger)
		return
	}
	backend, err := targetDialer().Dial("tcp", addr) // bounded as every target dial
	if err != nil {
		logger.Debug("e2ee: dial backend failed", "backend", addr, "error", err)
		_, _ = io.WriteString(client, badGateway)
		return
	}
	defer func() { _ = backend.Close() }()

	responses := make(chan struct{})
	go func() {
		defer close(responses)
		_ = copyPooled(client, backend)
		// The backend is done: so is the session. Closing the client also
		// ends a request read still waiting on it.
		_ = client.Close()
	}()

	bw := bufio.NewWriter(backend)
	for ; err == nil; req, err = http.ReadRequest(br) {
		if writeStreamRequest(bw, req, host, visitor) != nil {
			break
		}
		if req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" {
			_, _ = io.Copy(backend, br)
			break
		}
	} // err: the client's end of input, or a request the backend could not take either
	if tc, ok := backend.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	<-responses
}

// serveLastRequest answers req, a session's only request, through the
// pooled backend transport. The client's Connection: close ends its own
// connection, not the pooled one; the client gets Connection: close back.
func serveLastRequest(client net.Conn, req *http.Request, addr, host string, visitor netip.Addr, logger *slog.Logger) {
	req.RequestURI = ""
	setEdgeForwarded(req.Header, req.Host, visitor)
	req.URL.Scheme, req.URL.Host, req.Host = "http", addr, backendHost(req, host)
	req.Close = false
	req.Header.Del("Connection")
	resp, err := e2eeBackendTransport.RoundTrip(req)
	if err != nil {
		logger.Debug("e2ee: backend request failed", "backend", addr, "error", err)
		_, _ = io.WriteString(client, badGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	resp.Header.Del("Connection")
	resp.Header.Del("Keep-Alive")
	resp.Close = true
	bw := bufio.NewWriter(client)
	if isStreamingResponse(resp) { // the head now, then each read as it comes (SSE, long poll)
		resp.Body = flushBeforeRead{ReadCloser: resp.Body, w: bw}
	}
	if resp.Write(bw) == nil {
		_ = bw.Flush()
	}
}

// flushBeforeRead flushes w before each read of a body that is written to
// w: what was written reaches the client before the read waits.
type flushBeforeRead struct {
	io.ReadCloser
	w *bufio.Writer
}

func (f flushBeforeRead) Read(p []byte) (int, error) {
	if err := f.w.Flush(); err != nil {
		return 0, err
	}
	return f.ReadCloser.Read(p)
}

// copyPooled copies src to dst through a pooled 32 KiB buffer. The wrappers
// hide net.TCPConn's WriteTo and ReadFrom (and bufio.Writer's ReadFrom),
// which would allocate a buffer of their own for every copy.
func copyPooled(dst io.Writer, src io.Reader) error {
	buf := e2eeProxyBuffers.Get()
	defer e2eeProxyBuffers.Put(buf)
	_, err := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, buf)
	return err
}

// writeStreamRequest writes req to w as the client sent it, except Host
// (host, or the client's when "") and the forwarded headers. The head
// is flushed before the body is read, so a client waiting for
// "100 Continue" gets it from the backend.
func writeStreamRequest(w *bufio.Writer, req *http.Request, host string, visitor netip.Addr) error {
	chunked := len(req.TransferEncoding) > 0 // ReadRequest accepts only "chunked"
	setEdgeForwarded(req.Header, req.Host, visitor)
	_, _ = w.WriteString(req.Method + " " + req.RequestURI + " " + req.Proto + "\r\nHost: " + backendHost(req, host) + "\r\n")
	if chunked {
		_, _ = w.WriteString("Transfer-Encoding: chunked\r\n")
	}
	if len(req.Trailer) > 0 {
		names := make([]string, 0, len(req.Trailer))
		for k := range req.Trailer {
			names = append(names, k)
		}
		_, _ = w.WriteString("Trailer: " + strings.Join(names, ", ") + "\r\n")
	}
	// ReadRequest moved Host to req.Host and Transfer-Encoding/Trailer to
	// their fields; Content-Length stays in the header unless chunked.
	_ = req.Header.Write(w)
	_, _ = w.WriteString("\r\n")
	if err := w.Flush(); err != nil || req.Body == http.NoBody {
		return err
	}
	if !chunked {
		if err := copyPooled(w, req.Body); err != nil {
			return err
		}
		return w.Flush()
	}
	cw := httputil.NewChunkedWriter(w)
	if err := copyPooled(cw, req.Body); err != nil {
		return err
	}
	_ = cw.Close() // the last chunk; trailers and the final CRLF follow
	_ = req.Trailer.Write(w)
	_, _ = w.WriteString("\r\n")
	return w.Flush()
}

// RequireBasicAuth makes every request through the E2EE sessions carry HTTP
// Basic Auth credentials creds ("user:password"); others get 401. The agent is
// the only hop that reads E2EE requests, so a credential check the tunnel
// promises (--basic-auth) must happen here. Call it before RunTCPTunnel.
func (s *E2EESetup) RequireBasicAuth(creds string) {
	s.cfg.addWrap(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || !hmac.Equal([]byte(user+":"+pass), []byte(creds)) {
				w.Header().Set("WWW-Authenticate", `Basic realm="nfltr"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
}

// singleConnListener is a net.Listener that serves exactly one connection;
// later Accept calls wait for Close and then return io.EOF.
type singleConnListener struct {
	conn      net.Conn
	done      chan struct{}
	once      sync.Once
	closeOnce sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var accepted bool
	l.once.Do(func() { accepted = true })
	if accepted {
		return l.conn, nil
	}
	<-l.done
	return nil, io.EOF
}

// Close is safe to call concurrently: http.Server.Serve closes its
// listener on return while the ConnState hook may close it too.
func (l *singleConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// backendHost is the Host a backend gets for the client's req: host when the
// agent rewrites it (E2EESetup.RewriteHost), else the host the client asked for.
func backendHost(req *http.Request, host string) string {
	if host != "" {
		return host
	}
	return req.Host
}

// edgeProxyHeaders are what proxies tell a backend about the client and the
// hop-by-hop headers. The agent is the E2EE session's first HTTP hop, so a
// client's own forwarded headers are claims it could make up (another host,
// another address) and go.
var edgeProxyHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip",
	"Keep-Alive", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate"}

// setEdgeForwarded sets h's forwarded headers as the HTTPS front that ends
// an E2EE session's TLS: the host the client asked for, https, and the
// client's address (X-Forwarded-For and X-Real-IP) as the relay accepted
// its connection (client; none when the relay named none, e.g. nfltr-relay
// before v0.33.0). It also drops the hop-by-hop headers a reverse proxy drops (RFC 9110 7.6.1), but
// Connection and Upgrade: the stream path keeps the client's connection
// semantics (close, a protocol upgrade) on its own backend connection.
func setEdgeForwarded(h http.Header, host string, client netip.Addr) {
	for _, f := range h["Connection"] {
		for sf := range strings.SplitSeq(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" && !strings.EqualFold(sf, "upgrade") {
				h.Del(sf)
			}
		}
	}
	if !httpguts.HeaderValuesContainsToken(h["Te"], "trailers") {
		h.Del("Te")
	}
	for _, k := range edgeProxyHeaders {
		h.Del(k)
	}
	h.Set("X-Forwarded-Host", host)
	h.Set("X-Forwarded-Proto", "https")
	if client.IsValid() {
		h.Set("X-Forwarded-For", client.String())
		h.Set("X-Real-Ip", client.String())
	}
	// A relay's key is for the relay, never a service: removed here as the
	// relay removes it on the paths it reads.
	if vals := h["Authorization"]; slices.ContainsFunc(vals, agentwire.RelayKeyAuthorization) {
		if vals = slices.DeleteFunc(slices.Clone(vals), agentwire.RelayKeyAuthorization); len(vals) > 0 {
			h["Authorization"] = vals
		} else {
			h.Del("Authorization")
		}
	}
}

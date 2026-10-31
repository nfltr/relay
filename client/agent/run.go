// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// processStream is the core receive/forward/respond loop. It reads [pb.HTTPProxyRequest] messages
// from the server, forwards each to the local backend, and streams the
// response back.
//
// Requests are dispatched to goroutines (up to cfg.Concurrency in parallel)
// so that slow or large responses never block subsequent requests.
//
// It returns when the stream errors, the context is cancelled, or the server
// closes the stream. The caller owns the stream lifecycle. mv, when not nil,
// is the stream's part in a move (move.go): errMoved once it moved.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"github.com/nfltr/relay/proto/wire/chunking"
	"google.golang.org/protobuf/proto"
)

var errNoServerActivity = errors.New("no messages received from server")

// errUnackedUpload refuses a chunked request body the relay sends without
// upload acks: only a relay older than upload flow control does.
var errUnackedUpload = errors.New("agent: the relay sent a chunked request body without upload acks (a relay before upload flow control): update the relay")

func processStream(
	ctx context.Context,
	stream pb.Dispatcher_ConnectHTTPClient,
	agentID string,
	routes routeTable,
	cfg Config,
	httpClient *http.Client,
	logger *slog.Logger,
	wgx WireGuardTunnel,
	mv *move,
	linkUp func() bool,
) (err error) {
	// Serialise all stream.Send calls — gRPC streams are not concurrent-safe.
	var sendMu sync.Mutex
	safeSend := func(msg *pb.HTTPProxyResponse) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(msg)
	}

	// WireGuard exit: send the tunnel's sealed packets to the relay, each
	// tagged with the client it is for.
	if wgx != nil {
		go wgx.Pump(ctx, safeSend)
	}

	// sem limits the number of concurrently running request handlers.
	sem := make(chan struct{}, cfg.Concurrency)
	var processed atomic.Int64
	var inflight atomic.Int64 // requests received and not yet answered
	var moved atomic.Bool     // the old stream of a move: closed by the agent
	if mv != nil {
		ended := make(chan struct{})
		defer close(ended)
		defer func() {
			if moved.Load() {
				err = errMoved
			}
		}()
		go func() {
			select {
			case <-mv.connected:
				if err := safeSend(&pb.HTTPProxyResponse{Move: pb.Move_MOVE_CONNECTED}); err != nil {
					logger.Warn("move: telling the relay the new connection is up", "error", err)
				}
			case <-ended:
			}
		}()
	}
	var reqWG sync.WaitGroup
	defer reqWG.Wait()
	header, _ := stream.Header() // sent with the relay's accept; nil on a stream that ended
	recvThreshold := heartbeatRecvThreshold(cfg, header)
	// A relay that takes this agent's liveness from its agent link wants no
	// answer to its heartbeats while the link is up.
	linkLiveness := linkUp != nil && len(header[agentwire.LinkLivenessKey]) > 0 && header[agentwire.LinkLivenessKey][0] == "1"
	// The relay's cancel/ack frames and streamed uploads; when the stream
	// ends, a request still receiving its body stops (before reqWG.Wait).
	flow := chunking.NewAgentFlow(chunking.RelayAcks(stream))
	defer flow.StreamEnded()

	recv := newActivityRecv(stream, recvThreshold)
	defer recv.stop()
	for {
		msg, err := recv.next(ctx)
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}

		if step := msg.GetMove(); step != pb.Move_MOVE_UNSPECIFIED && mv != nil && msg.GetRequest() == nil {
			switch step {
			case pb.Move_MOVE_RECONNECT:
				logger.Info("relay replica leaving: connecting again before leaving it")
				mv.askReconnect()
			case pb.Move_MOVE_DONE:
				if moved.CompareAndSwap(false, true) {
					go closeWhenAnswered(ctx, stream, &sendMu, &inflight)
				}
			}
			continue
		}
		if isHeartbeat(msg) {
			if linkLiveness && linkUp() {
				continue
			}
			if err := safeSend(&pb.HTTPProxyResponse{}); err != nil {
				return fmt.Errorf("heartbeat send: %w", err)
			}
			continue
		}

		// WireGuard: a client's sealed packet, or a PeerUpdate from the relay.
		if wgx != nil && msg.Request != nil && wgx.Handle(msg.Request) {
			continue
		}

		// Defensive: a frame with no HTTPRequest envelope (e.g. server sent
		// only routing/timestamps, or a partially-decoded message) would
		// otherwise SIGSEGV on the field accesses below. isHeartbeat is
		// supposed to filter these out; the guard here is belt-and-braces.
		if msg.Request == nil {
			continue
		}
		if flow.Handle(msg.Request) {
			continue // a relay frame, or the next chunk of a streamed upload
		}

		var service []string
		if vs := msg.Request.Headers[agentservices.RequestHeader]; vs != nil {
			service = vs.HeaderValues
		}
		fwd := routes.forward(msg.Request.Url, service)
		fwd.rewriteHost = cfg.RewriteHost

		// Registered on the receive loop, so a frame or chunk that follows
		// the request always finds it. A chunked body streams (req.Body):
		// the agent asks for upload acks on connect, and a relay that sends
		// a multi-chunk body without them predates upload flow control. Its
		// request is refused, its remaining chunks dropped (flow.Handle).
		req := flow.Begin(ctx, msg.Request, safeSend)
		var body io.Reader = req.Body
		if req.Body == nil {
			if h := msg.Request.Headers; chunking.IsChunked(h) && !chunking.IsLastChunk(h) {
				req.Done()
				logger.Warn(errUnackedUpload.Error(), "txn", msg.Request.TransactionId)
				if err := safeSend(errorResponse(msg, http.StatusBadGateway, errUnackedUpload.Error())); err != nil {
					return fmt.Errorf("send unacked-upload refusal: %w", err)
				}
				continue
			}
			body = bytes.NewReader(msg.Request.Payload)
		}
		visitor := UpgradeVisitor(req, msg.Request)
		if visitor != nil {
			body = http.NoBody // the visitor's bytes follow the backend's 101
		}

		// Dispatch to a goroutine. The semaphore caps the handlers running
		// at once; a request waits for a slot in its own goroutine, never
		// here: the frames that free a slot (a response's acks, a cancel)
		// arrive on this loop, so a loop that waited for a slot would wait
		// for good (the HTTP sibling of the stuck-client rule).
		// ponytail: requests waiting for a slot are bounded only by what the
		// relay sends (each a goroutine and its request); HTTP transactions
		// as link sessions with credit would bound them.
		reqWG.Add(1)
		inflight.Add(1)
		go func(msg *pb.HTTPProxyRequest, fwd resolvedForward, body io.Reader) {
			defer reqWG.Done()
			defer inflight.Add(-1)
			defer req.Done()
			select {
			case sem <- struct{}{}:
			case <-req.Ctx.Done(): // cancelled, or the stream ended, while waiting
				return
			}
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					logger.Error("panic in request handler",
						"txn", msg.Request.TransactionId, "panic", r,
						"stack", string(debug.Stack()))
					errResp := errorResponse(msg, 502, "internal agent error")
					if sendErr := safeSend(errResp); sendErr != nil {
						logger.Warn("send panic error response failed",
							"txn", msg.Request.TransactionId, "error", sendErr)
					}
				}
			}()

			if fwd.targetBase == "" {
				if err := safeSend(errorResponse(msg, http.StatusNotFound, errNoRoute)); err != nil {
					logger.Warn("send error response failed", "txn", msg.Request.TransactionId, "error", err)
				}
				return
			}
			reqCtx := withRequest(req.Ctx, Request{URI: msg.Request.Url, TransactionID: msg.Request.TransactionId})
			resp, fwdErr := forwardRequest(reqCtx, httpClient, msg, fwd, agentID, body)
			if fwdErr != nil {
				logger.Error("forward error", "txn", msg.Request.TransactionId, "error", fwdErr)
				errResp := errorResponse(msg, 502, fmt.Sprintf("tunnel forward error: %v", fwdErr))
				if err := safeSend(errResp); err != nil {
					logger.Warn("send error response failed", "txn", msg.Request.TransactionId, "error", err)
				}
				processed.Add(1)
				return
			}

			if resp.StatusCode == http.StatusSwitchingProtocols {
				SpliceUpgrade(req.Ctx, resp, visitor)
			}
			n, sendErr := sendResponse(req.Ctx, safeSend, resp, msg, fwd, req.Acks)
			resp.Body.Close() //nolint:errcheck
			if sendErr != nil {
				logger.Warn("send error", "txn", msg.Request.TransactionId, "error", sendErr)
			}

			count := processed.Add(1)
			logger.Debug("request handled",
				"n", count,
				"method", msg.Request.Method,
				"url", msg.Request.Url,
				"backend", fwd.targetBase,
				"status", resp.StatusCode,
				"bytes", n,
				"txn", msg.Request.TransactionId,
			)
		}(msg, fwd, body)
	}
}

// closeWhenAnswered closes the sending side of a stream the agent moved off
// once every request it received there is answered; the relay then ends
// the stream.
func closeWhenAnswered(ctx context.Context, stream pb.Dispatcher_ConnectHTTPClient, sendMu *sync.Mutex, inflight *atomic.Int64) {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for inflight.Load() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
	sendMu.Lock()
	defer sendMu.Unlock()
	_ = stream.CloseSend()
}

// heartbeatRecvThreshold is the stream's silence limit: the configured one,
// else the liveness's wait past the relay's stated heartbeat, else 45s (a
// relay that states none: older ones send a heartbeat every 15s, skipping
// one after data, so up to 30s pass between frames).
func heartbeatRecvThreshold(cfg Config, header map[string][]string) time.Duration {
	switch {
	case cfg.HeartbeatRecvThreshold < 0:
		return 0
	case cfg.HeartbeatRecvThreshold > 0:
		return cfg.HeartbeatRecvThreshold
	}
	if limit := cfg.Liveness.DeadAfter(agentwire.Heartbeat(header, agentwire.HeartbeatKey)); limit > 0 {
		return limit
	}
	return 45 * time.Second
}

// activityRecv receives the relay's frames, failing with
// errNoServerActivity when none comes within threshold of asking for the
// next: one reader goroutine and one timer for the stream's life, not one
// per frame (threshold <= 0: plain Recv, no deadline).
type activityRecv struct {
	stream    pb.Dispatcher_ConnectHTTPClient
	threshold time.Duration
	ch        chan recvResult
	done      chan struct{}
	timer     *time.Timer
}

type recvResult struct {
	msg *pb.HTTPProxyRequest
	err error
}

// newActivityRecv starts the reader; stop ends it once the stream ends.
func newActivityRecv(stream pb.Dispatcher_ConnectHTTPClient, threshold time.Duration) *activityRecv {
	r := &activityRecv{stream: stream, threshold: threshold}
	if threshold <= 0 {
		return r
	}
	r.ch = make(chan recvResult)
	r.done = make(chan struct{})
	r.timer = time.NewTimer(threshold)
	go func() {
		for {
			msg, err := stream.Recv()
			select {
			case r.ch <- recvResult{msg, err}:
			case <-r.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return r
}

// next is the next frame, an error ending the stream, errNoServerActivity
// after threshold without one, or ctx's error.
func (r *activityRecv) next(ctx context.Context) (*pb.HTTPProxyRequest, error) {
	if r.threshold <= 0 {
		return r.stream.Recv()
	}
	r.timer.Reset(r.threshold)
	select {
	case res := <-r.ch:
		return res.msg, res.err
	case <-r.timer.C:
		return nil, errNoServerActivity
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// stop releases the reader (blocked in Recv until the stream ends).
func (r *activityRecv) stop() {
	if r.done != nil {
		r.timer.Stop()
		close(r.done)
	}
}

// forwardRequest builds and executes the HTTP request to the local backend.
// The caller must close resp.Body.
func forwardRequest(
	ctx context.Context,
	client *http.Client,
	msg *pb.HTTPProxyRequest,
	fwd resolvedForward,
	agentID string,
	body io.Reader,
) (*http.Response, error) {
	req := msg.Request

	headers := make(http.Header, len(req.Headers))
	for name, values := range req.Headers {
		if name == chunking.HeaderIndex || name == chunking.HeaderLast || name == chunking.HeaderUploadAcks {
			continue
		}
		headers[name] = values.HeaderValues
	}
	contentLength := int64(-1)
	if _, streamed := body.(*chunking.Upload); streamed {
		contentLength = chunking.StreamedContentLength(req.Headers)
	}
	httpReq, err := backendRequest(ctx, req.Method, headers, body, contentLength, fwd, agentID)
	if err != nil {
		return nil, err
	}
	return client.Do(httpReq)
}

// sendResponse streams the local HTTP response back to the server in chunks.
// safeSend must be concurrency-safe (callers use a mutex-protected wrapper).
// acks, when not nil, are the relay's acks: chunk i waits for the ack of
// chunk i-chunking.ResponseWindow. Returns total bytes sent and the first
// error encountered.
func sendResponse(
	ctx context.Context,
	safeSend func(*pb.HTTPProxyResponse) error,
	resp *http.Response,
	msg *pb.HTTPProxyRequest,
	fwd resolvedForward,
	acks <-chan struct{},
) (int, error) {
	browsePrefix := ""
	if vs, ok := msg.Request.Headers["X-Browse-Prefix"]; ok && len(vs.HeaderValues) > 0 {
		browsePrefix = vs.HeaderValues[0]
	}
	bodyReader, streaming, rewritten, err := responseBody(resp, fwd, browsePrefix)
	if err != nil {
		return 0, err
	}
	upgraded := resp.StatusCode == http.StatusSwitchingProtocols
	// The chunkers end the response with a last chunk on any read error;
	// a body that failed (the backend died, or the agent is closing) must
	// not look whole, so its end is never sent as the last chunk. (An
	// upgraded connection's end is its last chunk, however it ended.)
	failed := &readFailure{r: bodyReader}
	if !upgraded {
		bodyReader = failed
	}
	respHeaders := make(map[string]*pb.HeaderValueList)
	for name, values := range responseHeaders(resp.Header, fwd) {
		respHeaders[name] = &pb.HeaderValueList{HeaderValues: values}
	}
	if !rewritten && resp.ContentLength >= 0 { // its length stands (a HEAD's included)
		respHeaders["Content-Length"] = &pb.HeaderValueList{HeaderValues: []string{strconv.FormatInt(resp.ContentLength, 10)}}
	}

	now := time.Now()
	txnID := msg.Request.TransactionId
	ts := &pb.Timestamps{
		RequestAtHttpServer: msg.Timestamps.GetRequestAtHttpServer(),
		RequestAtGrpcServer: msg.Timestamps.GetRequestAtGrpcServer(),
		RequestAtAgent:      now.UnixMilli(),
		ResponseAtAgent:     now.UnixMilli(),
	}

	firstEnv := &pb.HTTPProxyResponse{
		Timestamps: ts,
		Response: &pb.HTTPResponse{
			TransactionId: txnID,
			StatusCode:    int32(resp.StatusCode),
			Headers:       respHeaders,
			Deadline:      msg.Request.Deadline,
		},
	}
	restEnv := &pb.HTTPProxyResponse{
		Timestamps: ts,
		Response: &pb.HTTPResponse{
			TransactionId: txnID,
			Headers:       make(map[string]*pb.HeaderValueList),
		},
	}
	chunking.SetChunkHeaders(restEnv.Response.Headers, 999, true)

	firstBudget := chunking.PayloadBudget(firstEnv)
	restBudget := chunking.PayloadBudget(restEnv)
	var chunkCh <-chan chunking.Chunk
	switch {
	case upgraded, streaming: // the head at once (a 101, or a body that may come much later: SSE, long poll), then the bytes as they come
		chunkCh = chunking.ReadUpgradeChunksWithContext(ctx, bodyReader)
	default:
		chunkCh = chunking.ReadChunksWithContext(ctx, bodyReader, firstBudget, restBudget)
	}

	total := 0
	i := 0
	ended := false // the last chunk was sent
	for chunk := range chunkCh {
		cut := chunk.Last && failed.err != nil
		if cut {
			chunk.Last = false
		}
		ended = chunk.Last
		var out *pb.HTTPProxyResponse
		switch {
		case i == 0 && chunk.Last:
			out = &pb.HTTPProxyResponse{
				Timestamps: ts,
				Response: &pb.HTTPResponse{
					TransactionId: txnID,
					StatusCode:    int32(resp.StatusCode),
					Headers:       respHeaders,
					Deadline:      msg.Request.Deadline,
					Payload:       chunk.Payload,
				},
			}
		case i == 0:
			hdrs := chunking.CopyHeaders(respHeaders)
			chunking.SetChunkHeaders(hdrs, 0, false)
			out = &pb.HTTPProxyResponse{
				Timestamps: ts,
				Response: &pb.HTTPResponse{
					TransactionId: txnID,
					StatusCode:    int32(resp.StatusCode),
					Headers:       hdrs,
					Deadline:      msg.Request.Deadline,
					Payload:       chunk.Payload,
				},
			}
		default:
			hdrs := make(map[string]*pb.HeaderValueList)
			chunking.SetChunkHeaders(hdrs, i, chunk.Last)
			out = &pb.HTTPProxyResponse{
				Timestamps: ts,
				Response: &pb.HTTPResponse{
					TransactionId: txnID,
					Headers:       hdrs,
					Payload:       chunk.Payload,
				},
			}
		}
		if err := chunking.AwaitAck(ctx, acks, i); err != nil {
			return total, err
		}
		if err := safeSend(out); err != nil {
			return total, fmt.Errorf("send chunk %d: %w", i, err)
		}
		total += len(chunk.Payload)
		i++
		if cut {
			return total, fmt.Errorf("read response body: %w", failed.err)
		}
	}
	if failed.err != nil {
		return total, fmt.Errorf("read response body: %w", failed.err)
	}
	// The chunkers stop on ctx without reading the body to its end: a body
	// cut that way is not whole either (TestSendResponseNeverEndsAFailedBody).
	if err := ctx.Err(); err != nil && !ended && !upgraded {
		return total, fmt.Errorf("read response body: %w", err)
	}

	// Empty body (e.g. redirect responses with Content-Length: 0) —
	// ReadChunks produces zero chunks, but we must still send the status
	// code and headers back to the server so the waiting proxy handler
	// can complete the HTTP response.
	if i == 0 {
		out := &pb.HTTPProxyResponse{
			Timestamps: ts,
			Response: &pb.HTTPResponse{
				TransactionId: txnID,
				StatusCode:    int32(resp.StatusCode),
				Headers:       respHeaders,
				Deadline:      msg.Request.Deadline,
			},
		}
		if err := safeSend(out); err != nil {
			return 0, fmt.Errorf("send empty response: %w", err)
		}
	}

	return total, nil
}

// isHeartbeat returns true when the message carries no meaningful payload
// (zero-size proto or missing transaction ID) — these are server keepalives.
func isHeartbeat(msg *pb.HTTPProxyRequest) bool {
	return proto.Size(msg) == 0 || msg.Request == nil || len(msg.Request.TransactionId) == 0
}

// errorResponse builds a 502 proxy-error response to send back to the server.
func errorResponse(msg *pb.HTTPProxyRequest, statusCode int32, body string) *pb.HTTPProxyResponse {
	now := time.Now()
	return &pb.HTTPProxyResponse{
		Timestamps: &pb.Timestamps{
			RequestAtHttpServer: msg.Timestamps.GetRequestAtHttpServer(),
			RequestAtGrpcServer: msg.Timestamps.GetRequestAtGrpcServer(),
			RequestAtAgent:      now.UnixMilli(),
			ResponseAtAgent:     now.UnixMilli(),
		},
		Response: &pb.HTTPResponse{
			TransactionId: msg.Request.TransactionId,
			StatusCode:    statusCode,
			Payload:       []byte(body),
			Headers:       map[string]*pb.HeaderValueList{"Content-Type": {HeaderValues: []string{"text/plain"}}},
			Deadline:      msg.Request.Deadline,
		},
	}
}

// isTextContent returns true for content types where URL rewriting is appropriate.
func isTextContent(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "text/css") ||
		strings.Contains(ct, "application/javascript") ||
		strings.Contains(ct, "text/javascript") ||
		strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "text/xml") ||
		strings.Contains(ct, "application/xml")
}

// isStreamingResponse returns true for responses that must be streamed
// incrementally without buffering (SSE, NDJSON, chunked event streams,
// and media streams such as video/audio served by Jellyfin, Plex, etc.).
func isStreamingResponse(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") ||
		strings.Contains(ct, "application/x-ndjson") ||
		strings.Contains(ct, "application/stream+json") ||
		strings.HasPrefix(ct, "video/") ||
		strings.HasPrefix(ct, "audio/") {
		return true
	}
	for _, te := range resp.TransferEncoding {
		if strings.EqualFold(te, "chunked") {
			return true
		}
	}
	return false
}

// rewriteLocalURLs makes a text body's references to the local backend
// load through the tunnel: absolute URLs to the backend (and a <base> tag
// naming it) become paths under the tunnel's base path (the browse prefix
// and the route's prefix), a <meta> Content-Security-Policy (which names
// the backend's origin) is dropped, and, under a prefix, root-relative
// links in HTML attributes and CSS url() get the base path.
func rewriteLocalURLs(body []byte, targetBase, servicePrefix, browsePrefix string) []byte {
	target := strings.TrimRight(targetBase, "/")
	basePath := "/"
	switch {
	case browsePrefix != "" && servicePrefix != "":
		basePath = browsePrefix + "/" + servicePrefix + "/"
	case browsePrefix != "":
		basePath = browsePrefix + "/"
	case servicePrefix != "":
		basePath = "/" + servicePrefix + "/"
	}
	re := rewriteRegexps()
	baseTag := regexp.MustCompile(`(?i)<base\s+href="` + regexp.QuoteMeta(target) + `[^"]*">`)
	result := baseTag.ReplaceAll(body, []byte(`<base href="`+basePath+`">`))
	result = re.cspMeta.ReplaceAll(result, nil)
	result = bytes.ReplaceAll(result, []byte(target+"/"), []byte(basePath))
	result = bytes.ReplaceAll(result, []byte(target), nil)
	if basePath != "/" {
		// RE2 has no lookahead: prefix every root-relative reference, then
		// undo the stutter on those the absolute pass already prefixed.
		doublePrefix := []byte(basePath + basePath[1:])
		result = re.attr.ReplaceAll(result, []byte("${1}"+basePath))
		result = bytes.ReplaceAll(result, doublePrefix, []byte(basePath))
		result = re.cssURL.ReplaceAll(result, []byte("${1}"+basePath))
		result = bytes.ReplaceAll(result, doublePrefix, []byte(basePath))
	}
	return result
}

var rewriteRegexps = sync.OnceValue(func() struct{ cspMeta, attr, cssURL *regexp.Regexp } {
	return struct{ cspMeta, attr, cssURL *regexp.Regexp }{
		cspMeta: regexp.MustCompile(`(?i)<meta\s+http-equiv="Content-Security-Policy"[^>]*>`),
		attr:    regexp.MustCompile(`((?:href|src|action)\s*=\s*["'])/`),
		cssURL:  regexp.MustCompile(`(url\(\s*['"]?)/`),
	}
})

// readFailure records r's first error other than io.EOF.
type readFailure struct {
	r   io.Reader
	err error
}

func (f *readFailure) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err != nil && err != io.EOF && f.err == nil {
		f.err = err
	}
	return n, err
}

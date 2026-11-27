// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package a2ahttp carries one HTTP request and its response as a single
// agent-to-agent call through the relay: an agent that serves an
// http.Handler over its relay connection (Serve), and a client
// http.RoundTripper that reaches it (Transport). It is transport only: no
// route, no vocabulary, no policy. The relay uses the same framing for the
// dashboard's session-authenticated calls to a user's own agents.
package a2ahttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

// Version is the framing version; a request carries it under the key that
// identifies it (IsRequest).
const Version = 1

// MaxBody bounds a request or response body (one A2A message stays under the
// relay's 8 MiB gRPC message limit after base64 and JSON).
const MaxBody = 4 << 20

// SourceHeader is set by Serve on the served request to the relay-
// authenticated id of the calling agent; a caller's own value is dropped.
const SourceHeader = "X-A2a-Source"

// Request is one HTTP request.
type Request struct {
	Version  int               `json:"a2a_http"`
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	RawQuery string            `json:"query,omitempty"`
	Header   map[string]string `json:"header,omitempty"`
	Body     []byte            `json:"body,omitempty"`
}

// Response is one HTTP response.
type Response struct {
	Status int               `json:"status"`
	Header map[string]string `json:"header,omitempty"`
	Body   []byte            `json:"body,omitempty"`
}

var requestPrefix = []byte(`{"a2a_http":`)

// IsRequest reports whether an A2A payload is an a2ahttp request (encoded by
// this package: the version key comes first). allow:wrapper
func IsRequest(data []byte) bool { return bytes.HasPrefix(data, requestPrefix) }

// ErrTooLarge is a body over MaxBody.
var ErrTooLarge = errors.New("a2ahttp: body exceeds 4 MiB")

// EncodeRequest frames r (its body is read and closed).
func EncodeRequest(r *http.Request) ([]byte, error) {
	req := Request{Version: Version, Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	for _, k := range []string{"Content-Type", "Accept", "Range"} {
		if v := r.Header.Get(k); v != "" {
			if req.Header == nil {
				req.Header = map[string]string{}
			}
			req.Header[k] = v
		}
	}
	if r.Body != nil {
		defer r.Body.Close() //nolint:errcheck
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		if err != nil {
			return nil, err
		}
		if len(body) > MaxBody {
			return nil, ErrTooLarge
		}
		req.Body = body
	}
	return json.Marshal(req)
}

// Serve runs h for one framed request from the agent source and returns the
// framed response. A malformed request answers 400; a response over MaxBody
// answers 502 (never a truncated body).
func Serve(ctx context.Context, h http.Handler, source string, data []byte) []byte {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil || req.Version != Version || !strings.HasPrefix(req.Path, "/") {
		return encodeResponse(Response{Status: http.StatusBadRequest, Body: []byte("a2ahttp: malformed request")})
	}
	if len(req.Body) > MaxBody {
		return encodeResponse(Response{Status: http.StatusRequestEntityTooLarge, Body: []byte(ErrTooLarge.Error())})
	}
	target := req.Path
	if req.RawQuery != "" {
		target += "?" + req.RawQuery
	}
	hr, err := http.NewRequestWithContext(ctx, req.Method, target, bytes.NewReader(req.Body))
	if err != nil {
		return encodeResponse(Response{Status: http.StatusBadRequest, Body: []byte("a2ahttp: " + err.Error())})
	}
	for k, v := range req.Header {
		hr.Header.Set(k, v)
	}
	hr.Header.Set(SourceHeader, source)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, hr)
	if rec.Body.Len() > MaxBody {
		return encodeResponse(Response{Status: http.StatusBadGateway, Body: []byte("a2ahttp: response exceeds 4 MiB")})
	}
	resp := Response{Status: rec.Code, Body: rec.Body.Bytes()}
	for k := range rec.Header() {
		if k == "Content-Length" {
			continue
		}
		if resp.Header == nil {
			resp.Header = map[string]string{}
		}
		resp.Header[k] = rec.Header().Get(k)
	}
	return encodeResponse(resp)
}

func encodeResponse(r Response) []byte {
	out, _ := json.Marshal(r)
	return out
}

// DecodeResponse parses a framed response into an *http.Response for req.
func DecodeResponse(data []byte, req *http.Request) (*http.Response, error) {
	var r Response
	if err := json.Unmarshal(data, &r); err != nil || r.Status == 0 {
		return nil, fmt.Errorf("a2ahttp: malformed response from agent")
	}
	h := http.Header{}
	for k, v := range r.Header {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: r.Status, Status: fmt.Sprintf("%d %s", r.Status, http.StatusText(r.Status)),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: h, Body: io.NopCloser(bytes.NewReader(r.Body)), ContentLength: int64(len(r.Body)), Request: req,
	}, nil
}

// Call sends one framed request to an agent and returns its framed reply
// (rpcclient.Agent.Invoke over the caller's relay connection).
type Call func(ctx context.Context, agentID string, request []byte) ([]byte, error)

// Transport is an http.RoundTripper that sends every request to Agent; the
// request URL's scheme and host are ignored.
type Transport struct {
	Call  Call
	Agent string
}

// RoundTrip implements http.RoundTripper.
func (t Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	data, err := EncodeRequest(r)
	if err != nil {
		return nil, err
	}
	reply, err := t.Call(r.Context(), t.Agent, data)
	if err != nil {
		return nil, err
	}
	return DecodeResponse(reply, r)
}

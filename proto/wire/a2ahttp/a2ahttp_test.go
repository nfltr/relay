// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package a2ahttp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRoundTripThroughServe(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" "+r.Header.Get(SourceHeader)+" "+string(body))
	})
	var gotAgent string
	call := func(ctx context.Context, agent string, req []byte) ([]byte, error) {
		gotAgent = agent
		if !IsRequest(req) {
			t.Fatalf("framed request not recognised: %s", req)
		}
		return Serve(ctx, h, "caller-1", req), nil
	}
	c := &http.Client{Transport: Transport{Call: call, Agent: "hub-a"}}
	req, _ := http.NewRequest(http.MethodPost, "a2a://ignored/api/v1/x?y=1", strings.NewReader(`{"k":1}`))
	req.Header.Set(SourceHeader, "forged")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if gotAgent != "hub-a" || resp.StatusCode != http.StatusAccepted || resp.Header.Get("Content-Type") != "application/json" ||
		string(body) != `POST /api/v1/x?y=1 caller-1 {"k":1}` {
		t.Fatalf("agent %q, %d %q %q", gotAgent, resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
}

func TestServeRejectsMalformedAndOversize(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, MaxBody+1)) })
	for name, data := range map[string]string{
		"not json":      `{"a2a_http":`,
		"wrong version": `{"a2a_http":2,"method":"GET","path":"/"}`,
		"relative path": `{"a2a_http":1,"method":"GET","path":"x"}`,
	} {
		resp, err := DecodeResponse(Serve(context.Background(), ok, "s", []byte(data)), nil)
		if err != nil || resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: %v %v", name, resp, err)
		}
	}
	resp, _ := DecodeResponse(Serve(context.Background(), ok, "s", []byte(`{"a2a_http":1,"method":"GET","path":"/"}`)), nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("oversize response: %d, want 502", resp.StatusCode)
	}
	big, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", MaxBody+1)))
	if _, err := EncodeRequest(big); err != ErrTooLarge {
		t.Fatalf("oversize request: %v", err)
	}
}

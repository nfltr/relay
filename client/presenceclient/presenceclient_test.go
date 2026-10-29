// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package presenceclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func TestWaitAndTypedErrors(t *testing.T) {
	calls := 0
	get := func(_ context.Context, path string) ([]byte, int, error) {
		calls++
		u, _ := url.Parse(path)
		switch u.Query().Get("cursor") {
		case "":
			return []byte(`{"cursor":"e.0"}`), http.StatusOK, nil
		case "e.0":
			return []byte(`{"cursor":"e.0"}`), http.StatusOK, nil // idle long-poll
		}
		return nil, 0, errors.New("unexpected")
	}
	if c, err := Wait(t.Context(), get, ""); err != nil || c != "e.0" {
		t.Fatalf("baseline = %q, %v", c, err)
	}
	changed := func(_ context.Context, path string) ([]byte, int, error) {
		return []byte(`{"cursor":"e.2","events":[{"revision":"2","agentId":"a","down":{}}]}`), http.StatusOK, nil
	}
	if c, err := Wait(t.Context(), changed, "e.0"); err != nil || c != "e.2" {
		t.Fatalf("changed = %q, %v", c, err)
	}
	reset := func(context.Context, string) ([]byte, int, error) {
		return []byte(`{"cursor":"f.9","reset":true}`), http.StatusOK, nil
	}
	if c, err := Wait(t.Context(), reset, "e.0"); err != nil || c != "f.9" {
		t.Fatalf("reset = %q, %v", c, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	idle := func(context.Context, string) ([]byte, int, error) {
		cancel()
		return []byte(`{"cursor":"e.0"}`), http.StatusOK, nil
	}
	if _, err := Wait(ctx, idle, "e.0"); !errors.Is(err, context.Canceled) {
		t.Fatalf("idle until cancel: %v", err)
	}
	gone := func(context.Context, string) ([]byte, int, error) { return []byte("404"), http.StatusNotFound, nil }
	if _, err := List(t.Context(), gone, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("404: %v", err)
	}
	typed := func(context.Context, string) ([]byte, int, error) {
		return []byte(`{"code":16,"message":"authenticated principal required","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ERROR_REASON_UNAUTHENTICATED","domain":"relay.nfltr.xyz"}]}`), http.StatusUnauthorized, nil
	}
	var e *Error
	if _, err := List(t.Context(), typed, map[string]string{"k": "v"}); !errors.As(err, &e) || e.Reason != "ERROR_REASON_UNAUTHENTICATED" {
		t.Fatalf("typed error: %v", err)
	}
}

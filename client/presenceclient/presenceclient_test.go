// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package presenceclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	presencev1 "github.com/nfltr/relay/proto/nfltr/presence/v1"
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

// TestServicesCarried: an agent's declared services (group, direct,
// health) come through List and Watch as the gateway's JSON sends them.
func TestServicesCarried(t *testing.T) {
	const svc = `"services":[{"name":"pg","kind":"tcp","e2ee":"e2ee","group":"db","direct":"on","down":true},{"name":"web","kind":"http"}]`
	get := func(_ context.Context, path string) ([]byte, int, error) {
		if u, _ := url.Parse(path); u.Path == AgentsPath {
			return []byte(`{"cursor":"e.1","agents":[{"agentId":"a",` + svc + `}]}`), http.StatusOK, nil
		}
		return []byte(`{"cursor":"e.2","events":[{"revision":"2","agentId":"a","up":{` + svc + `}}]}`), http.StatusOK, nil
	}
	check := func(what string, got []*presencev1.Service) {
		t.Helper()
		if len(got) != 2 || got[0].GetName() != "pg" || got[0].GetKind() != "tcp" || got[0].GetE2Ee() != "e2ee" ||
			got[0].GetGroup() != "db" || got[0].GetDirect() != "on" || !got[0].GetDown() ||
			got[1].GetName() != "web" || got[1].GetGroup() != "" || got[1].GetDown() {
			t.Fatalf("%s services = %v", what, got)
		}
	}
	l, err := List(t.Context(), get, nil)
	if err != nil || len(l.GetAgents()) != 1 {
		t.Fatalf("List = %v, %v", l, err)
	}
	check("List", l.GetAgents()[0].GetServices())
	w, err := Watch(t.Context(), get, "e.1", 0)
	if err != nil || len(w.GetEvents()) != 1 {
		t.Fatalf("Watch = %v, %v", w, err)
	}
	check("Watch", w.GetEvents()[0].GetUp().GetServices())
}

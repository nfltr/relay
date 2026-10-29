// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func newTestE2EESetup(t *testing.T) *E2EESetup {
	t.Helper()
	s, err := NewE2EESetup("agent-1", "", "", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// RequireSharePolicy validates the policy at the boundary and fails closed:
// nothing is enforced (or advertised) for a policy it rejects.
func TestRequireSharePolicyRejectsInvalidPolicies(t *testing.T) {
	for name, tc := range map[string]struct {
		code   string
		policy SharePolicy
	}{
		"no code":              {"", SharePolicy{BasicAuth: "a:b"}},
		"code not a share":     {"Bad Code", SharePolicy{BasicAuth: "a:b"}},
		"no credential gate":   {"swift-bay", SharePolicy{}},
		"basic auth no colon":  {"swift-bay", SharePolicy{BasicAuth: "alice"}},
		"bad header name":      {"swift-bay", SharePolicy{RequiredHeaders: map[string]string{"X Bad": "v"}}},
		"header value newline": {"swift-bay", SharePolicy{RequiredHeaders: map[string]string{"X-Key": "a\r\nb"}}},
		"bearer newline":       {"swift-bay", SharePolicy{BearerToken: "t\n"}},
	} {
		s := newTestE2EESetup(t)
		if err := s.RequireSharePolicy(tc.code, tc.policy); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if s.cfg.wrapHTTP != nil || len(s.cfg.shareCodes) != 0 {
			t.Errorf("%s: a rejected policy was installed", name)
		}
	}
}

// The share policy is checked on every E2EE request before the backend:
// required headers (403), Bearer token and Basic Auth (401 with a challenge).
func TestSharePolicyEnforcedPerRequest(t *testing.T) {
	type req struct {
		basic, bearer string
		headers       map[string]string
		want          int
		challenge     string
	}
	for name, tc := range map[string]struct {
		policy SharePolicy
		reqs   []req
	}{
		"basic auth": {SharePolicy{BasicAuth: "bob:pw"}, []req{
			{want: 401, challenge: "Basic"},
			{basic: "bob:nope", want: 401, challenge: "Basic"},
			{bearer: "pw", want: 401, challenge: "Basic"},
			{basic: "bob:pw", want: 200},
		}},
		"bearer": {SharePolicy{BearerToken: "tok-1"}, []req{
			{want: 401, challenge: "Bearer"},
			{bearer: "tok-2", want: 401, challenge: "Bearer"},
			{basic: "tok-1:", want: 401, challenge: "Bearer"},
			{bearer: "tok-1", want: 200},
		}},
		"required headers": {SharePolicy{RequiredHeaders: map[string]string{"X-Key": "k1", "X-Env": "prod"}}, []req{
			{want: 403},
			{headers: map[string]string{"X-Key": "k1"}, want: 403},
			{headers: map[string]string{"X-Key": "k1", "X-Env": "dev"}, want: 403},
			{headers: map[string]string{"X-Key": "k1", "X-Env": "prod"}, want: 200},
		}},
	} {
		s := newTestE2EESetup(t)
		if err := s.RequireSharePolicy("swift-bay", tc.policy); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		reached := 0
		h := s.cfg.wrapHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached++
			// The share's credential stops at the agent, which checked it.
			if v := r.Header.Values("Authorization"); len(v) > 0 {
				t.Errorf("%s: the share's credential reached the backend: %q", name, v)
			}
		}))
		for i, rq := range tc.reqs {
			r := httptest.NewRequest(http.MethodGet, "https://swift-bay.example/", nil)
			if user, pass, ok := strings.Cut(rq.basic, ":"); ok {
				r.SetBasicAuth(user, pass)
			}
			if rq.bearer != "" {
				r.Header.Set("Authorization", "Bearer "+rq.bearer)
			}
			for k, v := range rq.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			before := reached
			h.ServeHTTP(w, r)
			if w.Code != rq.want {
				t.Errorf("%s #%d: status %d, want %d", name, i, w.Code, rq.want)
			}
			if got := w.Header().Get("WWW-Authenticate"); rq.challenge != "" && !strings.HasPrefix(got, rq.challenge) {
				t.Errorf("%s #%d: challenge %q, want %s", name, i, got, rq.challenge)
			}
			if passed := reached > before; passed != (rq.want == 200) {
				t.Errorf("%s #%d: backend reached = %v", name, i, passed)
			}
		}
	}
}

// A share policy without a credential leaves Authorization to the service.
func TestSharePolicyWithoutCredentialKeepsAuthorization(t *testing.T) {
	s := newTestE2EESetup(t)
	if err := s.RequireSharePolicy("swift-bay", SharePolicy{RequiredHeaders: map[string]string{"X-Key": "k1"}}); err != nil {
		t.Fatal(err)
	}
	var got string
	h := s.cfg.wrapHTTP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Key", "k1")
	r.Header.Set("Authorization", "Bearer the-apps-own")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "Bearer the-apps-own" {
		t.Fatalf("Authorization at the backend = %q, want the app's own token", got)
	}
}

// --basic-auth (the agent's own) and the share policy both apply.
func TestSharePolicyComposesWithBasicAuth(t *testing.T) {
	s := newTestE2EESetup(t)
	s.RequireBasicAuth("alice:secret")
	if err := s.RequireSharePolicy("swift-bay", SharePolicy{RequiredHeaders: map[string]string{"X-Key": "k1"}}); err != nil {
		t.Fatal(err)
	}
	h := s.cfg.wrapHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, tc := range []struct {
		basic, key string
		want       int
	}{{"alice:secret", "", 403}, {"", "k1", 401}, {"alice:secret", "k1", 200}} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if user, pass, ok := strings.Cut(tc.basic, ":"); ok {
			r.SetBasicAuth(user, pass)
		}
		if tc.key != "" {
			r.Header.Set("X-Key", tc.key)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%+v: status %d", tc, w.Code)
		}
	}
}

// The agent names every share whose policy it enforces on its ConnectTCP
// streams (request metadata), so the relay forwards a protected share's
// sessions to it and to no agent that does not enforce.
func TestRunTCPTunnelAdvertisesEnforcedShares(t *testing.T) {
	s := newTestE2EESetup(t)
	if err := s.RequireSharePolicy("swift-bay", SharePolicy{BasicAuth: "bob:pw"}); err != nil {
		t.Fatal(err)
	}
	got := make(chan []string, 1)
	client := &mdCapturingClient{got: got}
	ctx := t.Context()
	go func() {
		_ = s.RunTCPTunnel(ctx, client, RelayDialer{}, ctx, "", "http://127.0.0.1:1", slog.New(slog.DiscardHandler))
	}()
	if codes := <-got; !slices.Equal(codes, []string{"swift-bay"}) {
		t.Fatalf("advertised %q", codes)
	}

	plain := newTestE2EESetup(t)
	got2 := make(chan []string, 1)
	go func() {
		_ = plain.RunTCPTunnel(ctx, &mdCapturingClient{got: got2}, RelayDialer{}, ctx, "", "http://127.0.0.1:1", slog.New(slog.DiscardHandler))
	}()
	if codes := <-got2; len(codes) != 0 {
		t.Fatalf("an agent without a share policy advertised %q", codes)
	}
}

type mdCapturingClient struct {
	pb.DispatcherClient
	got chan []string
}

func (c *mdCapturingClient) ConnectTCP(ctx context.Context, _ ...grpc.CallOption) (pb.Dispatcher_ConnectTCPClient, error) {
	md, _ := metadata.FromOutgoingContext(ctx)
	c.got <- md.Get(sharePolicyHeader)
	return nil, net.ErrClosed
}

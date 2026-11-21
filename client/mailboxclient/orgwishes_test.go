// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package mailboxclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The root's machine reads the pending wishes and drops one it handled.
func TestOrgWishes(t *testing.T) {
	dropped := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/org-wishes/o-1":
			_, _ = w.Write([]byte(`{"wishes":[{"id":"w1","act":"revoke","name":"web-1","serial":"ab","at":"2026-11-21T10:00:00Z"}]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/org-wishes/o-1/w1":
			dropped = "w1"
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := Client{ProxyURL: srv.URL}
	ws, err := c.OrgWishes(t.Context(), "o-1")
	if err != nil || len(ws) != 1 || ws[0].Act != "revoke" || ws[0].Name != "web-1" || ws[0].Serial != "ab" {
		t.Fatalf("wishes: %+v, %v", ws, err)
	}
	if ws, err := c.OrgWishes(t.Context(), "o-2"); err != nil || ws != nil {
		t.Fatalf("none: %+v, %v", ws, err)
	}
	if err := c.DropOrgWish(t.Context(), "o-1", "w1"); err != nil || dropped != "w1" {
		t.Fatalf("drop: %v (%q)", err, dropped)
	}
	if err := c.DropOrgWish(t.Context(), "o-1", "gone"); err != nil {
		t.Fatalf("a wish already gone: %v", err)
	}
}

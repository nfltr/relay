// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const self, box = "m-aaaaaaaaaaaaaaaaaaaaaaaaaa", "m-bbbbbbbbbbbbbbbbbbbbbbbbba"

// The relay's resolve route as relay-server machines_api.go answers it.
func relay(t *testing.T, calls *int) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.URL.Path != "/api/v1/machines/resolve" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Query().Get("name") {
		case "":
			_, _ = w.Write([]byte(`{"id":"` + self + `"}`))
		case "box":
			_, _ = w.Write([]byte(`{"id":"` + box + `"}`))
		default:
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestMachines(t *testing.T) {
	calls := 0
	m := Machines(relay(t, &calls), nil)
	for name, want := range map[string]string{"": self, "box": box} {
		if got, err := m(context.Background(), name); err != nil || got != want {
			t.Errorf("machine %q = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := m(context.Background(), "desk"); !errors.Is(err, ErrNoMachine) {
		t.Errorf("a name the account has not: %v, want ErrNoMachine", err)
	}
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer refusing.Close()
	if _, err := Machines(refusing.URL, nil)(context.Background(), ""); err == nil {
		t.Error("a refused machine resolved")
	}
}

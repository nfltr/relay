// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package mailboxclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The relay's copy round trips (the CRL's and the status's): a put is
// kept and read back, none is nil (404), a refusal is an *Error with its
// reason.
func TestOrgCRLCopy(t *testing.T) {
	testOrgCopy(t, "/api/v1/org-crl/o-1", Client.OrgCRL, Client.PutOrgCRL)
}

func TestOrgStatusCopy(t *testing.T) {
	testOrgCopy(t, "/api/v1/org-status/o-1", Client.OrgStatus, Client.PutOrgStatus)
}

func testOrgCopy(t *testing.T, path string, get func(Client, context.Context, string) ([]byte, error), put func(Client, context.Context, string, []byte) error) {
	var held []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			if len(b) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":3,"message":"empty","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ERROR_REASON_INVALID_ARGUMENT"}]}`))
				return
			}
			held = b
		case http.MethodGet:
			if held == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(held)
		}
	}))
	defer srv.Close()
	c := Client{ProxyURL: srv.URL + "/", Token: "tok"}
	if got, err := get(c, t.Context(), "o-1"); err != nil || got != nil {
		t.Fatalf("none held: %q, %v", got, err)
	}
	if err := put(c, t.Context(), "o-1", []byte(`{"crl":"AA=="}`)); err != nil {
		t.Fatal(err)
	}
	if got, err := get(c, t.Context(), "o-1"); err != nil || !bytes.Equal(got, []byte(`{"crl":"AA=="}`)) {
		t.Fatalf("read back: %q, %v", got, err)
	}
	if err := put(c, t.Context(), "o-1", nil); ReasonOf(err) != "ERROR_REASON_INVALID_ARGUMENT" {
		t.Fatalf("refusal: %v", err)
	}
}

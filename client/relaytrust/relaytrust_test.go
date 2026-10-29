// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relaytrust

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// get fetches srv's URL (rewritten to host when set) with cfg and reports
// whether the TLS handshake was accepted.
func get(t *testing.T, srv *httptest.Server, cfg *tls.Config, host string) error {
	t.Helper()
	url := srv.URL
	tr := &http.Transport{TLSClientConfig: cfg}
	if host != "" { // dial the test server under a DNS name
		_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
		url = "https://" + host + ":" + port
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}
	}
	resp, err := (&http.Client{Transport: tr}).Get(url)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

func TestWithPinAcceptsOnlyThePinnedCertificateOrAVerifiedOne(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	pin := Fingerprint(srv.Certificate().Raw)
	other := strings.Repeat("ab", 32)
	ca := x509.NewCertPool()
	ca.AddCert(srv.Certificate())

	cases := []struct {
		name string
		cfg  *tls.Config
		host string
		ok   bool
	}{
		{"no pin: self-signed refused", WithPin(nil, ""), "", false},
		{"pinned self-signed accepted", WithPin(nil, pin), "", true},
		{"pin with colons and capitals accepted", WithPin(nil, strings.ToUpper(colons(pin))), "", true},
		{"wrong pin refused", WithPin(nil, other), "", false},
		{"malformed pin never matches", WithPin(nil, "not-a-pin"), "", false},
		{"verified host still accepted with another pin", WithPin(&tls.Config{RootCAs: ca}, other), "example.com", true},
		{"verified chain for the wrong name refused", WithPin(&tls.Config{RootCAs: ca}, other), "wrong.invalid", false},
		{"IP target: only the pin, even with a verified chain", WithPin(&tls.Config{RootCAs: ca}, other), "", false},
	}
	for _, tc := range cases {
		err := get(t, srv, tc.cfg, tc.host)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestWithPinKeepsAnExplicitInsecureSkipVerifyAndCopies(t *testing.T) {
	base := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test
	if got := WithPin(base, strings.Repeat("ab", 32)); got == base || got.VerifyConnection != nil {
		t.Fatalf("WithPin must copy and leave an explicit skip alone")
	}
	plain := &tls.Config{}
	if WithPin(plain, strings.Repeat("ab", 32)); plain.InsecureSkipVerify || plain.VerifyConnection != nil {
		t.Fatal("WithPin mutated its input")
	}
}

func TestParsePin(t *testing.T) {
	good := strings.Repeat("Ab", 32)
	for _, form := range []string{good, colons(good), strings.ToUpper(colons(good)), "SHA256:" + strings.ToUpper(colons(good)), " sha256:" + good + "\n"} {
		if p, err := ParsePin(form); err != nil || p != strings.ToLower(good) {
			t.Fatalf("ParsePin(%q) = %q, %v", form, p, err)
		}
	}
	for _, bad := range []string{"", "abcd", strings.Repeat("zz", 32), strings.Repeat("ab", 33), "SHA1:" + good, "sha256:sha256:" + good} {
		if _, err := ParsePin(bad); err == nil {
			t.Errorf("ParsePin(%q) accepted", bad)
		}
	}
}

func colons(hexs string) string {
	var parts []string
	for i := 0; i < len(hexs); i += 2 {
		parts = append(parts, hexs[i:i+2])
	}
	return strings.Join(parts, ":")
}

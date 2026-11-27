// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package relaytrusttest makes the server certificates of the client TLS
// checks (badssl.com-style, on loopback, no network): a valid one from a
// test CA and the bad kinds a client must refuse unless the user pinned or
// trusted them. Test code only.
package relaytrusttest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Host is the name every certificate but WrongHost is issued for; it
// resolves to loopback without DNS.
const Host = "localhost"

// Kind is one server certificate of the matrix.
type Kind struct {
	Name string
	Cert tls.Certificate
	// Bad is whether a client must refuse it without a pin or trusted CA.
	// The weak RSA-1024 key is not: Go's floor is 1024 bits.
	Bad bool
}

// Set is the matrix: CA is the test CA a client may be told to trust.
type Set struct {
	CA    *x509.CertPool
	Kinds []Kind
}

// New makes the CA and every kind: valid, expired, self-signed, wrong host
// name, signed by an untrusted CA, and a weak (RSA-1024) key.
func New(t testing.TB) Set {
	t.Helper()
	ca, caKey := issue(t, nil, nil, ecKey(t), template(t, "test CA", true))
	other, otherKey := issue(t, nil, nil, ecKey(t), template(t, "untrusted CA", true))
	leaf := func(mut func(*x509.Certificate)) *x509.Certificate {
		c := template(t, Host, false)
		if mut != nil {
			mut(c)
		}
		return c
	}
	pair := func(parent *x509.Certificate, parentKey crypto.Signer, key crypto.Signer, tmpl *x509.Certificate) tls.Certificate {
		c, _ := issue(t, parent, parentKey, key, tmpl)
		return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return Set{CA: pool, Kinds: []Kind{
		{"valid", pair(ca, caKey, ecKey(t), leaf(nil)), false},
		{"expired", pair(ca, caKey, ecKey(t), leaf(func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
		})), true},
		{"self-signed", pair(nil, nil, ecKey(t), leaf(nil)), true},
		{"wrong host", pair(ca, caKey, ecKey(t), leaf(func(c *x509.Certificate) {
			c.DNSNames, c.IPAddresses = []string{"wrong.invalid"}, nil
		})), true},
		{"untrusted CA", pair(other, otherKey, ecKey(t), leaf(nil)), true},
		{"weak key RSA-1024", pair(ca, caKey, weak, leaf(nil)), false},
	}}
}

// Serve is a loopback HTTPS server (HTTP/2 and HTTP/1.1) presenting cert;
// it answers 200 to every request.
func Serve(t testing.TB, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // refused handshakes are the point
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// Addr is srv's address under Host (host:port).
func Addr(srv *httptest.Server) string {
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return net.JoinHostPort(Host, port)
}

func ecKey(t testing.TB) crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func template(t testing.TB, cn string, isCA bool) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if isCA {
		c.IsCA, c.BasicConstraintsValid, c.KeyUsage = true, true, x509.KeyUsageCertSign
		c.ExtKeyUsage = nil
	} else {
		c.DNSNames, c.IPAddresses = []string{Host}, []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	return c
}

// issue signs tmpl for key by parent (nil: self-signed).
func issue(t testing.TB, parent *x509.Certificate, parentKey, key crypto.Signer, tmpl *x509.Certificate) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

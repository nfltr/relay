// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcmd "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// certRelay records the client certificate and API key an AgentTunnel came
// with.
type certRelay struct {
	registeringRelay
	got chan [2]string // [client certificate CN, x-api-key]
}

func (r *certRelay) AgentTunnel(s grpc.BidiStreamingServer[pb.TunnelFrame, pb.TunnelFrame]) error {
	var cn, key string
	if p, ok := peer.FromContext(s.Context()); ok {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
			cn = ti.State.PeerCertificates[0].Subject.CommonName
		}
	}
	if md, ok := grpcmd.FromIncomingContext(s.Context()); ok && len(md.Get("x-api-key")) > 0 {
		key = md.Get("x-api-key")[0]
	}
	r.got <- [2]string{cn, key}
	return r.registeringRelay.AgentTunnel(s)
}

func selfSigned(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	tmpl.Subject.CommonName = cn
	tmpl.DNSNames = []string{"127.0.0.1"}
	tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// WithClientTLS dials over TLS with the caller's configuration (a machine
// certificate from GetClientCertificate, read at each handshake) and
// authenticates by the certificate alone: no API key is sent.
func TestDialWithClientTLSPresentsTheCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srvCert := selfSigned(t, "relay")
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12})))
	r := &certRelay{got: make(chan [2]string, 1)}
	pb.RegisterDispatcherServer(srv, r)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	machine := selfSigned(t, "m-1")
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, // #nosec G402 -- test relay's self-signed certificate
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &machine, nil }}
	a, err := Dial(ctx, lis.Addr().String(), WithAgentID("x"), WithClientTLS(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close() //nolint:errcheck
	if got := <-r.got; got != [2]string{"m-1", ""} {
		t.Fatalf("relay saw (certificate CN, API key) = %q, want the certificate and no key", got)
	}
}

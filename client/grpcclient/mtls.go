// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// NewMTLSClientConfig builds a *tls.Config suitable for a gRPC or HTTP client
// that needs to present a client certificate (mTLS). caFile is the server's CA
// bundle (or empty to use the system pool). certFile and keyFile are the
// client's certificate and private key.
func NewMTLSClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("grpcclient: load client keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("grpcclient: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("grpcclient: no valid certs in CA file %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"

	"github.com/nfltr/relay/client/relaytrust"
)

// ErrE2EEClientNotAllowed: a pinned session's client presented no
// certificate, or one whose key is not on the agent's list
// (Config.TCPE2EEClients, Service.E2EEClients). The client sees a TLS
// alert (bad_certificate, or certificate_required without one).
var ErrE2EEClientNotAllowed = errors.New("e2ee: the client's key is not on this agent's list")

// clientKeys is an allow-list of client key fingerprints
// (relaytrust.ClientKeyFingerprint); nil allows any client.
type clientKeys map[string]struct{}

// newClientKeys parses fps; none is nil (no client authentication).
func newClientKeys(fps []string) (clientKeys, error) {
	if len(fps) == 0 {
		return nil, nil
	}
	k := make(clientKeys, len(fps))
	for _, s := range fps {
		fp, err := relaytrust.ParsePin(s)
		if err != nil {
			return nil, fmt.Errorf("e2ee client key: %w", err)
		}
		k[fp] = struct{}{}
	}
	return k, nil
}

// serverConfig is base with client authentication against k: TLS requires
// a client certificate (crypto/tls checks its CertificateVerify against
// the certificate's key) whose key is listed. No CA: the relay's CA could
// mint any certificate (e2ee_tcp.pv mutant any-client-cert). nil k: base.
func (k clientKeys) serverConfig(base *tls.Config, logger *slog.Logger) *tls.Config {
	if k == nil {
		return base
	}
	c := base.Clone()
	c.ClientAuth = tls.RequireAnyClientCert
	// VerifyConnection, not VerifyPeerCertificate: it runs on a resumed
	// session too (gosec G123).
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return ErrE2EEClientNotAllowed
		}
		fp := relaytrust.ClientKeyFingerprint(cs.PeerCertificates[0])
		if _, ok := k[fp]; !ok {
			logger.Warn("e2ee tcp: client key not allowed", "client_key", fp)
			return ErrE2EEClientNotAllowed
		}
		return nil
	}
	return c
}

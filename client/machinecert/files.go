// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecert

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"

	"github.com/nfltr/relay/client/pairfile"
)

// KeyEnv holds the machine key (PKCS#8 PEM) instead of machine.key: a node
// hands its key to the agent processes it launches in memory (their env,
// non-dumpable; the node strips it from the model CLIs they run), and a
// Linux node container keeps machine.key in its root-only secrets dir and
// starts the node with the key here. machine.json (the chain, not secret)
// stays in the config directory, which renewals rewrite.
const KeyEnv = "NFLTR_MACHINE_KEY"

// Files in the config directory: the key (PKCS#8 PEM, 0600) and the
// certificate with what the relay answered (machine.json, 0600).
const (
	KeyFile  = "machine.key"
	CertFile = "machine.json"
)

// Saved is machine.json: the relay's answer and where it came from.
type Saved struct {
	Cert
	// RelayHost is the relay's host the certificate is for (only its
	// connections present it); BaseURL its HTTP base (enrol, renew).
	RelayHost string `json:"relay_host"`
	BaseURL   string `json:"base_url"`
}

// KeyPath is the machine key's file in dir.
func KeyPath(dir string) string { return filepath.Join(dir, KeyFile) }

// CertPath is the machine certificate's file in dir.
func CertPath(dir string) string { return filepath.Join(dir, CertFile) }

// Load reads dir's machine.json.
func Load(dir string) (*Saved, error) {
	b, err := os.ReadFile(CertPath(dir)) // #nosec G304 -- this machine's own certificate file
	if err != nil {
		return nil, err
	}
	return parseSaved(CertPath(dir), b)
}

func parseSaved(path string, b []byte) (*Saved, error) {
	var s Saved
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c, err := ParseCert([]byte(s.Chain))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.Leaf, s.NotAfter = c.Leaf, c.NotAfter
	return &s, nil
}

// Pair is dir's machine.key and machine.json, replaced and read as one
// pair: a writer stopped at any step leaves a pair (client/pairfile,
// spec/pair/MachinePair.tla, lane CERTATOMIC).
func Pair(dir string) pairfile.Pair {
	return pairfile.Pair{Key: KeyPath(dir), Cert: CertPath(dir), Match: func(cert, key []byte) error {
		s, err := parseSaved(CertPath(dir), cert)
		if err != nil {
			return err
		}
		k, err := parseKey(KeyPath(dir), key)
		if err != nil {
			return err
		}
		if pub, ok := s.Leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&k.PublicKey) {
			return pairfile.Mismatch(errors.New(CertPath(dir) + " certifies another key than " + KeyPath(dir)))
		}
		return nil
	}}
}

// SavePair writes s and key as dir's machine.json and machine.key, as one
// pair (Pair): what `nfltr config login` keeps. Writers of one directory
// are not run at once.
func SavePair(dir string, s *Saved, key *ecdsa.PrivateKey) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	k, err := keyPEM(key)
	if err != nil {
		return err
	}
	return Pair(dir).Write(append(b, '\n'), k)
}

// LoadPair reads dir's machine.json and the key it certifies (Pair).
func LoadPair(dir string) (*Saved, *ecdsa.PrivateKey, error) {
	cert, key, err := Pair(dir).Read()
	if err != nil {
		return nil, nil, err
	}
	s, err := parseSaved(CertPath(dir), cert)
	if err != nil {
		return nil, nil, err
	}
	k, err := parseKey(KeyPath(dir), key)
	return s, k, err
}

// Store writes s as dir's machine.json (0600, replaced atomically).
func (s *Saved) Store(dir string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".machine-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil { // a power loss keeps the old file or the new one
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), CertPath(dir))
}

// RelayHost is server's host name ("host:port", "host" or a URL).
func RelayHost(server string) string {
	if u, err := url.Parse(server); err == nil && u.Host != "" {
		server = u.Host
	}
	if h, _, err := net.SplitHostPort(server); err == nil {
		return h
	}
	return server
}

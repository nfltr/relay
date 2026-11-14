// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The files of a machine's directory, as enrolment and renewal write them.
const (
	RootFile     = "root.pem"     // the organisation's root certificate
	RecoveryFile = "recovery.pem" // its recovery certificate
	CertFile     = "machine.pem"  // this machine's certificate, its issuer's (then nfltr's SSH host certificate, which Load skips)
	KeyFile      = "machine.key"  // its key (PKCS#8 PEM), 0600
	CRLFile      = "crl.der"      // the issuer's newest CRL
)

// Dir is the machine directory under nfltr's config directory.
func Dir(configDir string) string { return filepath.Join(configDir, "org", "machine") }

// DefaultDir is Dir of nfltr's config directory: the directory of
// $NFLTR_CONFIG when set, else ~/.config/nfltr.
func DefaultDir() string {
	if v := os.Getenv("NFLTR_CONFIG"); v != "" {
		return Dir(filepath.Dir(v))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Dir(".")
	}
	return Dir(filepath.Join(home, ".config", "nfltr"))
}

// Identity is this machine's organisation identity, read from its
// directory, behind the checks of a Verifier. It serves both halves of a
// session in organisation mode: a service (agent.Org: Certificate,
// CheckClient, Changed) and a client that names a machine or a group
// (ClientTLS, GroupClientTLS, CheckServer; agent.DirectMachine). Reload
// takes what another process wrote (a renewal, a newer CRL, a rotated
// root) and signals Changed, so open sessions are checked again.
type Identity struct {
	dir string
	mu  sync.Mutex
	// rootMu serialises TakeRotation (the verifier, then root.pem) with
	// Reload's read of root.pem: a Reload between the two would read the
	// old root as a rotation, which the recovery key never signed.
	rootMu  sync.Mutex
	ver     *Verifier
	orgID   string
	root    []byte // root.pem's certificate, as the verifier took it
	cert    *tls.Certificate
	crl     []byte
	changed chan struct{}
}

// Load reads dir. A machine that is not enrolled (no files) is an error:
// organisation mode never runs without it.
func Load(dir string) (*Identity, error) {
	root, err := readCert(filepath.Join(dir, RootFile))
	if err != nil {
		return nil, notEnrolled(dir, err)
	}
	rec, err := readCert(filepath.Join(dir, RecoveryFile))
	if err != nil {
		return nil, notEnrolled(dir, err)
	}
	ver, err := NewVerifier(root, rec, Fingerprint(root), Fingerprint(rec))
	if err != nil {
		return nil, err
	}
	orgID, err := OrgIDOfRoot(root)
	if err != nil {
		return nil, err
	}
	m := &Identity{dir: dir, ver: ver, orgID: orgID, root: root.Raw, changed: make(chan struct{})}
	if _, err := m.Reload(time.Now()); err != nil {
		return nil, err
	}
	return m, nil
}

func notEnrolled(dir string, err error) error {
	return fmt.Errorf("this machine is not enrolled in an organisation (%s; enrol it with nfltr org join): %w", dir, err)
}

func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a file of the machine's own directory
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: not a PEM certificate", path)
	}
	return x509.ParseCertificate(b.Bytes)
}

// Reload reads the root, certificate, key and CRL again. A rotated root
// (Verifier.TakeRotation: the recovery key's only), a renewed certificate
// or a newer CRL (TakeCRL refuses an older one) is a change: Changed's
// channel closes. A file that does not parse fails it and changes
// nothing; a CRL the verifier refuses is only not taken.
func (m *Identity) Reload(now time.Time) (changed bool, err error) {
	m.rootMu.Lock()
	root, err := readCert(filepath.Join(m.dir, RootFile))
	if err != nil {
		m.rootMu.Unlock()
		return false, err
	}
	rotated, err := m.takeRoot(root.Raw)
	m.rootMu.Unlock()
	if err != nil {
		return false, fmt.Errorf("%s: %w", RootFile, err)
	}
	chain, err := os.ReadFile(filepath.Join(m.dir, CertFile))
	if err != nil {
		return false, notEnrolled(m.dir, err)
	}
	if err := checkKeyMode(filepath.Join(m.dir, KeyFile)); err != nil {
		return false, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(m.dir, KeyFile))
	if err != nil {
		return false, err
	}
	cert, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return false, fmt.Errorf("%s: %w", CertFile, err)
	}
	if len(cert.Certificate) != 2 {
		return false, fmt.Errorf("%s: want the machine's certificate and its issuer's", CertFile)
	}
	issuer, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		return false, err
	}
	crl, err := os.ReadFile(filepath.Join(m.dir, CRLFile))
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	newCRL := string(crl) != string(m.crl)
	if newCRL {
		// A CRL that the verifier refuses is not taken, and fails nothing
		// else: after a rotation crl.der is the old root's until the new
		// issuer's arrives, and the renewal into the new issuer must not
		// wait for it. The verifier keeps what it held (after a rotation
		// nothing: it admits no one under that issuer, fail closed) until
		// a CRL it takes.
		if err := m.ver.TakeCRL(crl, issuer, now); err != nil {
			newCRL = false
		} else {
			m.crl = crl
		}
	}
	newCert := m.cert == nil || string(m.cert.Certificate[0]) != string(cert.Certificate[0])
	if newCert {
		m.cert = &cert
	}
	if newCRL || newCert {
		m.signal()
	}
	return rotated || newCRL || newCert, nil
}

// signal closes Changed's channel. Callers hold mu.
func (m *Identity) signal() {
	if m.changed != nil {
		close(m.changed)
	}
	m.changed = make(chan struct{})
}

// takeRoot takes der as the organisation's root when it is not the one
// held: a rotation (Enrol.tla TakeRoot). The CRLs under the old root go
// with it, so the CRL is taken again (the new issuer's). It signals
// Changed: sessions under the old root are checked again and cut.
func (m *Identity) takeRoot(der []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bytes.Equal(der, m.root) {
		return false, nil
	}
	if err := m.ver.TakeRotation(der); err != nil {
		return false, err
	}
	m.root, m.crl = der, nil
	m.signal()
	return true, nil
}

// TakeRotation takes the organisation's new root (the recovery key's
// certificate of it, from the relay) and keeps it in root.pem; Changed.
// The certificate this machine holds is then under the old root until
// it renews.
func (m *Identity) TakeRotation(der []byte) (bool, error) {
	m.rootMu.Lock()
	defer m.rootMu.Unlock()
	taken, err := m.takeRoot(der)
	if err != nil || !taken {
		return taken, err
	}
	return true, writeFile(filepath.Join(m.dir, RootFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TakeCRL takes the issuer's CRL from the relay when the verifier does
// (signed by an issuer under the trusted root, newer than the one held,
// not lapsed) and keeps it in crl.der; Changed. The CRL held already is
// no change.
func (m *Identity) TakeCRL(crl, issuerDER []byte, now time.Time) (bool, error) {
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if bytes.Equal(crl, m.crl) {
		return false, nil
	}
	if err := m.ver.TakeCRL(crl, issuer, now); err != nil {
		return false, err
	}
	if err := writeFile(filepath.Join(m.dir, CRLFile), crl); err != nil {
		return false, err
	}
	m.crl = crl
	m.signal()
	return true, nil
}

// writeFile replaces path whole with data, readable by its owner only.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// OrgID is the organisation's id.
func (m *Identity) OrgID() string { return m.orgID }

// Verifier is the verifier m checks with (its root, its CRLs).
func (m *Identity) Verifier() *Verifier { return m.ver }

// checkKeyMode refuses a key other users can read.
func checkKeyMode(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: mode %v, want 0600", path, fi.Mode().Perm())
	}
	return nil
}

// Watch reloads every interval until stop is closed; a failed reload
// changes nothing (the verifier fails closed once its CRL lapses).
// ponytail: a reread on a timer; Follow carries the CRL push.
func (m *Identity) Watch(every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_, _ = m.Reload(time.Now())
		}
	}
}

// Certificate is this machine's certificate chain and key (agent.Org).
func (m *Identity) Certificate() (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cert, nil
}

// Changed is closed at the next change (agent.Org).
func (m *Identity) Changed() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.changed
}

// errNoChain: a peer presented no certificate, or no issuer after it.
var errNoChain = errors.New("the peer presented no organisation certificate and issuer")

// CheckClient admits a client in one of groups (agent.Org): the first
// group it is in.
func (m *Identity) CheckClient(certs []*x509.Certificate, groups []string, now time.Time) (time.Time, error) {
	if len(certs) != 2 {
		return time.Time{}, errNoChain
	}
	err := errors.New("no group allowed")
	for _, g := range groups {
		id, cerr := m.ver.Check(certs[0], certs[1], Peer{Group: g}, now)
		if cerr == nil {
			return id.Until, nil
		}
		err = cerr
	}
	return time.Time{}, err
}

// CheckServer checks a server's certificates as the machine name
// (agent.DirectMachine).
func (m *Identity) CheckServer(certs []*x509.Certificate, name string, now time.Time) (time.Time, error) {
	if len(certs) != 2 {
		return time.Time{}, errNoChain
	}
	id, err := m.ver.Check(certs[0], certs[1], Peer{Name: name}, now)
	return id.Until, err
}

// CheckServerGroup checks a server's certificates as any machine of
// group: chain, NotAfter, CRL and the group in its OU, no name (a group
// dial, <service>@<group>: BIND:org.group).
func (m *Identity) CheckServerGroup(certs []*x509.Certificate, group string, now time.Time) (time.Time, error) {
	if len(certs) != 2 {
		return time.Time{}, errNoChain
	}
	id, err := m.ver.Check(certs[0], certs[1], Peer{Group: group}, now)
	return id.Until, err
}

// ClientTLS is the TLS client of organisation mode to the machine name:
// TLS 1.3, ServerName its DNS name in the organisation, this machine's
// certificate as the client's, and CheckServer (not crypto/tls's CA
// check: the CRL and the name are the verifier's), whose until goes to
// admitted. No pin, no fallback.
func (m *Identity) ClientTLS(name string, admitted func(certs []*x509.Certificate, until time.Time)) *tls.Config {
	return m.clientTLS(MachineDNS(name, m.orgID), func(certs []*x509.Certificate, now time.Time) (time.Time, error) {
		until, err := m.CheckServer(certs, name, now)
		if err != nil {
			return until, fmt.Errorf("the server is not machine %s of the organisation (a machine enrols under its name in the account and is dialled as <machine>.<agent>): %w", name, err)
		}
		return until, nil
	}, admitted)
}

// GroupClientTLS is ClientTLS to any machine of group (CheckServerGroup):
// a group dial, whose server is whichever instance the relay picked.
func (m *Identity) GroupClientTLS(group string, admitted func(certs []*x509.Certificate, until time.Time)) *tls.Config {
	return m.clientTLS("", func(certs []*x509.Certificate, now time.Time) (time.Time, error) {
		until, err := m.CheckServerGroup(certs, group, now)
		if err != nil {
			return until, fmt.Errorf("the server is not a machine of group %s: %w", group, err)
		}
		return until, nil
	}, admitted)
}

func (m *Identity) clientTLS(serverName string, check func([]*x509.Certificate, time.Time) (time.Time, error), admitted func([]*x509.Certificate, time.Time)) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		ServerName:             serverName,
		GetClientCertificate:   func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return m.Certificate() },
		InsecureSkipVerify:     true, // #nosec G402 -- VerifyConnection runs the organisation's check (chain, name or group, CRL) instead
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			until, err := check(cs.PeerCertificates, time.Now())
			if err != nil {
				return err
			}
			admitted(cs.PeerCertificates, until)
			return nil
		},
	}
}

// Hold ends a session at its admission's end: cut at until, or at a
// change (changed closed) after which check refuses it; a change check
// still passes moves until (Enrol.tla NoExpiredSession and
// RevocationBound; mutants no-expiry-timer, no-cut-on-update). Take
// changed before the check that admitted the session. It returns when
// done is closed or after cut. client/agent's holdAdmission is the same
// loop for a service.
func (m *Identity) Hold(until time.Time, changed <-chan struct{}, check func(now time.Time) (time.Time, error), cut func(), done <-chan struct{}) {
	t := time.NewTimer(time.Until(until))
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			cut()
			return
		case <-changed:
			changed = m.Changed()
			u, cerr := check(time.Now())
			if cerr != nil {
				cut()
				return
			}
			t.Reset(time.Until(u))
		}
	}
}

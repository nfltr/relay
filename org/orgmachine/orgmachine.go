// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package orgmachine is this machine's organisation identity on disk: its
// certificate
// and key, the organisation's root and recovery certificates and the
// issuer's CRL, behind the checks of orgid.Verifier. It serves both
// halves of a session in organisation mode: the relay agent's tcp service
// (agent.Org: Certificate, CheckClient, Changed) and a client that names a
// machine (ClientTLS, CheckServer). The files are what enrolment and
// renewal write (orgenrol, over the relay's mailboxes, through
// WriteFiles, Install, TakeCRL and TakeRotation, each checked by the
// verifier first); Reload takes what another process wrote and signals
// Changed, so open sessions are checked again.
package orgmachine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/internal/orgfiles"
	"github.com/nfltr/relay/org/orgpki"
)

// The files of a machine's directory: orgid's (orgid.Load reads the same
// directory), and the KRL.
const (
	RootFile     = orgid.RootFile      // the organisation's root certificate
	RecoveryFile = orgid.RecoveryFile  // its recovery certificate
	CertFile     = orgid.CertFile      // this machine's certificate, its issuer's, then its SSH host certificate
	KeyFile      = orgid.KeyFile       // its key (PKCS#8 PEM), 0600
	CRLFile      = orgid.CRLFile       // the issuer's newest CRL
	IssuersFile  = orgid.IssuersFile   // the root's CRL of issuers, once one is published
	StatusFile   = orgid.StatusFile    // the issuer's newest signed status: the access rules (TakeStatus)
	KRLFile      = "revoked-hosts.krl" // its OpenSSH KRL (orgpki.HostKRL), 0644: ssh's RevokedHostKeys
)

// HostCertBlock is the PEM type of the SSH host certificate in CertFile
// (orgpki.HostCert, its SSH wire form): one file with the chain, so a
// reader never sees a host certificate of another key than the chain's.
const HostCertBlock = "NFLTR SSH HOST CERTIFICATE"

// Dir is the machine directory under nfltr's config directory (orgid.Dir).
func Dir(configDir string) string { return orgid.Dir(configDir) }

// Machine is the identity read from one directory.
type Machine struct {
	dir string
	mu  sync.Mutex
	// rootMu serialises TakeRotation (the verifier, then root.pem) with
	// Reload's read of root.pem: a Reload between the two would read the
	// old root as a rotation, which the recovery key never signed.
	rootMu  sync.Mutex
	ver     *orgid.Verifier
	orgID   string
	root    []byte // root.pem's certificate, as the verifier took it
	cert    *tls.Certificate
	issuer  *x509.Certificate
	host    *ssh.Certificate // the host certificate of cert
	crl     []byte
	issuers []byte      // issuers.crl, as the verifier took it
	krl     []byte      // orgpki.HostKRL of crl
	rules   orgid.Rules // the access rules of the newest status taken (TakeStatus, status.json)
	changed chan struct{}
	audited chan struct{} // a line written to the audit log (Audited)
	log     *orgaudit.Log // this process's writer of the audit log (audit.go)
}

// Open reads dir. A machine that is not enrolled (no files) is an error:
// organisation mode never runs without it.
func Open(dir string) (*Machine, error) {
	root, err := readCert(filepath.Join(dir, RootFile))
	if err != nil {
		return nil, notEnrolled(dir, err)
	}
	rec, err := readCert(filepath.Join(dir, RecoveryFile))
	if err != nil {
		return nil, notEnrolled(dir, err)
	}
	ver, err := orgid.NewVerifier(root, rec, orgid.Fingerprint(root), orgid.Fingerprint(rec))
	if err != nil {
		return nil, err
	}
	orgID, err := orgid.OrgIDOfRoot(root)
	if err != nil {
		return nil, err
	}
	m := &Machine{dir: dir, ver: ver, orgID: orgID, root: root.Raw, changed: make(chan struct{}), audited: make(chan struct{}, 1)}
	m.log = &orgaudit.Log{Dir: dir, Signer: m.Current, Written: m.wroteAudit}
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
// (orgid.Verifier.TakeRotation: the recovery key's only), a renewed
// certificate or a newer CRL (TakeCRL refuses an older one) is a change:
// Changed's channel closes. A file that does not parse fails it and
// changes nothing; a CRL the verifier refuses is only not taken.
func (m *Machine) Reload(now time.Time) (changed bool, err error) {
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
	chain, cert, err := orgid.ReadPair(m.dir)
	if err != nil {
		return false, err
	}
	if len(cert.Certificate) != 2 {
		return false, fmt.Errorf("%s: want the machine's certificate and its issuer's", CertFile)
	}
	issuer, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		return false, err
	}
	host, err := orgpki.CheckHostCert(hostCertOf(chain), cert.Leaf, issuer)
	if err != nil {
		return false, fmt.Errorf("%s: SSH host certificate: %w", CertFile, err)
	}
	crl, err := os.ReadFile(filepath.Join(m.dir, CRLFile))
	if err != nil {
		return false, err
	}
	issuers, err := os.ReadFile(filepath.Join(m.dir, IssuersFile))
	if errors.Is(err, os.ErrNotExist) {
		issuers, err = nil, nil
	}
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	// The root's CRL of issuers: one the verifier refuses is only not taken.
	newIssuers := issuers != nil && !bytes.Equal(issuers, m.issuers) && m.ver.TakeIssuerCRL(issuers) == nil
	if newIssuers {
		m.issuers = issuers
	}
	newCRL := string(crl) != string(m.crl)
	if newCRL {
		// A CRL that the verifier refuses is not taken, and fails nothing
		// else: after a rotation crl.der is the old root's until the new
		// issuer's arrives, and the renewal into the new issuer must not
		// wait for it (a fleet test with the push withheld found it). The
		// verifier keeps what it held (after a rotation nothing: it admits
		// no one under that issuer, fail closed) until a CRL it takes.
		if err := m.ver.TakeCRL(crl, issuer, now); err != nil {
			newCRL = false
		} else {
			m.crl, m.krl = crl, hostKRL(crl, issuer)
		}
	}
	newCert := m.cert == nil || string(m.cert.Certificate[0]) != string(cert.Certificate[0])
	if newCert {
		m.cert, m.issuer, m.host = &cert, issuer, host
	}
	// The status another process of the machine took (or none yet): one
	// not taken (older, lapsed) changes nothing.
	newStatus := false
	if st, err := os.ReadFile(filepath.Join(m.dir, StatusFile)); err == nil { // #nosec G304 -- a file of the machine's own directory
		newStatus, _ = m.rules.Take(st, m.ver.Root(), m.orgID, now)
	}
	if newCRL || newCert || newIssuers || newStatus {
		m.signal()
	}
	m.mu.Unlock()
	// A KRL that cannot be written now is written at the next Reload;
	// KRL (nfltr cat ssh, nfltr org trust) reports the error.
	_ = m.keepKRL()
	return rotated || newCRL || newCert || newIssuers || newStatus, nil
}

// TakeStatus takes the organisation's signed status from the relay for
// its access rules (orgid.Rules.Take: the root's issuer's, newer only,
// unexpired) and keeps it in status.json; Changed, so open sessions are
// checked again against its rules.
func (m *Machine) TakeStatus(msg []byte, now time.Time) (bool, error) {
	took, err := m.rules.Take(msg, m.ver.Root(), m.orgID, now)
	if !took || err != nil {
		return took, err
	}
	if err := orgfiles.Write(filepath.Join(m.dir, StatusFile), msg, 0o600); err != nil {
		return true, err
	}
	m.mu.Lock()
	m.signal()
	m.mu.Unlock()
	return true, nil
}

// signal closes Changed's channel. Callers hold mu.
func (m *Machine) signal() {
	if m.changed != nil {
		close(m.changed)
	}
	m.changed = make(chan struct{})
}

// takeRoot takes der as the organisation's root when it is not the one
// held: a rotation (Enrol.tla TakeRoot). The CRLs under the old root go
// with it, so the CRL is taken again (the new issuer's). It signals
// Changed: sessions under the old root are checked again and cut.
func (m *Machine) takeRoot(der []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bytes.Equal(der, m.root) {
		return false, nil
	}
	if err := m.ver.TakeRotation(der); err != nil {
		return false, err
	}
	m.root, m.crl, m.issuers = der, nil, nil
	m.signal()
	return true, nil
}

// TakeRotation takes the organisation's new root (the recovery key's
// certificate of it, from the relay) and keeps it in root.pem. The
// certificate this machine holds is then under the old root: RenewDue says
// renew at once (Enrol.tla Request after a rotation).
func (m *Machine) TakeRotation(der []byte) (bool, error) {
	m.rootMu.Lock()
	defer m.rootMu.Unlock()
	taken, err := m.takeRoot(der)
	if err != nil || !taken {
		return taken, err
	}
	return true, orgfiles.Write(filepath.Join(m.dir, RootFile), certPEM(der), 0o600)
}

// TakeCRL takes the issuer's CRL from the relay when the verifier does
// (signed by an issuer under the trusted root, newer than the one held,
// not lapsed) and keeps it in crl.der; Changed. The CRL held already is
// no change.
func (m *Machine) TakeCRL(crl, issuerDER []byte, now time.Time) (bool, error) {
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return false, err
	}
	if taken, err := m.takeCRL(crl, issuer, now); !taken || err != nil {
		return taken, err
	}
	return true, m.keepKRL()
}

// TakeIssuerCRL takes the root's CRL of issuers from the relay when the
// verifier does (the root's, newer than the one held) and keeps it in
// issuers.crl; Changed, so sessions under an issuer it lists are cut. The
// one held already is no change.
func (m *Machine) TakeIssuerCRL(der []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bytes.Equal(der, m.issuers) {
		return false, nil
	}
	if err := m.ver.TakeIssuerCRL(der); err != nil {
		return false, err
	}
	if err := orgfiles.Write(filepath.Join(m.dir, IssuersFile), der, 0o600); err != nil {
		return false, err
	}
	m.issuers = der
	m.signal()
	return true, nil
}

func (m *Machine) takeCRL(crl []byte, issuer *x509.Certificate, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bytes.Equal(crl, m.crl) {
		return false, nil
	}
	if err := m.ver.TakeCRL(crl, issuer, now); err != nil {
		return false, err
	}
	if err := orgfiles.Write(filepath.Join(m.dir, CRLFile), crl, 0o600); err != nil {
		return false, err
	}
	m.crl, m.krl = crl, hostKRL(crl, issuer)
	m.signal()
	return true, nil
}

// listed: crl (one the verifier took, or nil) lists leaf's serial.
func listed(crl []byte, leaf *x509.Certificate) bool {
	c, err := x509.ParseRevocationList(crl)
	return err == nil && slices.ContainsFunc(c.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool {
		return e.SerialNumber.Cmp(leaf.SerialNumber) == 0
	})
}

// hostKRL is orgpki.HostKRL of a CRL the verifier took (so it parses),
// nil if not.
func hostKRL(crl []byte, issuer *x509.Certificate) []byte {
	k, _ := orgpki.HostKRL(crl, issuer)
	return k
}

// keepKRL writes the KRL of the CRL held into KRLFile (atomically, 0644:
// a KRL is public) unless the file holds the same or a newer one: the
// machine's processes all keep it, and none takes it back to an older
// CRL.
func (m *Machine) keepKRL() error {
	m.mu.Lock()
	k := m.krl
	m.mu.Unlock()
	path := filepath.Join(m.dir, KRLFile)
	newer := func() bool {
		held, _ := os.ReadFile(path) // #nosec G304 -- a file of the machine's own directory
		return orgpki.KRLDate(held) < orgpki.KRLDate(k)
	}
	if k == nil || !newer() {
		return nil
	}
	unlock, err := orgfiles.Lock(filepath.Join(m.dir, "krl.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if !newer() {
		return nil
	}
	return orgfiles.Write(path, k, 0o644) // #nosec G306 -- a KRL is public, read by ssh
}

// KRL is the path of this machine's KRL of the CRL it holds, written
// first when it is missing or older (ssh refuses every host when its
// RevokedHostKeys file is missing).
func (m *Machine) KRL() (string, error) {
	if err := m.keepKRL(); err != nil {
		return "", fmt.Errorf("the organisation's SSH revocation list: %w", err)
	}
	path := filepath.Join(m.dir, KRLFile)
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("the organisation's SSH revocation list: %w", err)
	}
	return path, nil
}

// CRLStale is orgid.Verifier.CRLStale of the machine's CRL: a warning
// once it is orgid.CRLWarnAge old.
func (m *Machine) CRLStale(now time.Time) error { return m.ver.CRLStale(now) }

// OrgID is the organisation's id.
func (m *Machine) OrgID() string { return m.orgID }

// Dir is the machine's directory.
func (m *Machine) Dir() string { return m.dir }

// RenewDue is when this machine renews: at half the life of its
// certificate or of its SSH host certificate, whichever ends first (the
// host certificate's orgpki.HostLife is shorter; a renewal brings both),
// up to 10 % of it later (spread by the serial, so a fleet does not renew
// at once; lane SEAMLESS), or now when the certificate is not under the
// root it trusts (after a rotation; Enrol.tla Request, Due;
// spec/enrol/CertRide.tla Ask), or listed in the CRL it holds (a move
// order revoked it: the renewal brings its new groups, relay-server
// spec/GroupMirror.tla Pickup; mutant no-renew-when-moved).
func (m *Machine) RenewDue(now time.Time) time.Time {
	m.mu.Lock()
	leaf, issuer, host, crl := m.cert.Leaf, m.issuer, m.host, m.crl
	m.mu.Unlock()
	if m.ver.Issued(leaf, issuer, now) != nil || listed(crl, leaf) {
		return now
	}
	spread := new(big.Int).Mod(leaf.SerialNumber, big.NewInt(1000)).Int64() // 0..999
	due := func(from, to time.Time) time.Time {
		life := to.Sub(from)
		return from.Add(life/2 + life/10*time.Duration(spread)/1000)
	}
	d := due(leaf.NotBefore, leaf.NotAfter)
	hostFrom := time.Unix(int64(host.ValidAfter), 0) // #nosec G115 -- a checked host certificate's times (CheckHostCert)
	hostTo := time.Unix(int64(host.ValidBefore), 0)  // #nosec G115 -- likewise
	if h := due(hostFrom, hostTo); h.Before(d) {     // mutant renew-machine-only
		d = h
	}
	return d
}

// Root is the organisation's root certificate this machine holds.
func (m *Machine) Root() (*x509.Certificate, error) {
	m.mu.Lock()
	der := m.root
	m.mu.Unlock()
	return x509.ParseCertificate(der)
}

// Current is this machine's certificate and its private key.
func (m *Machine) Current() (*x509.Certificate, ed25519.PrivateKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, _ := m.cert.PrivateKey.(ed25519.PrivateKey)
	return m.cert.Leaf, key
}

// Issuer is the issuer certificate of this machine's chain: whom its
// audit lines are sealed to (orgpki.SealAudit).
func (m *Machine) Issuer() *x509.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.issuer
}

// HostSigner is this machine's SSH host key: its current key, presenting
// its host certificate (nfltr cat serve --ssh). Read once per SSH handshake, so
// a renewal serves the next connection.
func (m *Machine) HostSigner() (ssh.Signer, error) {
	m.mu.Lock()
	key, host := m.cert.PrivateKey, m.host
	m.mu.Unlock()
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(host, s)
}

// HostCA is the organisation's SSH host CA as this machine trusts it now:
// the issuer's key, after this machine's own chain passed the full check
// (the root, the issuer, NotAfter, the issuer's CRL current and not listing
// it). nfltr org trust writes it into known_hosts.
func (m *Machine) HostCA(now time.Time) (ssh.PublicKey, error) {
	m.mu.Lock()
	leaf, issuer := m.cert.Leaf, m.issuer
	m.mu.Unlock()
	if _, err := m.CheckServer([]*x509.Certificate{leaf, issuer}, leaf.Subject.CommonName, now); err != nil {
		return nil, fmt.Errorf("this machine's own certificate: %w", err)
	}
	return orgpki.HostCA(issuer)
}

// renewLock serialises the writers of the machine's key and certificate.
const renewLock = "renew.lock"

// LockRenewal serialises the renewals of this machine's processes (nfltr
// node and nfltr up may both run): the holder reloads, checks RenewDue
// again, then renews.
func (m *Machine) LockRenewal() (unlock func(), err error) {
	return orgfiles.Lock(filepath.Join(m.dir, renewLock))
}

// ErrNotForKey: an answer certifies another key than the one this machine
// made for the request (a relay handing back an old answer under the new
// request's id; Enrol.tla MachineHoldsItsKey, mutant install-stale-answer).
var ErrNotForKey = errors.New("the certificate is not for the key this machine made for the request")

// hostCertOf is the SSH host certificate's block of a CertFile, nil if
// none.
func hostCertOf(chain []byte) []byte {
	for b, rest := pem.Decode(chain); b != nil; b, rest = pem.Decode(rest) {
		if b.Type == HostCertBlock {
			return b.Bytes
		}
	}
	return nil
}

// Checked checks an issuer's answer: a certificate for key, under the root
// ver trusts, not expired, naming name when given, and its SSH host
// certificate (orgpki.CheckHostCert).
func Checked(ver *orgid.Verifier, certDER, issuerDER, hostCert []byte, key ed25519.PrivateKey, name string, now time.Time) error {
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return err
	}
	if pub, ok := leaf.PublicKey.(ed25519.PublicKey); !ok || !pub.Equal(key.Public()) {
		return ErrNotForKey
	}
	if err := ver.Issued(leaf, issuer, now); err != nil {
		return err
	}
	if name != "" && leaf.Subject.CommonName != name {
		return fmt.Errorf("the certificate names %q, not this machine %q", leaf.Subject.CommonName, name)
	}
	if _, err := orgpki.CheckHostCert(hostCert, leaf, issuer); err != nil {
		return fmt.Errorf("SSH host certificate: %w", err)
	}
	return nil
}

// Install keeps a renewal: the certificate for key (Checked: this
// machine's name, the trusted root), written with its key, then reloaded.
// Callers hold LockRenewal.
func (m *Machine) Install(certDER, issuerDER, hostCert []byte, key ed25519.PrivateKey, now time.Time) error {
	cur, _ := m.Current()
	if err := Checked(m.ver, certDER, issuerDER, hostCert, key, cur.Subject.CommonName, now); err != nil {
		return err
	}
	if err := writeIdentity(m.dir, certDER, issuerDER, hostCert, key); err != nil {
		return err
	}
	_, err := m.Reload(now)
	return err
}

// writeIdentity replaces the key and the certificate chain with the host
// certificate as one pair (orgid.Pair: write-ahead, so a writer stopped at
// any step leaves a pair; spec/pair/MachinePair.tla, lane CERTATOMIC).
// Callers hold renew.lock.
func writeIdentity(dir string, certDER, issuerDER, hostCert []byte, key ed25519.PrivateKey) error {
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	host := pem.EncodeToMemory(&pem.Block{Type: HostCertBlock, Bytes: hostCert})
	return orgid.Pair(dir).Write(slices.Concat(certPEM(certDER), certPEM(issuerDER), host), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Enrolment is what a machine's enrolment writes into its directory.
type Enrolment struct {
	Root, Recovery, Cert, Issuer, CRL []byte // DER
	Issuers                           []byte // DER: the root's CRL of issuers (nil: none published)
	HostCert                          []byte // SSH wire form
	Key                               ed25519.PrivateKey
}

// WriteFiles writes a new enrolment into dir (made 0700), the certificate
// and key last.
func WriteFiles(dir string, e Enrolment) error {
	if err := os.MkdirAll(dir, 0o700); err != nil { // nosemgrep: incorrect-default-permission -- a directory needs x; 0o700 is owner-only
		return err
	}
	unlock, err := orgfiles.Lock(filepath.Join(dir, renewLock)) // a renewal of a machine already enrolled may run
	if err != nil {
		return err
	}
	defer unlock()
	for _, f := range []struct {
		name string
		data []byte
	}{{RootFile, certPEM(e.Root)}, {RecoveryFile, certPEM(e.Recovery)}, {CRLFile, e.CRL}} {
		if err := orgfiles.Write(filepath.Join(dir, f.name), f.data, 0o600); err != nil {
			return err
		}
	}
	if e.Issuers != nil {
		if err := orgfiles.Write(filepath.Join(dir, IssuersFile), e.Issuers, 0o600); err != nil {
			return err
		}
	}
	return writeIdentity(dir, e.Cert, e.Issuer, e.HostCert, e.Key)
}

// Watch reloads every interval until stop is closed; a failed reload
// changes nothing (the verifier fails closed once its CRL lapses).
// ponytail: a stat-free reread on a timer; orgenrol's CRL push replaces it.
func (m *Machine) Watch(every time.Duration, stop <-chan struct{}) {
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
func (m *Machine) Certificate() (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cert, nil
}

// Changed is closed at the next change (agent.Org).
func (m *Machine) Changed() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.changed
}

// errNoChain: a peer presented no certificate, or no issuer after it.
var errNoChain = errors.New("the peer presented no organisation certificate and issuer")

// CheckClient admits a client to one of services on this machine
// (agent.Org): its certificate checked (chain, NotAfter, CRL), then a rule
// of the organisation's access rules (orgid.Rules.Admit, TakeStatus), else
// a grant it presented (orgid.AdmitClient).
func (m *Machine) CheckClient(certs []*x509.Certificate, services []string, now time.Time) (time.Time, error) {
	m.mu.Lock()
	leaf := m.cert.Leaf
	m.mu.Unlock()
	return orgid.AdmitClient(m.ver, &m.rules, certs, orgid.Checked{Name: leaf.Subject.CommonName, Groups: leaf.Subject.OrganizationalUnit}, services, now)
}

// CheckServer checks a server's certificates as the machine name.
func (m *Machine) CheckServer(certs []*x509.Certificate, name string, now time.Time) (time.Time, error) {
	if len(certs) != 2 {
		return time.Time{}, errNoChain
	}
	id, err := m.ver.Check(certs[0], certs[1], orgid.Peer{Name: name}, now)
	return id.Until, err
}

// CheckServerGroup checks a server's certificates as any machine of
// group: chain, NotAfter, CRL and the group in its OU, no name (a group
// dial, <service>@<group>: BIND:org.group).
func (m *Machine) CheckServerGroup(certs []*x509.Certificate, group string, now time.Time) (time.Time, error) {
	if len(certs) != 2 {
		return time.Time{}, errNoChain
	}
	id, err := m.ver.Check(certs[0], certs[1], orgid.Peer{Group: group}, now)
	return id.Until, err
}

// ClientTLS is the TLS client of organisation mode to the machine name:
// TLS 1.3, ServerName its DNS name in the organisation, this machine's
// certificate as the client's, and CheckServer (not crypto/tls's CA
// check: the CRL and the name are the verifier's), whose until goes to
// admitted. No pin, no fallback.
func (m *Machine) ClientTLS(name string, admitted func(certs []*x509.Certificate, until time.Time)) *tls.Config {
	return m.clientTLS(orgid.MachineDNS(name, m.orgID), func(certs []*x509.Certificate, now time.Time) (time.Time, error) {
		until, err := m.CheckServer(certs, name, now)
		if err != nil {
			return until, fmt.Errorf("the server is not machine %s of the organisation: %w", name, err)
		}
		return until, nil
	}, admitted)
}

// GroupClientTLS is ClientTLS to any machine of group (CheckServerGroup):
// a group dial, whose server is whichever instance the relay picked.
func (m *Machine) GroupClientTLS(group string, admitted func(certs []*x509.Certificate, until time.Time)) *tls.Config {
	return m.clientTLS("", func(certs []*x509.Certificate, now time.Time) (time.Time, error) {
		until, err := m.CheckServerGroup(certs, group, now)
		if err != nil {
			return until, fmt.Errorf("the server is not a machine of group %s: %w", group, err)
		}
		return until, nil
	}, admitted)
}

func (m *Machine) clientTLS(serverName string, check func([]*x509.Certificate, time.Time) (time.Time, error), admitted func([]*x509.Certificate, time.Time)) *tls.Config {
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
// still passes moves until (spec/enrol/Enrol.tla NoExpiredSession and
// RevocationBound; mutants no-expiry-timer, no-cut-on-update). Take
// changed before the check that admitted the session. It returns when
// done is closed or after cut. orgid.Identity.Hold is the same loop in
// the relay SDK, which client/agent runs for a service.
func (m *Machine) Hold(until time.Time, changed <-chan struct{}, check func(now time.Time) (time.Time, error), cut func(), done <-chan struct{}) {
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

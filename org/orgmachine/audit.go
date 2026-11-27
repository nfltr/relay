// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine

// The machine's audit log (nfltr docs/decisions/service-access-2026-11-25.md
// "SA5: the record, its check, the names"): every organisation session a
// process of this machine admits is two signed, numbered lines of
// AuditFile (client/orgaudit), its open and its close, under one file
// lock for every process of the machine, so the machine has one
// sequence. orgenrol's keeper ships the lines to the issuer.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/internal/orgfiles"
)

// AuditFile is the machine's audit log, 0600; auditLock its writers' lock.
const (
	AuditFile = "audit.jsonl"
	auditLock = "audit.lock"
)

// Audit records a session certs opened to service (agent.OrgAuditor):
// its open line now, its close line at the end it returns. A line not
// written is logged; the session goes on (its absence is the machine's
// only loss: the sequence has no gap where nothing was written).
func (m *Machine) Audit(certs []*x509.Certificate, service string, services []string, opened time.Time) func(orgaudit.End) {
	m.mu.Lock()
	leaf := m.cert.Leaf
	m.mu.Unlock()
	self := orgid.Checked{Name: leaf.Subject.CommonName, Groups: leaf.Subject.OrganizationalUnit}
	s := orgaudit.Session{ID: randomHex(8), Service: service, Who: whoOf(certs[0]), Opened: opened.UTC(),
		By: orgid.AdmittedBy(m.ver, &m.rules, certs, self, services, opened)}
	m.writeAudit(s.Open())
	return func(e orgaudit.End) {
		e.Closed = e.Closed.UTC()
		m.writeAudit(s.Close(e))
	}
}

func (m *Machine) writeAudit(r orgaudit.Record) {
	cert, key := m.Current()
	if err := AppendAudit(m.dir, r, cert, key, time.Now()); err != nil {
		slog.Default().Warn("org: a session's audit record was not written", "session", r.Session, "kind", r.Kind, "error", err)
		return
	}
	select {
	case m.audited <- struct{}{}:
	default:
	}
}

// Audited has a value after a line this process wrote to the audit log,
// kept until taken: the keeper ships it then.
func (m *Machine) Audited() <-chan struct{} { return m.audited }

// whoOf is the client as its certificate names it.
func whoOf(leaf *x509.Certificate) orgaudit.Who {
	w := orgaudit.Who{Name: leaf.Subject.CommonName, Groups: leaf.Subject.OrganizationalUnit}
	if len(leaf.EmailAddresses) == 1 {
		w.Person = leaf.EmailAddresses[0]
	}
	return w
}

// AppendAudit appends r to dir's audit log, signed by key (cert's), as
// the line after the log's last; a log's first line starts a new log id.
// A torn last line (a crash in its write) is cut first.
func AppendAudit(dir string, r orgaudit.Record, cert *x509.Certificate, key ed25519.PrivateKey, now time.Time) error {
	unlock, err := orgfiles.Lock(filepath.Join(dir, auditLock))
	if err != nil {
		return err
	}
	defer unlock()
	f, err := os.OpenFile(filepath.Join(dir, AuditFile), os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- the machine's own directory
	if err != nil {
		return err
	}
	defer f.Close()
	last, end, err := lastLine(f)
	if err != nil {
		return err
	}
	if err := f.Truncate(end); err != nil {
		return err
	}
	s := orgaudit.Signing{Log: randomHex(16), Seq: 1, Machine: cert.Subject.CommonName, Cert: cert, Key: key, At: now}
	// A last line that does not verify (edited) starts a new log: every
	// reader reports it ("new log"), and the machine goes on auditing.
	if lr, err := orgaudit.Parse(last); last != nil && err == nil {
		s.Log, s.Seq, s.Prev = lr.Log, lr.Seq+1, orgaudit.Hash(last)
	}
	line, err := orgaudit.Line(r, s)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(append(line, '\n'), end); err != nil {
		return err
	}
	return f.Sync()
}

// auditTail bounds the read for the last line: a line is under 2 KiB.
const auditTail = 64 << 10

// lastLine is f's last complete line (nil: none) and where complete lines
// end.
func lastLine(f *os.File) ([]byte, int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	off := max(fi.Size()-auditTail, 0)
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, 0, err
	}
	i := bytes.LastIndexByte(buf, '\n')
	if i < 0 {
		if off > 0 {
			return nil, 0, errors.New("the audit log's last line is too long")
		}
		return nil, 0, nil
	}
	buf = buf[:i]
	return buf[bytes.LastIndexByte(buf, '\n')+1:], off + int64(i) + 1, nil
}

// LastAudit is dir's audit log's last line, nil when it has none.
func LastAudit(dir string) ([]byte, error) {
	f, err := os.Open(filepath.Join(dir, AuditFile)) // #nosec G304 -- the machine's own directory
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	last, _, err := lastLine(f)
	return last, err
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

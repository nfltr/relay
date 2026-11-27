// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine

// The machine's audit log (client/orgaudit Log, nfltr
// docs/decisions/service-access-2026-11-25.md "SA5"): every organisation
// session a process of this machine admits is two signed, numbered lines
// of orgaudit.LogFile, its open and its close; orgenrol's keeper ships
// them to the issuer, closes a gone process's sessions (CloseLost) and
// rotates the file (orgaudit.Rotate): spec/AuditLog.tla.

import (
	"crypto/x509"
	"time"

	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/client/orgid"
)

// Audit records a session certs opened to service (agent.OrgAuditor):
// its open line now, its close line at the end it returns.
func (m *Machine) Audit(certs []*x509.Certificate, service string, services []string, opened time.Time) func(orgaudit.End) {
	m.mu.Lock()
	leaf := m.cert.Leaf
	m.mu.Unlock()
	self := orgid.Checked{Name: leaf.Subject.CommonName, Groups: leaf.Subject.OrganizationalUnit}
	return m.log.Audit(orgaudit.Session{Service: service, Who: orgaudit.WhoOf(certs[0]), Opened: opened,
		By: orgid.AdmittedBy(m.ver, &m.rules, certs, self, services, opened)})
}

// CloseLost closes the sessions of the machine's other processes that
// ended without closing them (orgaudit.Log.CloseLost).
func (m *Machine) CloseLost(now time.Time) (int, error) { return m.log.CloseLost(now) }

// Audited has a value after a line this process wrote to the audit log,
// kept until taken: the keeper ships it then.
func (m *Machine) Audited() <-chan struct{} { return m.audited }

func (m *Machine) wroteAudit() {
	select {
	case m.audited <- struct{}{}:
	default:
	}
}

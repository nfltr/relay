// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine

// The machine's audit log (nfltr docs/decisions/service-access-2026-11-25.md
// "SA5: the record, its check, the names"): every organisation session a
// process of this machine admits is two signed, numbered lines of
// AuditFile (client/orgaudit), its open and its close, under one file
// lock for every process of the machine, so the machine has one
// sequence. orgenrol's keeper ships the lines to the issuer.
//
// A killed process's sessions are closed by the machine's next process
// (CloseLost), and the file is rotated past what the issuer holds
// (RotateAudit): spec/AuditLog.tla.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/internal/orgfiles"
)

// AuditFile is the machine's audit log, 0600, under its writers' lock.
const (
	AuditFile = "sessions.jsonl"
	auditLock = "sessions.lock"
	ownersDir = "sessions.owners" // per process: <id> its open sessions, <id>.lock held for its life
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
	m.own.add(m.dir, s.ID) // before the open line (AuditLog.tla Intent; mutant open-before-intent)
	m.writeAudit(s.Open())
	return func(e orgaudit.End) {
		e.Closed = e.Closed.UTC()
		m.writeAudit(s.Close(e))
		m.own.remove(m.dir, s.ID) // after the close line (Forget)
	}
}

// owner is this process's owner file: the sessions it opened and has not
// closed, under a lock it holds for its life, so that another process of
// the machine can tell when it is gone (CloseLost). A file not written is
// logged: a session it misses is only not closed if this process dies.
type owner struct {
	mu      sync.Mutex
	id      string
	open    map[string]bool
	release func() // the owner lock's
}

func (o *owner) add(dir, session string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.id == "" {
		id := randomHex(8)
		if err := os.MkdirAll(filepath.Join(dir, ownersDir), 0o700); err != nil { // nosemgrep: incorrect-default-permission -- the machine's private directory
			slog.Default().Warn("org: the audit's owner file was not made", "error", err)
			return
		}
		unlock, err := orgfiles.TryLock(filepath.Join(dir, ownersDir, id+".lock"))
		if err != nil {
			slog.Default().Warn("org: the audit's owner file was not made", "error", err)
			return
		}
		// ponytail: held until the process exits (flock goes with it); a Machine has no Close.
		o.id, o.open, o.release = id, map[string]bool{}, unlock
	}
	o.open[session] = true
	o.write(dir)
}

func (o *owner) remove(dir, session string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.open[session] {
		delete(o.open, session)
		o.write(dir)
	}
}

func (o *owner) write(dir string) {
	data, _ := json.Marshal(slices.Sorted(maps.Keys(o.open)))
	if err := orgfiles.Write(filepath.Join(dir, ownersDir, o.id), data, 0o600); err != nil {
		slog.Default().Warn("org: the audit's owner file was not written", "error", err)
	}
}

// CloseLost closes the sessions of the machine's processes that ended
// without closing them (killed, crashed): an owner file whose lock it can
// take is a gone process's, and under the log's lock each session it lists
// whose open is in the log and whose close is not gets a close line,
// ReasonLost at now, then the owner file goes (spec/AuditLog.tla Recover,
// RecoverDone; mutants recover-live, recover-no-log-check). It returns the
// lines written; orgenrol's keeper runs it every round.
func (m *Machine) CloseLost(now time.Time) (int, error) {
	ents, err := os.ReadDir(filepath.Join(m.dir, ownersDir))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	m.own.mu.Lock()
	self := m.own.id
	m.own.mu.Unlock()
	n := 0
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".lock")
		if !ok || id == self {
			continue
		}
		k, err := m.closeOwner(id, now)
		if n += k; err != nil {
			return n, err
		}
	}
	return n, nil
}

func (m *Machine) closeOwner(id string, now time.Time) (int, error) {
	path := filepath.Join(m.dir, ownersDir, id)
	unlock, err := orgfiles.TryLock(path + ".lock")
	if errors.Is(err, orgfiles.ErrLocked) {
		return 0, nil // its process runs
	}
	if err != nil {
		return 0, err
	}
	var ids []string
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- the machine's own directory
		_ = json.Unmarshal(data, &ids) // a torn file lists nothing: its sessions stay open, shown so
	}
	cert, key := m.Current()
	n := 0
	err = withAudit(m.dir, func(f *os.File) error {
		open, _, err := scanOpen(f)
		if err != nil {
			return err
		}
		for _, sid := range ids {
			r, ok := open[sid]
			if !ok {
				continue // closed, or never opened (killed before its open line)
			}
			s := orgaudit.Session{ID: r.Session, Service: r.Service, Who: r.Who, By: r.By, Opened: r.Opened}
			if err := appendLine(f, s.Close(orgaudit.End{Closed: now.UTC(), Reason: orgaudit.ReasonLost}), cert, key, now); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err == nil {
		if err = os.Remove(path); errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	unlock()
	if err == nil {
		_ = os.Remove(path + ".lock")
	}
	if n > 0 {
		select {
		case m.audited <- struct{}{}:
		default:
		}
	}
	return n, err
}

// scanOpen reads f's complete lines: the sessions opened and not closed,
// their open lines' offsets, and where the complete lines end.
func scanOpen(f *os.File) (map[string]orgaudit.Record, map[string]int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	open, at := map[string]orgaudit.Record{}, map[string]int64{}
	var off int64
	for l := range bytes.Lines(data) {
		if !bytes.HasSuffix(l, []byte("\n")) {
			break // a torn last line
		}
		if r, err := orgaudit.Parse(l[:len(l)-1]); err == nil {
			switch r.Kind {
			case orgaudit.KindOpen:
				open[r.Session], at[r.Session] = r, off
			case orgaudit.KindClose:
				delete(open, r.Session)
				delete(at, r.Session)
			}
		}
		off += int64(len(l))
	}
	return open, at, nil
}

// RotateAudit drops the head of dir's audit log up to acked (the bytes
// of it the issuer acknowledged) once the file is over size bytes,
// keeping the last line (the next chains to it: the log goes on; mutant
// rotate-all) and every line from the first open whose close is not
// written (CloseLost reads it; mutant rotate-drops-open); never past
// acked (mutant rotate-unacked) (spec/AuditLog.tla Rotate: OneLog,
// EveryOpenCloses, NothingLost). It returns the bytes dropped; moved is
// told them first, under the log's lock, so the caller's offsets move
// back before the file is replaced: a crash between ships acknowledged
// lines again (the issuer holds them: no line twice), never skips one.
func RotateAudit(dir string, acked, size int64, moved func(cut int64) error) (int64, error) {
	var cut int64
	err := withAudit(dir, func(f *os.File) error {
		fi, err := f.Stat()
		if err != nil || fi.Size() <= size {
			return err
		}
		last, end, err := lastLine(f)
		if err != nil || last == nil {
			return err
		}
		_, at, err := scanOpen(f)
		if err != nil {
			return err
		}
		cut = min(acked, end-int64(len(last))-1)
		for _, o := range at {
			cut = min(cut, o)
		}
		if cut <= 0 {
			cut = 0
			return nil
		}
		buf := make([]byte, end-cut)
		if _, err := f.ReadAt(buf, cut); err != nil && err != io.EOF {
			return err
		}
		if err := moved(cut); err != nil {
			return err
		}
		return orgfiles.Write(filepath.Join(dir, AuditFile), buf, 0o600)
	})
	if err != nil {
		return 0, err
	}
	return cut, nil
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
	return withAudit(dir, func(f *os.File) error { return appendLine(f, r, cert, key, now) })
}

// withAudit runs fn on dir's audit log under its lock.
func withAudit(dir string, fn func(*os.File) error) error {
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
	return fn(f)
}

// appendLine is AppendAudit's under the lock.
func appendLine(f *os.File, r orgaudit.Record, cert *x509.Certificate, key ed25519.PrivateKey, now time.Time) error {
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

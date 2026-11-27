// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgaudit

// A machine's audit log in its directory (nfltr
// docs/decisions/service-access-2026-11-25.md "SA5"): every organisation
// session a process of the machine serves is two lines of LogFile, its
// open and its close, under one file lock for every process of the
// machine, so the machine has one sequence. Both serving identities write
// it: relay org orgmachine.Machine (nfltr's) and client/orgid.Identity
// (the SDK's); relay org orgenrol's keeper ships it to the issuer.
//
// A killed process's sessions are closed by the machine's next process
// (CloseLost), and the file is rotated past what the issuer holds
// (Rotate): spec/AuditLog.tla.

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
)

// The files of the log in the machine's directory.
const (
	LogFile   = "sessions.jsonl"  // the lines, 0600
	logLock   = "sessions.lock"   // its writers' lock
	OwnersDir = "sessions.owners" // per process: <id> its open sessions, <id>.lock held for its life
)

// Log is one process's writer of the audit log of the machine directory
// Dir. Each line is signed by Signer's certificate's key, read at the
// write (a renewal signs the next line); Written, when set, is told after
// each line this process wrote. A Log keeps the process's owner file:
// the sessions it opened and has not closed, under a lock it holds for
// its life, so that another process of the machine can tell when it is
// gone (CloseLost). A line or owner file not written is logged; the
// session goes on (a missing line is the machine's only loss: the
// sequence has no gap where nothing was written).
type Log struct {
	Dir     string
	Signer  func() (*x509.Certificate, ed25519.PrivateKey)
	Written func()

	mu      sync.Mutex
	id      string
	open    map[string]bool
	release func() // the owner lock's
}

// Audit writes s's open line now (its ID made when empty) and returns the
// writer of its close line.
func (l *Log) Audit(s Session) (end func(End)) {
	if s.ID == "" {
		s.ID = randomHex(8)
	}
	s.Opened = s.Opened.UTC()
	// The owner file lists it before the open line (AuditLog.tla Intent,
	// OpenLine; mutant open-before-intent) and forgets it after the close
	// line (CloseLine, Forget), each pair under one hold of the log's lock.
	l.line(s.Open(), func() { l.add(s.ID) }, nil)
	return func(e End) {
		e.Closed = e.Closed.UTC()
		l.line(s.Close(e), nil, func() { l.remove(s.ID) })
	}
}

// line appends r under the log's lock, with before and after (when set)
// run under the same hold.
func (l *Log) line(r Record, before, after func()) {
	cert, key := l.Signer()
	err := withLog(l.Dir, func(f *os.File) error {
		if before != nil {
			before()
		}
		if after != nil {
			defer after()
		}
		if cert == nil || key == nil {
			return errors.New("no Ed25519 certificate and key to sign it")
		}
		seq, err := appendLine(f, r, cert, key, time.Now())
		if err == nil {
			l.trace(r.Kind, r.Session, "", seq)
		}
		return err
	})
	if err != nil {
		slog.Default().Warn("org: a session's audit record was not written", "session", r.Session, "kind", r.Kind, "error", err)
		return
	}
	if l.Written != nil {
		l.Written()
	}
}

// WhoOf is the client as its certificate names it.
func WhoOf(leaf *x509.Certificate) Who {
	w := Who{Name: leaf.Subject.CommonName, Groups: leaf.Subject.OrganizationalUnit}
	if len(leaf.EmailAddresses) == 1 {
		w.Person = leaf.EmailAddresses[0]
	}
	return w
}

// CloseLost closes the sessions of the machine's processes that ended
// without closing them (killed, crashed): an owner file whose lock it can
// take is a gone process's, and under the log's lock each session it lists
// whose open is in the log and whose close is not gets a close line,
// ReasonLost at now, then the owner file goes (spec/AuditLog.tla Recover,
// RecoverDone; mutants recover-live, recover-no-log-check). It returns the
// lines written; relay org orgenrol's keeper runs it every round.
func (l *Log) CloseLost(now time.Time) (int, error) {
	ents, err := os.ReadDir(filepath.Join(l.Dir, OwnersDir))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	l.mu.Lock()
	self := l.id
	l.mu.Unlock()
	n := 0
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".lock")
		if !ok || id == self {
			continue
		}
		k, err := l.closeOwner(id, now)
		if n += k; err != nil {
			return n, err
		}
	}
	return n, nil
}

func (l *Log) closeOwner(id string, now time.Time) (int, error) {
	path := filepath.Join(l.Dir, OwnersDir, id)
	unlock, err := tryLockFile(path + ".lock")
	if errors.Is(err, errLocked) {
		return 0, nil // its process runs
	}
	if err != nil {
		return 0, err
	}
	var ids []string
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- the machine's own directory
		_ = json.Unmarshal(data, &ids) // a torn file lists nothing: its sessions stay open, shown so
	}
	cert, key := l.Signer()
	n := 0
	err = withLog(l.Dir, func(f *os.File) error {
		open, _, err := scanOpen(f)
		if err != nil {
			return err
		}
		for _, sid := range ids {
			r, ok := open[sid]
			if !ok {
				continue // closed, or never opened (killed before its open line)
			}
			s := Session{ID: r.Session, Service: r.Service, Who: r.Who, By: r.By, Opened: r.Opened}
			seq, err := appendLine(f, s.Close(End{Closed: now.UTC(), Reason: ReasonLost}), cert, key, now)
			if err != nil {
				return err
			}
			l.trace("lost", sid, id, seq)
			n++
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		l.trace("recovered", "", id, 0)
		return nil
	})
	unlock()
	if err == nil {
		_ = os.Remove(path + ".lock")
	}
	if n > 0 && l.Written != nil {
		l.Written()
	}
	return n, err
}

// Append appends r to dir's audit log, signed by key (cert's), as the
// line after the log's last; a log's first line starts a new log id. A
// torn last line (a crash in its write) is cut first.
func Append(dir string, r Record, cert *x509.Certificate, key ed25519.PrivateKey, now time.Time) error {
	return withLog(dir, func(f *os.File) error { _, err := appendLine(f, r, cert, key, now); return err })
}

// withLog runs fn on dir's audit log under its lock.
func withLog(dir string, fn func(*os.File) error) error {
	unlock, err := lockFile(filepath.Join(dir, logLock))
	if err != nil {
		return err
	}
	defer unlock()
	f, err := os.OpenFile(filepath.Join(dir, LogFile), os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- the machine's own directory
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}

// Last is dir's audit log's last line, nil when it has none.
func Last(dir string) ([]byte, error) {
	f, err := os.Open(filepath.Join(dir, LogFile)) // #nosec G304 -- the machine's own directory
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

func (l *Log) add(session string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.id == "" {
		id := randomHex(8)
		if err := os.MkdirAll(filepath.Join(l.Dir, OwnersDir), 0o700); err != nil { // nosemgrep: incorrect-default-permission -- the machine's private directory
			slog.Default().Warn("org: the audit's owner file was not made", "error", err)
			return
		}
		unlock, err := tryLockFile(filepath.Join(l.Dir, OwnersDir, id+".lock"))
		if err != nil {
			slog.Default().Warn("org: the audit's owner file was not made", "error", err)
			return
		}
		// ponytail: held until the process exits (flock goes with it); a Log has no Close.
		l.id, l.open, l.release = id, map[string]bool{}, l.traceCrash(unlock)
	}
	l.open[session] = true
	l.write()
	l.traceHeld("intent", session)
}

func (l *Log) remove(session string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open[session] {
		delete(l.open, session)
		l.write()
		l.traceHeld("forget", session)
	}
}

func (l *Log) write() {
	data, _ := json.Marshal(slices.Sorted(maps.Keys(l.open)))
	if err := writeFile(filepath.Join(l.Dir, OwnersDir, l.id), data, 0o600); err != nil {
		slog.Default().Warn("org: the audit's owner file was not written", "error", err)
	}
}

// appendLine is Append's under the lock; it returns the line's seq.
func appendLine(f *os.File, r Record, cert *x509.Certificate, key ed25519.PrivateKey, now time.Time) (uint64, error) {
	last, end, err := lastLine(f)
	if err != nil {
		return 0, err
	}
	if err := f.Truncate(end); err != nil {
		return 0, err
	}
	s := Signing{Log: randomHex(16), Seq: 1, Machine: cert.Subject.CommonName, Cert: cert, Key: key, At: now}
	// A last line that does not verify (edited) starts a new log: every
	// reader reports it ("new log"), and the machine goes on auditing.
	if lr, err := Parse(last); last != nil && err == nil {
		s.Log, s.Seq, s.Prev = lr.Log, lr.Seq+1, Hash(last)
	}
	line, err := Line(r, s)
	if err != nil {
		return 0, err
	}
	if _, err := f.WriteAt(append(line, '\n'), end); err != nil {
		return 0, err
	}
	traceWrite(s.Seq)
	return s.Seq, f.Sync()
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

// scanOpen reads f's complete lines: the sessions opened and not closed,
// their open lines' offsets.
func scanOpen(f *os.File) (map[string]Record, map[string]int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	open, at := map[string]Record{}, map[string]int64{}
	var off int64
	for l := range bytes.Lines(data) {
		if !bytes.HasSuffix(l, []byte("\n")) {
			break // a torn last line
		}
		if r, err := Parse(l[:len(l)-1]); err == nil {
			switch r.Kind {
			case KindOpen:
				open[r.Session], at[r.Session] = r, off
			case KindClose:
				delete(open, r.Session)
				delete(at, r.Session)
			}
		}
		off += int64(len(l))
	}
	return open, at, nil
}

// Rotate drops the head of dir's audit log up to acked (the bytes
// of it the issuer acknowledged) once the file is over size bytes,
// keeping the last line (the next chains to it: the log goes on; mutant
// rotate-all) and every line from the first open whose close is not
// written (CloseLost reads it; mutant rotate-drops-open); never past
// acked (mutant rotate-unacked) (spec/AuditLog.tla Rotate: OneLog,
// EveryOpenCloses, NothingLost). It returns the bytes dropped; moved is
// told them first, under the log's lock, so the caller's offsets move
// back before the file is replaced: a crash between ships acknowledged
// lines again (the issuer holds them: no line twice), never skips one.
func Rotate(dir string, acked, size int64, moved func(cut int64) error) (int64, error) {
	var cut int64
	err := withLog(dir, func(f *os.File) error {
		traceShip(dir, f, acked)
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
		if err := writeFile(filepath.Join(dir, LogFile), buf, 0o600); err != nil {
			return err
		}
		traceRotate(dir, buf)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return cut, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

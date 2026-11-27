// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgaudit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// machine is a certified key of a machine name.
type machine struct {
	name string
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func newMachine(t *testing.T, name string, serial int64) machine {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return machine{name: name, cert: &x509.Certificate{SerialNumber: big.NewInt(serial), PublicKey: key.Public()}, key: key}
}

func fp(pub ed25519.PublicKey) string { s := sha256.Sum256(pub); return hex.EncodeToString(s[:]) }

// checker knows the machines' certificates, as the issuer's log does.
func checker(ms ...machine) *Checker {
	known := map[string]Signer{}
	for _, m := range ms {
		known[hex.EncodeToString(m.cert.SerialNumber.Bytes())] = Signer{Machine: m.name, Key: fp(m.key.Public().(ed25519.PublicKey))}
	}
	return &Checker{Signers: func(s string) (Signer, bool) { v, ok := known[s]; return v, ok }, KeyOf: fp}
}

// writeLog is n lines of m's log: alternately a session's open and close.
func writeLog(t *testing.T, m machine, log string, n int) [][]byte {
	t.Helper()
	var lines [][]byte
	prev := ""
	t0 := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		s := Session{ID: "s" + string(rune('0'+(i+1)/2)), Service: "pg", Who: Who{Name: "ci-1", Person: "alice@acme.com", Groups: []string{"ops"}}, By: "rule group:ops machine:db pg", Opened: t0}
		r := s.Open()
		if i%2 == 0 {
			r = s.Close(End{Closed: t0.Add(time.Minute), In: 10, Out: 20, Reason: ReasonClosed, Path: "relayed"})
		}
		line, err := Line(r, Signing{Log: log, Seq: uint64(i), Prev: prev, Machine: m.name, Cert: m.cert, Key: m.key, At: t0})
		if err != nil {
			t.Fatal(err)
		}
		lines, prev = append(lines, line), Hash(line)
	}
	return lines
}

// check runs lines through a fresh checker: the lines taken and every finding.
func check(c *Checker, lines [][]byte) (taken int, findings []string) {
	for _, l := range lines {
		_, ok, fs := c.Add(l)
		if ok {
			taken++
		}
		for _, f := range fs {
			findings = append(findings, f.What)
		}
	}
	return taken, findings
}

func TestAuditLogVerifies(t *testing.T) {
	db := newMachine(t, "db", 1)
	lines := writeLog(t, db, "L1", 6)
	if taken, fs := check(checker(db), lines); taken != 6 || fs != nil {
		t.Fatalf("an honest log: taken %d, findings %q", taken, fs)
	}
	r, err := Parse(lines[1])
	if err != nil || r.Kind != KindClose || r.Who.Person != "alice@acme.com" || r.MS != 60000 || r.Out != 20 || r.By == "" {
		t.Fatalf("the close record: %+v, %v", r, err)
	}
}

// TestAuditGapAndAlterationFound is the design's table, one planted
// mutant per row: each is found, and the record is refused where it
// cannot be the machine's own.
func TestAuditGapAndAlterationFound(t *testing.T) {
	db, web := newMachine(t, "db", 1), newMachine(t, "web", 2)
	lines := writeLog(t, db, "L1", 6)
	webLines := writeLog(t, web, "W1", 4)
	without := func(i int) [][]byte { return append(append([][]byte{}, lines[:i]...), lines[i+1:]...) }
	edited := bytes.Replace(lines[2], []byte(`"service":"pg"`), []byte(`"service":"pq"`), 1)
	edited2 := bytes.Replace(lines[3], []byte(`"out":20`), []byte(`"out":2`), 1)
	forged := func() []byte {
		mallory := newMachine(t, "db", 1) // claims db's serial with its own key
		return writeLog(t, mallory, "L1", 3)[2]
	}()
	foreign := writeLog(t, newMachine(t, "db", 9), "L1", 3)[2] // a key the issuer never certified for db
	for _, c := range []struct {
		name  string
		lines [][]byte
		taken int
		want  string
	}{
		{"dropped", without(2), 5, "gap: seq 3..3 missing"},
		{"dropped-last-two-then-one", append(without(4)[:4], lines[5]), 5, "gap: seq 5..5 missing"},
		{"reordered", [][]byte{lines[0], lines[2], lines[1], lines[3]}, 3, "out of order: seq 2 after 3"},
		{"replayed", append(append([][]byte{}, lines...), lines[1]), 6, "out of order: seq 2 after 6"},
		{"edited-service", [][]byte{lines[0], lines[1], edited, lines[3]}, 3, "bad signature at seq 3"},
		{"edited-bytes", [][]byte{lines[0], lines[1], lines[2], edited2}, 3, "bad signature at seq 4"},
		{"forged-signature", [][]byte{lines[0], lines[1], forged}, 2, "not this machine's key at seq 3"},
		{"uncertified-key", [][]byte{lines[0], lines[1], foreign}, 2, "not this machine's key at seq 3"},
		{"from-another-machine", [][]byte{lines[0], relabel(t, webLines[1], "db")}, 1, "bad signature at seq 2"},
		{"another-machines-record", [][]byte{lines[0], webLines[0], lines[1]}, 3, ""}, // web's own line is web's, and db's log has no gap
		{"chain-broken", [][]byte{lines[0], rechain(t, db, lines[1], 2, "")}, 2, "chain broken at seq 2"},
		{"new-log", append(lines[:2:2], writeLog(t, db, "L2", 1)...), 3, "new log L2 (log L1 ended at seq 2)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			taken, fs := check(checker(db, web), c.lines)
			if taken != c.taken {
				t.Errorf("taken %d, want %d (findings %q)", taken, c.taken, fs)
			}
			if c.want == "" {
				if fs != nil {
					t.Errorf("findings %q, want none", fs)
				}
				return
			}
			if !contains(fs, c.want) {
				t.Errorf("findings %q, want %q", fs, c.want)
			}
		})
	}
}

// relabel is line with its machine changed, its signature unchanged.
func relabel(t *testing.T, line []byte, to string) []byte {
	t.Helper()
	out := bytes.Replace(line, []byte(`"machine":"web"`), []byte(`"machine":"`+to+`"`), 1)
	if bytes.Equal(out, line) {
		t.Fatal("relabel: no machine field")
	}
	return out
}

// rechain is line re-signed by m as seq with prev: the machine's own key
// over a chain it did not write in order.
func rechain(t *testing.T, m machine, line []byte, seq uint64, prev string) []byte {
	t.Helper()
	r, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Line(r, Signing{Log: r.Log, Seq: seq, Prev: prev, Machine: m.name, Cert: m.cert, Key: m.key, At: r.At})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func contains(fs []string, want string) bool {
	for _, f := range fs {
		if strings.HasPrefix(f, want) {
			return true
		}
	}
	return false
}

func TestAuditHeadFindsWithheldLines(t *testing.T) {
	db := newMachine(t, "db", 1)
	lines := writeLog(t, db, "L1", 4)
	c := checker(db)
	check(c, lines[:2])
	head, err := SignHead(Signing{Log: "L1", Seq: 4, Prev: Hash(lines[3]), Machine: "db", Cert: db.cert, Key: db.key, At: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, fs := c.CheckHead(head); len(fs) != 1 || !strings.HasPrefix(fs[0].What, "withheld: the machine holds seq 4, the issuer 2") {
		t.Fatalf("findings %v", fs)
	}
	check(c, lines[2:])
	if _, fs := c.CheckHead(head); fs != nil {
		t.Fatalf("all lines taken: findings %v", fs)
	}
	bad := bytes.Replace(head, []byte(`"seq":4`), []byte(`"seq":3`), 1)
	if _, fs := c.CheckHead(bad); len(fs) != 1 || fs[0].What != "a head with a bad signature" {
		t.Fatalf("an edited head: %v", fs)
	}
	now := time.Now()
	if Silent("db", now.Add(-SilentAfter), 1, now) == nil || Silent("db", now.Add(-SilentAfter), 0, now) != nil || Silent("db", now.Add(-time.Minute), 2, now) != nil {
		t.Fatal("silent: reported only with sessions open past SilentAfter")
	}
}

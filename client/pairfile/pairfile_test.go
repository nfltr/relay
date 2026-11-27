// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package pairfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A certificate certifies key k when it reads "cert of k".
func testPair(dir string) Pair {
	return Pair{Key: filepath.Join(dir, "machine.key"), Cert: filepath.Join(dir, "machine.pem"), Match: func(cert, key []byte) error {
		if string(cert) != "cert of "+string(key) {
			return Mismatch(errors.New("tls: private key does not match public key"))
		}
		return nil
	}}
}

func enrolled(t *testing.T) Pair {
	t.Helper()
	p := testPair(t.TempDir())
	if err := p.Write([]byte("cert of k1"), []byte("k1")); err != nil {
		t.Fatal(err)
	}
	return p
}

func readKeyOf(t *testing.T, p Pair) string {
	t.Helper()
	cert, key, err := p.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(cert) != "cert of "+string(key) {
		t.Fatalf("Read: %q with %q", cert, key)
	}
	return string(key)
}

// The writer stopped after each of its steps (killed: the files as that
// step left them): a reader still takes a pair, the old one or the new one
// (MachinePair.tla Usable), and the next replacement succeeds and is read
// (Recover). Before CERTATOMIC the writer replaced the key, then the
// certificate: stopped between them, Read failed and the machine needed
// nfltr config login / nfltr org join again.
func TestEveryCrashLeavesAPair(t *testing.T) {
	if len(testPair("").steps(nil, nil)) != Steps {
		t.Fatalf("Steps is %d, Write has %d", Steps, len(testPair("").steps(nil, nil)))
	}
	for n := range Steps + 1 {
		p := enrolled(t)
		if err := p.WriteFirst(n, []byte("cert of k2"), []byte("k2")); err != nil {
			t.Fatal(err)
		}
		if got := readKeyOf(t, p); got != "k1" && got != "k2" {
			t.Fatalf("stopped after %d steps: read %q", n, got)
		}
		// a crash during the first replacement, then a stop of the next
		// one after its recovery and new key, then a whole one
		if err := p.WriteFirst(2, []byte("cert of k3"), []byte("k3")); err != nil {
			t.Fatal(err)
		}
		if got := readKeyOf(t, p); got != "k1" && got != "k2" {
			t.Fatalf("stopped after %d steps, then 2: read %q", n, got)
		}
		if err := p.Write([]byte("cert of k4"), []byte("k4")); err != nil {
			t.Fatal(err)
		}
		if got := readKeyOf(t, p); got != "k4" {
			t.Fatalf("stopped after %d steps, then a replacement: read %q", n, got)
		}
		if _, err := os.Stat(p.Next()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stopped after %d steps: %s left: %v", n, p.Next(), err)
		}
	}
}

// An error other than a mismatch (a file that does not parse) fails Read
// at once.
func TestReadRefusesAnUnmatchedPair(t *testing.T) {
	p := enrolled(t)
	p.Match = func([]byte, []byte) error { return errors.New("not PEM") }
	start := time.Now()
	if _, _, err := p.Read(); err == nil || err.Error() != "not PEM" {
		t.Fatalf("Read: %v", err)
	}
	if d := time.Since(start); d >= wait {
		t.Fatalf("Read waited %v on a file that does not parse", d)
	}
}

// A key file other users may read is refused, as machine.key always was.
func TestReadRefusesAReadableKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports every writable file as 0666: no mode to check")
	}
	p := enrolled(t)
	if err := os.Chmod(p.Key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Read(); err == nil {
		t.Fatal("Read took a key mode 0644")
	}
}

// A reader that read the certificate before a whole replacement and the
// key after it (another process renewed in between) reads again instead
// of failing; the files here stand for what it read.
func TestReadWaitsOutAReplacement(t *testing.T) {
	p := enrolled(t)
	if err := write(p.Key, []byte("k2")); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		_, key, err := p.Read()
		if err != nil {
			t.Error(err)
		}
		done <- string(key)
	}()
	select {
	case k := <-done:
		t.Fatalf("Read returned %q with the certificate of another key", k)
	case <-time.After(50 * time.Millisecond):
	}
	if err := write(p.Cert, []byte("cert of k2")); err != nil {
		t.Fatal(err)
	}
	if k := <-done; k != "k2" {
		t.Fatalf("Read: %q, want k2", k)
	}
}

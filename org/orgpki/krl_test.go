// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// OpenSSH reads the KRL of a CRL as the CRL says: the revoked machine's
// host certificate REVOKED, another machine's ok; before the revoke both
// ok (ssh-keygen -Q, the check ssh's RevokedHostKeys runs).
func TestHostKRLRevokesBySerial(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no OpenSSH ssh-keygen on PATH")
	}
	o := newOrg(t)
	dir := t.TempDir()
	certFile := func(name string) string {
		_, _, raw := o.hostCert(t, name)
		k, err := ssh.ParsePublicKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name+"-cert.pub")
		if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(k), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	web1, web2 := certFile("web-1"), certFile("web-2")
	query := func(crl []byte) (string, error) {
		data, err := HostKRL(crl, o.iss.Cert())
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, "revoked-hosts.krl")
		if err := os.WriteFile(f, data, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(keygen, "-Q", "-f", f, web1, web2).CombinedOutput() // #nosec G204 -- test files
		return string(out), err
	}
	before, err := o.iss.CRL(t0)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := query(before); err != nil || strings.Contains(out, "REVOKED") {
		t.Fatalf("no revocation yet: %v\n%s", err, out)
	}
	if err := o.iss.Revoke("web-1", t0); err != nil {
		t.Fatal(err)
	}
	after, err := o.iss.CRL(t0.Add(1))
	if err != nil {
		t.Fatal(err)
	}
	out, err := query(after)
	verdict := func(file string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, file+" ") {
				return l[strings.LastIndex(l, ": ")+2:]
			}
		}
		return ""
	}
	if err == nil || verdict(web1) != "REVOKED" || verdict(web2) != "ok" {
		t.Fatalf("after revoking web-1: %v\n%s", err, out)
	}
	k, _ := HostKRL(after, o.iss.Cert())
	if KRLDate(k) != uint64(t0.Unix()) || KRLDate([]byte("not a krl")) != 0 { // #nosec G115 -- test
		t.Fatalf("KRLDate %d, want %d", KRLDate(k), t0.Unix())
	}
}

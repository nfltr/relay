// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package machinecert is a machine's side of nfltr machine certificates
// (relay-server spec/MachineAuth.tla): the machine makes its key and keeps
// it (NewKey, SaveKey: a 0600 file), sends only a CSR to the relay's
// accounts service (Client.Enrol with a code or an enrolment token), and
// renews its 24 h certificate at half its lifetime, up to 10 % later
// (Loop; also after it expired, within the relay's grace), or
// rotates to a new key with the current key's proof (Client.Rotate). The
// certificate is a TLS client certificate for the relay (Cert.TLS); the
// relay knows the machine by the one URI SAN spiffe://<domain>/m/<id>.
//
// The certificate files: `nfltr config login` saves the key (machine.key,
// 0600; or KeyEnv) and the certificate with what the relay answered
// (machine.json, 0600: Saved) in the nfltr config directory (KeyPath,
// CertPath, Load, Saved.Store). The process that presents and renews them
// is client/machinecred; this package stays standard library only, so the
// relay's own enrolment (relay-server service-enrol) links it without the
// agent SDK.
package machinecert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// The relay's routes (relay-server services/accounts/accountswire).
const (
	EnrolPath   = "/api/v1/machines/enrol"
	ReissuePath = "/api/v1/machines/reissue"
)

// NewKey makes a machine key (ECDSA P-256).
func NewKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// CSR is a PKCS#10 request for key (DER). It names nothing: the relay
// gives the machine its id.
func CSR(key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
}

// RotationProof is cur's signature (ASN.1, over SHA-256) of the new key's
// CSR: the relay rotates a machine to a new key only with it.
func RotationProof(cur *ecdsa.PrivateKey, csr []byte) ([]byte, error) {
	h := sha256.Sum256(csr)
	return ecdsa.SignASN1(rand.Reader, cur, h[:])
}

// SaveKey writes key to path (PKCS#8 PEM), readable by its owner only,
// replacing the file whole.
func SaveKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".machine-key-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := pem.Encode(tmp, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadKey reads a key SaveKey wrote; a file group or others may read is
// refused. Windows reports every writable file as 0666 whatever its ACL
// says, so there the key is as private as its directory's ACL (the user
// profile's) and the mode is not checked.
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("machine key %s: mode %o, want 0600 (owner only)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path) // #nosec G304 -- the machine's own key file
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("machine key %s: not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("machine key %s: %w", path, err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("machine key %s: not an ECDSA key", path)
	}
	return ek, nil
}

// Cert is a machine certificate as the relay answers it.
type Cert struct {
	MachineID string            `json:"machine_id"`
	Name      string            `json:"name"`
	Group     string            `json:"group"`
	Chain     string            `json:"chain"` // PEM: the certificate, then the CA's
	NotAfter  time.Time         `json:"not_after"`
	Leaf      *x509.Certificate `json:"-"`
}

func (c *Cert) parse() error {
	blk, _ := pem.Decode([]byte(c.Chain))
	if blk == nil {
		return errors.New("machinecert: the answer carries no certificate")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return fmt.Errorf("machinecert: %w", err)
	}
	c.Leaf = leaf
	return nil
}

// ParseCert reads a Cert's PEM chain (a certificate file saved earlier).
func ParseCert(chain []byte) (*Cert, error) {
	c := &Cert{Chain: string(chain)}
	if err := c.parse(); err != nil {
		return nil, err
	}
	c.NotAfter = c.Leaf.NotAfter
	return c, nil
}

// TLS is c with key as a TLS client certificate.
func (c *Cert) TLS(key *ecdsa.PrivateKey) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{c.Leaf.Raw}, PrivateKey: key, Leaf: c.Leaf}
}

// RefusedError is the relay's refusal: Status and its message (what to do).
type RefusedError struct {
	Status  int
	Message string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("machinecert: refused (%d): %s", e.Status, e.Message)
}

// Final reports whether retrying cannot help: the code or token is spent,
// the machine revoked, its key rotated away, or its certificate expired
// past the relay's grace (sign in again: nfltr config login).
func (e *RefusedError) Final() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden || e.Status == http.StatusBadRequest
}

// Client calls the relay's machine routes at BaseURL (the relay's
// https:// URL) with HTTP (nil: http.DefaultClient).
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// Enrol exchanges an enrolment code or token (name names the machine a
// token enrols) and key's CSR for the machine and its certificate.
func (c *Client) Enrol(ctx context.Context, code, token, name string, key *ecdsa.PrivateKey) (*Cert, error) {
	csr, err := CSR(key)
	if err != nil {
		return nil, err
	}
	return c.post(ctx, EnrolPath, map[string]any{"code": code, "token": token, "name": name, "csr": csr})
}

// Renew asks a new certificate for cur's key (the relay answers 409 until
// the last two thirds of cur's lifetime; it renews an expired one within
// its grace).
func (c *Client) Renew(ctx context.Context, cur *Cert, key *ecdsa.PrivateKey) (*Cert, error) {
	csr, err := CSR(key)
	if err != nil {
		return nil, err
	}
	return c.post(ctx, ReissuePath, map[string]any{"chain": cur.Chain, "csr": csr})
}

// Rotate moves the machine from curKey to next: from then on the relay
// refuses curKey and every certificate of it.
func (c *Client) Rotate(ctx context.Context, cur *Cert, curKey, next *ecdsa.PrivateKey) (*Cert, error) {
	csr, err := CSR(next)
	if err != nil {
		return nil, err
	}
	proof, err := RotationProof(curKey, csr)
	if err != nil {
		return nil, err
	}
	return c.post(ctx, ReissuePath, map[string]any{"chain": cur.Chain, "csr": csr, "proof": proof})
}

func (c *Client) post(ctx context.Context, path string, body any) (*Cert, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.BaseURL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &RefusedError{Status: resp.StatusCode, Message: strings.TrimSpace(string(data))}
	}
	var out Cert
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("machinecert: the answer: %w", err)
	}
	if err := out.parse(); err != nil {
		return nil, err
	}
	return &out, nil
}

// RenewAt is when a certificate valid from notBefore to notAfter renews:
// at half its lifetime, up to 10 % of it later by jitter (in [-1, 1]: -1
// at half, 1 at 60 %), so a fleet's machines spread their renewals and
// half the lifetime is left for retries (the relay takes a renewal in the
// last two thirds).
func RenewAt(notBefore, notAfter time.Time, jitter float64) time.Time {
	jitter = max(-1, min(1, jitter))
	life := notAfter.Sub(notBefore)
	return notBefore.Add(life/2 + time.Duration(float64(life)*0.05*(jitter+1)))
}

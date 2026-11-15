// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// SealedKey is the enrolment answer's machine key (K_m) field: a key the
// issuer's host seals to the enrolled machine (nfltr's
// spec/proverif/a2a_keytransfer.pv Token and Enrolling): K_m sealed with
// crypto/hpke to the key the issuer certified, and the issuer's signature
// over the request's token id, the certificate, the key id and the sealed
// key. It carries nothing secret: the relay sees it.
type SealedKey struct {
	KeyID  string `json:"key_id"` // <machine id>.<generation>
	Sealed []byte `json:"sealed"` // hpke.Seal: the encapsulated key, then the ciphertext
	Sig    []byte `json:"sig"`
}

const machineKeyLabel = "nfltr-org-machine-key-v1\x00"

func machineKeyInfo(cert []byte, keyID string) []byte {
	sum := sha256.Sum256(cert)
	return slices.Concat([]byte(machineKeyLabel), sum[:], []byte(keyID))
}

func machineKeyMessage(tokenID string, cert []byte, k SealedKey) []byte {
	return slices.Concat(machineKeyInfo(cert, k.KeyID), []byte("\x00"+tokenID+"\x00"), k.Sealed)
}

// machineKeyID checks that keyID is the certificate's machine id and a
// generation.
func machineKeyID(c *x509.Certificate, keyID string) error {
	mid := orgid.MachineID(c)
	gen, ok := strings.CutPrefix(keyID, mid+".")
	if n, err := strconv.Atoi(gen); mid == "" || !ok || err != nil || n < 1 || strconv.Itoa(n) != gen {
		return fmt.Errorf("key id %q is not the certificate's machine id %q and a generation", keyID, mid)
	}
	return nil
}

func hpkeSuite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.ChaCha20Poly1305() }

// x25519Public is an Ed25519 public key's X25519 image, u = (1+y)/(1-y)
// mod p (RFC 7748 section 4.1), the key x25519Private's scalar has: what
// age's ssh-ed25519 recipients and libsodium's crypto_sign_ed25519_pk_to_
// curve25519 do. The key is public, so math/big's timing does not matter;
// the issuer takes it from a CSR whose signature it checked, so it is a
// point of the curve.
func x25519Public(pub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 key")
	}
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	b := slices.Clone(pub)
	b[31] &= 0x7f // x's sign
	slices.Reverse(b)
	y := new(big.Int).SetBytes(b)
	den := new(big.Int).Mod(new(big.Int).Sub(big.NewInt(1), y), p)
	if y.Cmp(p) >= 0 || den.Sign() == 0 {
		return nil, errors.New("not an Ed25519 key")
	}
	u := new(big.Int).Add(big.NewInt(1), y)
	u.Mul(u, den.ModInverse(den, p)).Mod(u, p)
	out := u.FillBytes(make([]byte, 32))
	slices.Reverse(out)
	return ecdh.X25519().NewPublicKey(out)
}

// x25519Private is the X25519 key of an Ed25519 private key: the first
// half of SHA-512 of its seed, which X25519 clamps as Ed25519 does.
func x25519Private(key ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	h := sha512.Sum512(key.Seed())
	return ecdh.X25519().NewPrivateKey(h[:32])
}

// SealMachineKey seals km, the machine key of keyID, for the machine
// certificate cert that this issuer issued at the redemption of token
// tokenID: to the key it certified, never a key from the request
// (a2a_keytransfer.pv mutant seal-to-request-key), and signed.
func (i *Issuer) SealMachineKey(tokenID string, cert []byte, keyID string, km []byte) (SealedKey, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return SealedKey{}, err
	}
	sum := sha256.Sum256(cert)
	rec := i.certs[hex.EncodeToString(c.SerialNumber.Bytes())]
	if rec == nil || rec.digest != hex.EncodeToString(sum[:]) || rec.token == "" || rec.token != tokenID {
		return SealedKey{}, fmt.Errorf("%w: not a certificate this issuer issued for that token", ErrRefused)
	}
	if err := machineKeyID(c, keyID); err != nil {
		return SealedKey{}, err
	}
	k := SealedKey{KeyID: keyID}
	if k.Sealed, err = sealTo(c, keyID, km); err != nil {
		return SealedKey{}, err
	}
	k.Sig = ed25519.Sign(i.key, machineKeyMessage(tokenID, cert, k))
	return k, nil
}

// SealToMachine seals km, the machine key of keyID (cert's machine id
// and a generation), to the key machine certificate cert certifies: the
// seal of SealMachineKey, unsigned, for a caller that checked cert itself
// (the root holder keying a machine after its enrolment). It opens with
// OpenFromMachine.
func SealToMachine(cert *x509.Certificate, keyID string, km []byte) ([]byte, error) {
	if err := machineKeyID(cert, keyID); err != nil {
		return nil, err
	}
	return sealTo(cert, keyID, km)
}

// sealTo is crypto/hpke to the X25519 image of c's Ed25519 key, bound to c
// and keyID.
func sealTo(c *x509.Certificate, keyID string, km []byte) ([]byte, error) {
	edpub, _ := c.PublicKey.(ed25519.PublicKey)
	pub, err := x25519Public(edpub)
	if err != nil {
		return nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, err
	}
	kdf, aead := hpkeSuite()
	return hpke.Seal(pk, kdf, aead, machineKeyInfo(c.Raw, keyID), km)
}

// OpenFromMachine opens a seal of km (key id keyID) made to machine
// certificate cert (DER) with that certificate's key.
func OpenFromMachine(sealed, cert []byte, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	priv, err := x25519Private(key)
	if err != nil {
		return nil, err
	}
	sk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	kdf, aead := hpkeSuite()
	return hpke.Open(sk, kdf, aead, machineKeyInfo(cert, keyID), sealed)
}

// OpenMachineKey is the enrolling machine's side: K_m from the answer to
// its request under tokenID, made with key. cert and issuer are the
// answer's certificates, root the organisation root the machine pinned by
// its fingerprint. It takes only its own certified key, under that root,
// the issuer's signature over this token id, certificate, key id and
// sealed key (a2a_keytransfer.pv mutants unsigned-key, any-token).
func OpenMachineKey(k SealedKey, tokenID string, cert, issuer []byte, root *x509.Certificate, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	ic, err := x509.ParseCertificate(issuer)
	if err != nil {
		return nil, err
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inter.AddCert(ic)
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, err
	}
	if pub, ok := c.PublicKey.(ed25519.PublicKey); !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("the certificate is not for this machine's key")
	}
	if err := machineKeyID(c, k.KeyID); err != nil {
		return nil, err
	}
	if ipub, ok := ic.PublicKey.(ed25519.PublicKey); !ok || !ed25519.Verify(ipub, machineKeyMessage(tokenID, cert, k), k.Sig) {
		return nil, errors.New("the machine key is not signed by the issuer for this request")
	}
	return OpenFromMachine(k.Sealed, cert, k.KeyID, key)
}

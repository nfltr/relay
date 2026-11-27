// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/relay/client/tlsend"
)

// Identity is what an organisation-mode tcp service tells its target
// about who called (Service.Identity; nfltr
// docs/decisions/service-access-2026-11-25.md "3. Identity to the app",
// spec/proverif/svc_access.pv queries 5 and 6): always the admitted
// client certificate's name, person and groups, never a value the client
// sent.
type Identity string

const (
	// IdentityOff, the default: the target gets the session's bytes only.
	IdentityOff Identity = ""
	// IdentityHTTP: the target speaks HTTP/1. Every request reaches it
	// without any header of the client's named Nfltr-* or X-Nfltr-*
	// (underscores read as dashes) and with Nfltr-Machine, Nfltr-Person
	// (when the certificate names one), Nfltr-Groups, Nfltr-Service and
	// Nfltr-Assertion (AssertionHeader) set by the agent
	// (BIND:svc.hdrwho).
	IdentityHTTP Identity = "http"
	// IdentityProxyV2: before the session's first byte the target reads a
	// PROXY protocol v2 header (command LOCAL, no addresses) whose TLVs
	// carry the caller (TLVMachine, TLVPerson, TLVGroups, TLVService).
	IdentityProxyV2 Identity = "proxy-v2"
)

// The identity headers IdentityHTTP sets.
const (
	MachineHeader = "Nfltr-Machine"
	PersonHeader  = "Nfltr-Person"
	GroupsHeader  = "Nfltr-Groups" // comma-separated
	ServiceHeader = "Nfltr-Service"
	// AssertionHeader is a JWT (RFC 7519, compact JWS RFC 7515, alg EdDSA
	// RFC 8037) under this machine's organisation key: iss this machine's
	// name, aud the service (BIND:svc.aud), sub the person or else the
	// caller's machine, machine, groups, iat, exp (iat + AssertionLife).
	// An app beyond loopback verifies it against its agent's key (JWKS)
	// and checks aud is its own service.
	AssertionHeader = "Nfltr-Assertion"
)

// AssertionLife is how long an assertion is valid.
const AssertionLife = time.Minute

// The PROXY v2 TLV types IdentityProxyV2 sends (in the range E0 to EF hex the
// specification leaves to applications); each value is UTF-8.
const (
	TLVMachine = 0xE0
	TLVPerson  = 0xE1
	TLVGroups  = 0xE2 // comma-separated
	TLVService = 0xE3
)

// errIdentityKey: IdentityHTTP signs with an Ed25519 machine key only.
var errIdentityKey = errors.New("identity: the machine certificate's key is not Ed25519: no assertion can be signed")

// caller is an admitted session's client as its certificate names it.
type caller struct {
	machine, person, service string
	groups                   []string
}

// callerOf reads leaf, the certificate Org.CheckClient admitted: its name,
// its one rfc822Name SAN (client/orgid PersonOf), its groups (OU).
func callerOf(leaf *x509.Certificate, service string) caller {
	c := caller{machine: leaf.Subject.CommonName, service: service, groups: leaf.Subject.OrganizationalUnit}
	if len(leaf.EmailAddresses) == 1 {
		c.person = leaf.EmailAddresses[0]
	}
	return c
}

// withIdentity is what serveE2EETCP joins to target for mode: tc itself,
// after a PROXY v2 header written to target, or tc with its requests
// rewritten (identityConn).
func withIdentity(mode Identity, tc *tlsend.Conn, target net.Conn, o Org, c caller) (peerlink.Session, error) {
	switch mode {
	case IdentityProxyV2:
		_, err := target.Write(proxyV2Header(c))
		return tc, err
	case IdentityHTTP:
		cert, err := o.Certificate()
		if err != nil {
			return nil, err
		}
		if _, err := machineKey(o); err != nil {
			return nil, err
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		a := assertion{o: o, iss: leaf.Subject.CommonName} // a renewal keeps the name
		pr, pw := io.Pipe()
		sw := newSwitchWatch()
		go func() {
			_ = pw.CloseWithError(rewriteRequests(bufio.NewReader(tc), pw, sw, func(h http.Header) error {
				return setIdentity(h, c, a, time.Now())
			}))
		}()
		return &identityConn{Conn: tc, r: pr, sw: sw}, nil
	}
	return tc, nil
}

// identityConn is the session's TLS conn whose reads are its requests as
// rewriteRequests passed them on and whose writes (the app's responses)
// sw sees; Close also ends those goroutines.
type identityConn struct {
	*tlsend.Conn
	r  *io.PipeReader
	sw *switchWatch
}

func (c *identityConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *identityConn) Write(p []byte) (int, error) {
	return watchedWriter{Writer: c.Conn, w: c.sw}.Write(p)
}

func (c *identityConn) Close() error {
	_ = c.r.Close()
	c.sw.end()
	return c.Conn.Close()
}

// rewriteRequests writes the HTTP/1 requests read from br to out, each
// after set changed its header and with no identity trailer, as the
// stream path does (writeStreamRequest); once the app switched protocols
// (sw) the rest goes on as bytes. nil at the client's end between
// requests.
func rewriteRequests(br *bufio.Reader, out io.Writer, sw *switchWatch, set func(http.Header) error) error {
	defer sw.requestsEnd()
	w := bufio.NewWriter(out)
	for {
		req, err := http.ReadRequest(br)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := set(req.Header); err != nil {
			return err
		}
		dropIdentity(req.Trailer) // the Trailer line names none
		if req.Body != http.NoBody {
			req.Body = identityTrailers{req.Body, req}
		}
		ch := sw.expect(req)
		if err := writeStreamRequest(w, req, "", netip.Addr{}); err != nil {
			return err
		}
		if sw.switched(ch) {
			_, err := io.Copy(out, br) // each read as it comes: a frame waits for no other
			return err
		}
	}
}

// identityTrailers is a request's body that drops its identity trailers
// once read: the client's trailers arrive at the body's end.
type identityTrailers struct {
	io.ReadCloser
	req *http.Request
}

func (b identityTrailers) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		dropIdentity(b.req.Trailer)
	}
	return n, err
}

// isIdentity: name, underscores read as dashes, starts with Nfltr- or
// X-Nfltr- (a CGI or nginx backend reads Nfltr_Person as Nfltr-Person).
func isIdentity(name string) bool {
	n := strings.ReplaceAll(strings.ToLower(name), "_", "-")
	return strings.HasPrefix(n, "nfltr-") || strings.HasPrefix(n, "x-nfltr-")
}

// dropIdentity deletes every identity header of h.
func dropIdentity(h http.Header) {
	for k := range h {
		if isIdentity(k) {
			delete(h, k)
		}
	}
}

// setIdentity deletes every identity header of h and every Connection
// token naming one (a hop would drop the agent's header it names), then
// sets c's.
func setIdentity(h http.Header, c caller, a assertion, now time.Time) error {
	dropIdentity(h)
	if v, ok := h["Connection"]; ok {
		var keep []string
		for _, f := range v {
			for tok := range strings.SplitSeq(f, ",") {
				if tok = strings.TrimSpace(tok); tok != "" && !isIdentity(tok) {
					keep = append(keep, tok)
				}
			}
		}
		delete(h, "Connection")
		if len(keep) > 0 {
			h["Connection"] = []string{strings.Join(keep, ", ")}
		}
	}
	jwt, err := a.sign(c, now)
	if err != nil {
		return err
	}
	h.Set(MachineHeader, c.machine)
	if c.person != "" {
		h.Set(PersonHeader, c.person)
	}
	h.Set(GroupsHeader, strings.Join(c.groups, ","))
	h.Set(ServiceHeader, c.service)
	h.Set(AssertionHeader, jwt)
	return nil
}

// assertion signs AssertionHeader's JWTs with this machine's current key
// (o's, read at each request: a renewal's new key signs a long session's
// next request).
type assertion struct {
	o   Org
	iss string
}

type assertionClaims struct {
	Iss     string   `json:"iss"`
	Sub     string   `json:"sub"`
	Aud     string   `json:"aud"`
	Machine string   `json:"machine"`
	Person  string   `json:"person,omitempty"`
	Groups  []string `json:"groups"`
	Iat     int64    `json:"iat"`
	Exp     int64    `json:"exp"`
}

func (a assertion) sign(c caller, now time.Time) (string, error) {
	key, err := machineKey(a.o)
	if err != nil {
		return "", err
	}
	sub := c.person
	if sub == "" {
		sub = c.machine
	}
	head, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": keyID(key.Public().(ed25519.PublicKey))})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(assertionClaims{Iss: a.iss, Sub: sub, Aud: c.service, Machine: c.machine, Person: c.person,
		Groups: c.groups, Iat: now.Unix(), Exp: now.Add(AssertionLife).Unix()})
	if err != nil {
		return "", err
	}
	in := b64(head) + "." + b64(body)
	return in + "." + b64(ed25519.Sign(key, []byte(in))), nil
}

// machineKey is o's current machine key.
func machineKey(o Org) (ed25519.PrivateKey, error) {
	cert, err := o.Certificate()
	if err != nil {
		return nil, err
	}
	key, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errIdentityKey
	}
	return key, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// keyID is pub's JWK thumbprint (RFC 7638): the kid of its assertions and
// of its JWKS entry.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64(pub) + `"}`))
	return b64(sum[:])
}

// jwks is the JSON Web Key Set (RFC 7517, OKP keys RFC 8037) of pub.
func jwks(pub ed25519.PublicKey) []byte {
	return []byte(fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":%q,"x":%q}]}`, keyID(pub), b64(pub)))
}

// JWKSPath is where JWKSHandler serves.
const JWKSPath = "/.well-known/nfltr/jwks.json"

// JWKSHandler serves at JWKSPath the JSON Web Key Set of o's current
// machine key, which an app beyond loopback verifies AssertionHeader
// with: a renewal brings a new key (kid), so an app fetches the set again
// for a kid it does not know, as for any JWKS.
func JWKSHandler(o Org) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path != JWKSPath:
			http.NotFound(w, r)
			return
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		key, err := machineKey(o)
		if err != nil {
			http.Error(w, "no machine key", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write(jwks(key.Public().(ed25519.PublicKey))) // nosemgrep: no-direct-write-to-responsewriter -- the JSON key set of the machine's public key (its key id and base64url, no request input), served as application/json
	})
}

// proxyV2Sig is the PROXY protocol v2 signature.
const proxyV2Sig = "\r\n\r\n\x00\r\nQUIT\n"

// proxyV2Header is a PROXY v2 header, command LOCAL (0x20) and family
// UNSPEC (no addresses: the relay's word on the client's address is no
// identity), with c in TLVs.
func proxyV2Header(c caller) []byte {
	var tlv []byte
	add := func(t byte, v string) {
		if v != "" {
			tlv = append(tlv, t)
			tlv = binary.BigEndian.AppendUint16(tlv, uint16(len(v))) // #nosec G115 -- names are short; a value over 64 KiB is cut below
			tlv = append(tlv, v...)
		}
	}
	add(TLVMachine, clip(c.machine))
	add(TLVPerson, clip(c.person))
	add(TLVGroups, clip(strings.Join(c.groups, ",")))
	add(TLVService, clip(c.service))
	h := append([]byte(proxyV2Sig), 0x20, 0x00)
	h = binary.BigEndian.AppendUint16(h, uint16(len(tlv))) // #nosec G115 -- four TLVs of at most 1 KiB each
	return append(h, tlv...)
}

// clip bounds a TLV value: certificate names and groups are far shorter.
func clip(s string) string {
	if len(s) > 1024 {
		return s[:1024]
	}
	return s
}

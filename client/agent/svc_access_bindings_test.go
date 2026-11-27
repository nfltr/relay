// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// The bindings spec/proverif/svc_access.pv's identity to the app relies on
// (queries 5 and 6), against the real code: what the target of an
// organisation-mode service is told of its caller (Service.Identity).
// Each BIND:svc.* the model lists has a row here or an entry in
// modelbind.Pending (the rules' and grants' rows come with lanes SA3 and
// SA4). `make spec-bindings`.

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/internal/modelbind"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

const svcAccessModel = "../../spec/proverif/svc_access.pv"

// idRig is agent web serving pg and vault in organisation mode to group
// db, each with identity mode, its target at target(name); bob is a
// person's device in db, cli a machine in db.
type idRig struct {
	l        *linkSessions
	org      *renewingOrg
	pool     *x509.CertPool
	bob, cli tls.Certificate
}

func newIDRig(t *testing.T, mode Identity, target func(name string) string) idRig {
	t.Helper()
	o := newTestOrg(t)
	web := o.machine(t, "web", []string{"db"}, time.Hour, false)
	org := &renewingOrg{fakeOrg: o.agentOrg(web), o: o}
	svc := func(name string) Service {
		return Service{Name: name, Kind: agentservices.TCP, Target: target(name), E2EE: agentservices.E2EEOn, Org: org, Identity: mode}
	}
	table, err := NewServiceTable([]Service{svc("pg"), svc("vault")})
	if err != nil {
		t.Fatal(err)
	}
	return idRig{org: org, l: &linkSessions{ctx: t.Context(), targets: sessionTargets{services: table, agent: "web"}, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}},
		pool: o.pool, bob: personCert(t, o, "bob-mac", "bob@acme.com", []string{"db", "dev"}), cli: o.machine(t, "cli", []string{"db"}, time.Hour, false)}
}

// renewingOrg is a fakeOrg whose machine certificate renew replaces (a
// new key, as orgenrol's renewal makes).
type renewingOrg struct {
	*fakeOrg
	o    *testOrg
	mu   sync.Mutex
	cert *tls.Certificate
}

func (r *renewingOrg) Certificate() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert == nil {
		return r.fakeOrg.Certificate()
	}
	return r.cert, nil
}

func (r *renewingOrg) renew(t *testing.T) {
	c := r.o.machine(t, "web", []string{"db"}, time.Hour, false)
	r.mu.Lock()
	r.cert = &c
	r.mu.Unlock()
}

// getJWKS is what JWKSHandler serves for o now.
func getJWKS(t *testing.T, o Org) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	JWKSHandler(o).ServeHTTP(w, httptest.NewRequest(http.MethodGet, JWKSPath, nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("JWKS: %d %v", w.Code, w.Header())
	}
	return w.Body.Bytes()
}

// personCert is a device certificate of the organisation naming a person
// (its rfc822Name SAN, as client/orgid's enrolment writes it).
func personCert(t *testing.T, o *testOrg, name, email string, groups []string) tls.Certificate {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name, OrganizationalUnit: groups}, EmailAddresses: []string{email},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	c := mustCert(t, tmpl, o.root, pub, o.rootKey)
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
}

// open is an honest client's session to svc on web, as cert.
func (r idRig) open(t *testing.T, svc string, cert tls.Certificate) net.Conn {
	t.Helper()
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: svc, E2Ee: true, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go r.l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("answer %v, %v", a, err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.pool, ServerName: "web.org.internal", Certificates: []tls.Certificate{cert}}
	BindServiceTLS(cfg, MachineALPN("web", svc))
	tc := tls.Client(c, cfg)
	t.Cleanup(func() { _ = tc.Close() })
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	return tc
}

// hostile is a request carrying every identity header a client could
// make up, in the spellings an app might read as one.
func hostile(path string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://pg.web"+path, nil)
	for k, v := range map[string]string{"Nfltr-Machine": "eve", "Nfltr-Person": "eve@acme.com", "Nfltr-Groups": "ops", "Nfltr-Service": "vault",
		"Nfltr-Assertion": "forged", "X-Nfltr-Caller": "eve", "X-Nfltr-Caller-Principal": "eve"} {
		req.Header.Set(k, v)
	}
	req.Header["Nfltr_Person"] = []string{"eve@acme.com"} // CGI and nginx read it as Nfltr-Person
	req.Header["nfltr-machine"] = []string{"eve"}
	return req
}

// httpApps is a loopback app per service that hands each request's
// header to its channel.
func httpApps(t *testing.T) (func(string) string, map[string]chan http.Header) {
	got := map[string]chan http.Header{}
	return func(name string) string {
		ch := make(chan http.Header, 4)
		got[name] = ch
		app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ch <- r.Header.Clone(); _, _ = io.WriteString(w, "ok") }))
		t.Cleanup(app.Close)
		return app.Listener.Addr().String()
	}, got
}

// httpRoundTrip sends req on c and reads its response.
func httpRoundTrip(t *testing.T, c net.Conn, br *bufio.Reader, req *http.Request) {
	t.Helper()
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// identityOf is h's identity headers: every Nfltr-* name (underscores read
// as dashes) the app got, lower-cased, with its values.
func identityOf(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		n := strings.ReplaceAll(strings.ToLower(k), "_", "-")
		if strings.HasPrefix(n, "nfltr-") || strings.HasPrefix(n, "x-nfltr-") {
			out[n] = strings.Join(v, "|")
		}
	}
	delete(out, "nfltr-assertion")
	return out
}

// verifyJWT is an app's check of an assertion: EdDSA under its agent's
// key from JWKS, aud its own service, not expired. It returns the claims.
func verifyJWT(jwt string, jwks []byte, aud string, now time.Time) (assertionClaims, error) {
	var set struct {
		Keys []struct{ Kty, Crv, Kid, X string }
	}
	var cl assertionClaims
	if err := json.Unmarshal(jwks, &set); err != nil || len(set.Keys) != 1 || set.Keys[0].Crv != "Ed25519" {
		return cl, fmt.Errorf("jwks %s: %v", jwks, err)
	}
	pub, _ := base64.RawURLEncoding.DecodeString(set.Keys[0].X)
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return cl, errors.New("not a compact JWS")
	}
	var head struct{ Alg, Kid string }
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if err := json.Unmarshal(hb, &head); err != nil || head.Alg != "EdDSA" || head.Kid != set.Keys[0].Kid {
		return cl, fmt.Errorf("header %s", hb)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return cl, errors.New("signature")
	}
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(body, &cl); err != nil {
		return cl, err
	}
	switch {
	case cl.Aud != aud:
		return cl, fmt.Errorf("aud %q, not %q", cl.Aud, aud)
	case now.Unix() >= cl.Exp:
		return cl, errors.New("expired")
	}
	return cl, nil
}

// verifyOnce is verifyJWT with the app's replay check, the one the
// organisation guide asks of an app beyond loopback: seen keeps the jti of
// each assertion taken until its exp; a jti taken before is refused
// (lane SECFIX2, review S17).
func verifyOnce(seen map[string]int64, jwt string, jwks []byte, aud string, now time.Time) (assertionClaims, error) {
	cl, err := verifyJWT(jwt, jwks, aud, now)
	if err != nil {
		return cl, err
	}
	for j, exp := range seen {
		if now.Unix() >= exp {
			delete(seen, j)
		}
	}
	if _, ok := seen[cl.Jti]; ok || cl.Jti == "" {
		return cl, fmt.Errorf("jti %q taken before: a replay", cl.Jti)
	}
	seen[cl.Jti] = cl.Exp
	return cl, nil
}

var svcAccessBindings = map[string]func(*testing.T){
	// The app gets the admitted certificate's name, person and groups and
	// the session's service, whatever identity headers the client sent, on
	// every request of the session; over PROXY v2, the same in its TLVs
	// (mutants header-from-client, header-underscore, proxy-no-header).
	"svc.hdrwho": func(t *testing.T) {
		target, got := httpApps(t)
		r := newIDRig(t, IdentityHTTP, target)
		for _, c := range []struct {
			cert tls.Certificate
			want map[string]string
		}{
			{r.bob, map[string]string{"nfltr-machine": "bob-mac", "nfltr-person": "bob@acme.com", "nfltr-groups": "db,dev", "nfltr-service": "pg"}},
			{r.cli, map[string]string{"nfltr-machine": "cli", "nfltr-groups": "db", "nfltr-service": "pg"}},
		} {
			tc := r.open(t, "pg", c.cert)
			br := bufio.NewReader(tc)
			for _, path := range []string{"/1", "/2"} { // a keep-alive session's second request too
				httpRoundTrip(t, tc, br, hostile(path))
				if h := identityOf(<-got["pg"]); !maps.Equal(h, c.want) {
					t.Errorf("%s %s: the app got %v, want %v", c.cert.Leaf.Subject.CommonName, path, h, c.want)
				}
			}
		}
		// An upgrade the app refuses (it answers 200 and keeps the
		// connection) leaves the session HTTP: the next request is
		// rewritten too, and no trailer or Connection token names an
		// identity header (the agent's would be dropped as hop-by-hop).
		reqs := make(chan *http.Request, 4)
		ur := newIDRig(t, IdentityHTTP, func(string) string { return keepAliveApp(t, reqs) })
		tc := ur.open(t, "pg", ur.bob)
		br := bufio.NewReader(tc)
		up := hostile("/upgrade")
		up.Header.Set("Upgrade", "x")
		up.Header.Set("Connection", "Upgrade, Nfltr-Person")
		next := hostile("/next")
		next.Header.Set("Connection", "keep-alive, Nfltr-Person, X-Nfltr-Caller")
		next.TransferEncoding, next.ContentLength = []string{"chunked"}, -1
		next.Body = io.NopCloser(strings.NewReader("body"))
		next.Trailer = http.Header{"Nfltr-Person": {"eve@acme.com"}, "X-Nfltr-Caller": {"eve"}}
		for _, req := range []*http.Request{up, next} {
			httpRoundTrip(t, tc, br, req)
			got := <-reqs
			if h := identityOf(got.Header); !maps.Equal(h, map[string]string{"nfltr-machine": "bob-mac", "nfltr-person": "bob@acme.com", "nfltr-groups": "db,dev", "nfltr-service": "pg"}) {
				t.Errorf("%s after a refused upgrade: the app got %v", req.URL.Path, h)
			}
			if h := identityOf(got.Trailer); len(h) != 0 {
				t.Errorf("%s: the app got trailers %v", req.URL.Path, h)
			}
			for _, v := range got.Header["Connection"] {
				if strings.Contains(strings.ToLower(v), "nfltr") {
					t.Errorf("%s: Connection %q names an identity header", req.URL.Path, v)
				}
			}
		}
		tlvs := make(chan map[byte]string, 1)
		pr := newIDRig(t, IdentityProxyV2, func(string) string { return proxyV2Target(t, tlvs) })
		tc = pr.open(t, "pg", pr.bob)
		if _, err := io.WriteString(tc, "Nfltr-Machine: eve\r\n"); err != nil {
			t.Fatal(err)
		}
		want := map[byte]string{TLVMachine: "bob-mac", TLVPerson: "bob@acme.com", TLVGroups: "db,dev", TLVService: "pg"}
		if got := <-tlvs; !maps.Equal(got, want) {
			t.Errorf("PROXY v2 TLVs %v, want %v", got, want)
		}
	},
	// An assertion verifies under the agent's key (JWKS) for the session's
	// own service only: pg's app refuses one made for vault, and one past
	// exp (mutant jwt-no-aud).
	"svc.aud": func(t *testing.T) {
		target, got := httpApps(t)
		r := newIDRig(t, IdentityHTTP, target)
		jwks := getJWKS(t, r.org)
		jwtOf := func(svc string) string {
			tc := r.open(t, svc, r.bob)
			httpRoundTrip(t, tc, bufio.NewReader(tc), hostile("/"))
			return (<-got[svc]).Get(AssertionHeader)
		}
		pg, vault := jwtOf("pg"), jwtOf("vault")
		cl, err := verifyJWT(pg, jwks, "pg", time.Now())
		if err != nil {
			t.Fatalf("pg's app refused pg's assertion: %v", err)
		}
		if want := (assertionClaims{Iss: "web", Sub: "bob@acme.com", Aud: "pg", Machine: "bob-mac", Person: "bob@acme.com", Groups: []string{"db", "dev"}, Iat: cl.Iat, Exp: cl.Iat + 60}); !equalClaims(cl, want) {
			t.Errorf("claims %+v, want %+v", cl, want)
		}
		if _, err := verifyJWT(vault, jwks, "pg", time.Now()); err == nil {
			t.Error("pg's app took an assertion for vault")
		}
		if _, err := verifyJWT(pg, jwks, "pg", time.Now().Add(AssertionLife+time.Second)); err == nil {
			t.Error("an assertion was good past its exp")
		}
		// Each request's assertion has a jti of its own: an app that keeps
		// them takes the next request's and refuses a replay of the first
		// within its life (mutant jti-fixed).
		seen := map[string]int64{}
		if _, err := verifyOnce(seen, pg, jwks, "pg", time.Now()); err != nil {
			t.Fatalf("the first assertion: %v", err)
		}
		if _, err := verifyOnce(seen, jwtOf("pg"), jwks, "pg", time.Now()); err != nil {
			t.Errorf("the next request's assertion: %v", err)
		}
		if _, err := verifyOnce(seen, pg, jwks, "pg", time.Now()); err == nil {
			t.Error("a replayed assertion was taken again within its life")
		}
	},
}

func equalClaims(a, b assertionClaims) bool {
	return a.Jti != "" && slices.Equal(a.Groups, b.Groups) && a.Iss == b.Iss && a.Sub == b.Sub && a.Aud == b.Aud && a.Machine == b.Machine && a.Person == b.Person && a.Iat == b.Iat && a.Exp == b.Exp
}

// keepAliveApp is a target that answers every request of a connection
// 200, an upgrade too (it ignores Upgrade), and hands each to reqs once
// its body and trailers are read.
func keepAliveApp(t *testing.T, reqs chan<- *http.Request) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck
		br := bufio.NewReader(c)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			reqs <- req
			if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

// proxyV2Target is a target that reads one PROXY v2 header and sends its
// TLVs to tlvs.
func proxyV2Target(t *testing.T, tlvs chan<- map[byte]string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck
		head := make([]byte, 16)
		out := map[byte]string{}
		if _, err := io.ReadFull(c, head); err != nil || string(head[:12]) != proxyV2Sig || head[12] != 0x20 || head[13] != 0 {
			tlvs <- out
			return
		}
		rest := make([]byte, binary.BigEndian.Uint16(head[14:]))
		if _, err := io.ReadFull(c, rest); err != nil {
			tlvs <- out
			return
		}
		for len(rest) >= 3 {
			n := int(binary.BigEndian.Uint16(rest[1:3]))
			out[rest[0]] = string(rest[3 : 3+n])
			rest = rest[3+n:]
		}
		tlvs <- out
	}()
	return ln.Addr().String()
}

// TestSvcAccessModelBindings runs every row, and fails when the model's
// identity ids (svc.hdrwho, svc.aud) and the rows differ; the policy's and
// grants' rows are client/orgid's and org/orgpki's, and client's
// TestEveryModelBindingHasARow checks that every id has one.
func TestSvcAccessModelBindings(t *testing.T) {
	src, err := os.ReadFile(svcAccessModel)
	if err != nil {
		t.Fatal(err)
	}
	rows := slices.Sorted(maps.Keys(svcAccessBindings))
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:(svc\.(?:hdrwho|aud))\s`), rows); err != nil {
		t.Fatalf("%s: %v", svcAccessModel, err)
	}
	for _, id := range rows {
		t.Run(id, svcAccessBindings[id])
	}
}

// Identity is an organisation-mode tcp service's only.
func TestIdentityNeedsOrgTCP(t *testing.T) {
	o := newTestOrg(t)
	org := o.agentOrg(o.machine(t, "web", []string{"db"}, time.Hour, false))
	for _, c := range []struct {
		name string
		s    Service
	}{
		{"plain tcp", Service{Name: "pg", Kind: agentservices.TCP, Target: "127.0.0.1:1", E2EE: agentservices.E2EEOff, Identity: IdentityHTTP}},
		{"http", Service{Name: "web", Kind: agentservices.HTTP, Target: "http://127.0.0.1:1", Identity: IdentityHTTP}},
		{"udp", Service{Name: "dns", Kind: agentservices.UDP, Target: "127.0.0.1:1", E2EE: agentservices.E2EEOn, Org: org, Identity: IdentityProxyV2}},
		{"unknown mode", Service{Name: "pg", Kind: agentservices.TCP, Target: "127.0.0.1:1", E2EE: agentservices.E2EEOn, Org: org, Identity: "headers"}},
	} {
		if _, err := NewServiceTable([]Service{c.s}); err == nil {
			t.Errorf("%s: identity accepted", c.name)
		}
	}
}

// After an upgrade the session's bytes go on as they are, both ways, and
// the client's end reaches the app.
func TestIdentityHTTPUpgrade(t *testing.T) {
	r := newIDRig(t, IdentityHTTP, func(string) string {
		app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			c, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer c.Close() //nolint:errcheck
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
			_ = rw.Flush()
			_, _ = io.Copy(c, rw) // echo until the client's end
		}))
		t.Cleanup(app.Close)
		return app.Listener.Addr().String()
	})
	tc := r.open(t, "pg", r.cli)
	req := hostile("/ws")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "echo")
	if err := req.Write(tc); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, req)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	const raw = "GET / HTTP/1.1\r\nNfltr-Machine: raw\r\n\r\n"
	if _, err := io.WriteString(tc, raw); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(raw)) // before the client's end: a frame goes on as it comes
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != raw {
		t.Fatalf("after the upgrade: %q, %v", echo, err)
	}
	_ = tc.(interface{ CloseWrite() error }).CloseWrite()
	if got, err := io.ReadAll(br); err != nil || len(got) != 0 {
		t.Fatalf("after the client's end: %q, %v", got, err)
	}
}

// A renewal's new key signs the next request of a session open across it,
// and JWKSHandler serves the new key (a new kid); elsewhere than JWKSPath
// it serves nothing, and only to GET and HEAD.
func TestIdentityAssertionAfterRenewal(t *testing.T) {
	target, got := httpApps(t)
	r := newIDRig(t, IdentityHTTP, target)
	tc := r.open(t, "pg", r.cli)
	br := bufio.NewReader(tc)
	httpRoundTrip(t, tc, br, hostile("/1"))
	old, oldSet := (<-got["pg"]).Get(AssertionHeader), getJWKS(t, r.org)
	r.org.renew(t)
	httpRoundTrip(t, tc, br, hostile("/2"))
	next, newSet := (<-got["pg"]).Get(AssertionHeader), getJWKS(t, r.org)
	if _, err := verifyJWT(old, oldSet, "pg", time.Now()); err != nil {
		t.Errorf("before the renewal: %v", err)
	}
	if _, err := verifyJWT(next, newSet, "pg", time.Now()); err != nil {
		t.Errorf("after the renewal, under the served set: %v", err)
	}
	if _, err := verifyJWT(next, oldSet, "pg", time.Now()); err == nil {
		t.Error("the renewed key's assertion verified under the old set")
	}
	for _, c := range []struct {
		method, path string
		code         int
	}{{http.MethodPost, JWKSPath, http.StatusMethodNotAllowed}, {http.MethodGet, "/", http.StatusNotFound}, {http.MethodHead, JWKSPath, http.StatusOK}} {
		w := httptest.NewRecorder()
		JWKSHandler(r.org).ServeHTTP(w, httptest.NewRequest(c.method, c.path, nil))
		if w.Code != c.code {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, w.Code, c.code)
		}
	}
}

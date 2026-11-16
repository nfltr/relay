// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Command harness is the browser extension's e2e world (make browser-e2e;
// nfltr docs/decisions/browser-peer-2026-11-16.md, lane BP4): a relay core
// (github.com/nfltr/relay-core compose.Serve, nf1 and nf1.websocket on) in
// a child process on fixed loopback ports, so a restart is the process's
// exit and a new one (its sessions cut as a relay's exit cuts them), two agents of this checkout's
// client/agent (an echo under an address, and one whose service also takes
// the browser direct path, client/p2p BrowserDirect), and the front: the
// TLS host relay.test the browser maps to it (--host-resolver-rules), which
// passes each WebSocket to the relay, or, while a fault is armed, answers it
// itself with a close code (the codes a relay gives only under conditions a
// test can't make cheaply: balance, draining, reset). It prints one JSON
// line ({front, ctrl, spki}) and serves its control port on loopback:
//
//	GET  /state                  {echo, direct, unknown} addresses
//	POST /fault?code=N&n=K       the next K WebSockets close N (1006: dropped)
//	GET  /count                  WebSockets the front took since the last /count
//	POST /restart                the relay process stops (SIGTERM) and starts again
//
// It exits when its stdin closes (the test runner's end).
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6455's accept key
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/nfltr/relay-core/compose"
	"github.com/nfltr/relay-core/core/frontend"
	"github.com/nfltr/relay-core/core/identity"
	httpingress "github.com/nfltr/relay-core/frontend/http"
	"github.com/nfltr/relay-core/frontend/sni"
	"github.com/nfltr/relay-core/keyfile"
	"github.com/nfltr/relay-core/platform/config"
	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/p2p"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/wsframe"
	"github.com/spf13/viper"
)

const host = "relay.test"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "relay" {
		return serveRelay()
	}
	r, err := newRelay()
	if err != nil {
		return err
	}
	if err := r.start(); err != nil {
		return err
	}
	keyFile, err := os.CreateTemp("", "harness-key")
	if err != nil {
		return err
	}
	defer os.Remove(keyFile.Name()) //nolint:errcheck
	if _, err := keyFile.WriteString(r.key); err != nil {
		return err
	}
	_ = keyFile.Close()
	echo, err := serveAgent(r.grpc, keyFile.Name(), "echo", nil)
	if err != nil {
		return err
	}
	direct, err := serveAgent(r.grpc, keyFile.Name(), "direct", &p2p.BrowserDirect{})
	if err != nil {
		return err
	}
	unknown := echo.Address()
	unknown.RID[0] ^= 0xff

	f, spki, err := newFront(r.proxy)
	if err != nil {
		return err
	}
	ctrl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"echo": echo.Address().String(), "direct": direct.Address().String(), "unknown": unknown.String()})
	})
	mux.HandleFunc("POST /fault", func(w http.ResponseWriter, q *http.Request) {
		code, err1 := strconv.Atoi(q.URL.Query().Get("code"))
		n, err2 := strconv.Atoi(q.URL.Query().Get("n"))
		if err1 != nil || err2 != nil {
			http.Error(w, "code and n", http.StatusBadRequest)
			return
		}
		f.arm(code, n)
	})
	mux.HandleFunc("GET /count", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, f.take()) })
	mux.HandleFunc("POST /restart", func(w http.ResponseWriter, _ *http.Request) {
		if err := r.restart(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	go func() { _ = http.Serve(ctrl, mux) }() // #nosec G114 -- loopback test control
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"front": f.ln.Addr().String(), "ctrl": ctrl.Addr().String(), "spki": spki}); err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	r.stop()
	return nil
}

// relay is a relay core process on fixed loopback ports.
type relay struct {
	key                   string
	proxy, grpc, internal string
	cmd                   *exec.Cmd
}

func newRelay() (*relay, error) {
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	r := &relay{key: "rpc_" + hex.EncodeToString(secret)}
	for _, a := range []*string{&r.proxy, &r.grpc, &r.internal} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		*a = l.Addr().String()
		_ = l.Close()
	}
	return r, nil
}

func (r *relay) start() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	r.cmd = exec.Command(self, "relay") // #nosec G204 -- this binary
	r.cmd.Env = append(os.Environ(), "HARNESS_KEY="+r.key, "HARNESS_PROXY="+r.proxy, "HARNESS_GRPC="+r.grpc, "HARNESS_INTERNAL="+r.internal)
	r.cmd.Stderr = os.Stderr
	if _, err := r.cmd.StdinPipe(); err != nil { // the child ends with this process
		return err
	}
	if err := r.cmd.Start(); err != nil {
		return err
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		res, err := http.Get("http://" + r.internal + "/ready")
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the relay is not ready: %v", err)
		}
	}
}

func (r *relay) stop() {
	_ = r.cmd.Process.Signal(syscall.SIGTERM)
	_ = r.cmd.Wait()
}

func (r *relay) restart() error {
	r.stop()
	return r.start()
}

// serveRelay is the child: the relay core until SIGTERM or its stdin's end.
func serveRelay() error {
	os.Args = os.Args[:1] // the configuration parses the process's argv
	config.SetDefaultFlags()
	for k, v := range map[string]any{
		"tcp.enabled": true, "termination.grace.periodseconds": 1,
		"nf1.enabled": true, "nf1.hosts": []string{host}, "nf1.websocket": true, "nf1.address_max": 64,
	} {
		viper.Set(k, v)
	}
	keys := keyfile.NewAPIKeyStore()
	keys.Add(keyfile.Machine{ID: identity.NewMachineID(), Name: "harness"}, os.Getenv("HARNESS_KEY"))
	var ls compose.Ports
	for _, p := range []struct {
		l    *net.Listener
		addr string
	}{{&ls.Proxy, os.Getenv("HARNESS_PROXY")}, {&ls.GRPC, os.Getenv("HARNESS_GRPC")}, {&ls.Internal, os.Getenv("HARNESS_INTERNAL")}} {
		var err error
		for i := 0; ; i++ { // the port the last process held may linger a moment
			if *p.l, err = net.Listen("tcp", p.addr); err == nil || i == 50 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); stop() }()
	return compose.Serve(ctx, slog.New(slog.DiscardHandler), ls, []frontend.Frontend{httpingress.Frontend{}, sni.Frontend{}}, keyfile.Provider{Store: keys})
}

// serveAgent connects an agent serving an echo under a fresh address of
// host; with bd, its service also takes the browser direct path.
func serveAgent(grpcAddr, keyFile, id string, bd *p2p.BrowserDirect) (*nf1.Listener, error) {
	l, _, err := nf1.Mint(host)
	if err != nil {
		return nil, err
	}
	target, err := echoListener()
	if err != nil {
		return nil, err
	}
	svc := agent.Service{Name: "clip", Kind: agentservices.TCP, E2EE: agentservices.E2EEOn, Target: target, NF1: l}
	if bd != nil {
		svc.BrowserDirect = bd
	}
	table, err := agent.NewServiceTable([]agent.Service{svc})
	if err != nil {
		return nil, err
	}
	decl := agentservices.Format([]agentservices.Decl{{Name: "clip", Kind: agentservices.TCP, E2EE: agentservices.E2EEOn, NF1: l.Address().RID}})
	md := []string{agentservices.Header, decl, agentservices.ModesHeader, "1", agentservices.RegHeader, agentservices.FormatReg(l.Address().RID, l.RegistrationProof())}
	a := agent.New(agent.Config{ServerAddr: grpcAddr, AgentID: id, APIKeyFile: keyFile, Logger: slog.New(slog.DiscardHandler)},
		agent.WithMetadata(md...),
		agent.WithConnected(func(agent.Connection) (*agent.Tunnel, error) { return &agent.Tunnel{Services: table}, nil }))
	if err := a.Connect(context.Background()); err != nil {
		return nil, err
	}
	return l, nil
}

// echoListener is a service that sends back what it reads.
func echoListener() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	go func() {
		for c, err := ln.Accept(); err == nil; c, err = ln.Accept() {
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().String(), nil
}

// front is the TLS host the browser opens.
type front struct {
	ln       net.Listener
	upstream string

	mu      sync.Mutex
	code, n int
	count   int
}

// newFront listens for host's TLS (a fresh self-signed key; spki is its
// SubjectPublicKeyInfo's base64 sha256, for Chromium's
// --ignore-certificate-errors-spki-list).
func newFront(upstream string) (*front, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(pub)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		return nil, "", err
	}
	f := &front{ln: ln, upstream: upstream}
	go func() {
		for c, err := ln.Accept(); err == nil; c, err = ln.Accept() {
			go f.serve(c)
		}
	}()
	return f, base64.StdEncoding.EncodeToString(sum[:]), nil
}

func (f *front) arm(code, n int) {
	f.mu.Lock()
	f.code, f.n = code, n
	f.mu.Unlock()
}

func (f *front) take() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.count
	f.count = 0
	return n
}

func (f *front) serve(c net.Conn) {
	defer c.Close() //nolint:errcheck
	br := bufio.NewReader(c)
	if _, err := br.Peek(1); err != nil {
		return // a connection that sent nothing (a preconnect) is no WebSocket
	}
	f.mu.Lock()
	f.count++
	code := 0
	if f.n > 0 {
		f.n--
		code = f.code
	}
	f.mu.Unlock()
	if code != 0 {
		f.fault(c, br, code)
		return
	}
	up, err := net.Dial("tcp", f.upstream)
	if err != nil {
		return
	}
	defer up.Close() //nolint:errcheck
	go func() { _, _ = io.Copy(up, br); _ = up.(*net.TCPConn).CloseWrite() }()
	_, _ = io.Copy(c, up)
}

// fault answers the WebSocket itself: the upgrade, the rid message, then
// the close code (1006: the connection dropped with no close frame).
func (f *front) fault(c net.Conn, br *bufio.Reader, code int) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	h := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401 -- RFC 6455
	fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: nf1.v1\r\n\r\n", base64.StdEncoding.EncodeToString(h[:]))
	var mr wsframe.MessageReader
	if _, _, err := mr.ReadMessage(br, 1<<20); err != nil || code == 1006 {
		return
	}
	payload := binary.BigEndian.AppendUint16(nil, uint16(code)) // #nosec G115 -- a close code
	_, _ = c.Write(wsframe.AppendFrame(nil, 0x8, append(payload, "harness fault"...), nil))
	_, _, _ = mr.ReadMessage(br, 1<<20) // the browser's close
}

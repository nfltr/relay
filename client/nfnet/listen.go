// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// Caller is who opened an accepted session, as the relay authenticated it
// (never what the caller sent): its machine, group and account ids, and
// the machine's name for display.
type Caller = agent.Caller

// ListenOptions are a listener's choices; zero values are omissions.
type ListenOptions struct {
	// AllowGroups are the organisation groups whose machines may open the
	// service: required in organisation mode (Config.Org set, without
	// Plain or Address), refused otherwise.
	AllowGroups []string
	// Publish also serves the service as <service>@<Publish> (this
	// machine's certificate must carry the group); organisation mode only.
	Publish string
	// Direct lets sessions move to a direct path (organisation mode or an
	// address); DirectOff, the default, keeps them relayed.
	Direct DirectMode
	// Address serves the service under this capability address
	// (nf1.Mint, nf1.NewListener): whoever holds the address may open it;
	// no AllowGroups, Publish or Plain.
	Address *nf1.Listener
	// Plain serves a plain service though Config.Org is set.
	Plain bool
	// Backlog is how many sessions wait for Accept (0: 16). A session
	// beyond it is refused: its client's Dial fails CodeRefused.
	Backlog int
}

// Listener serves one service of an agent named Config.Agent: Accept
// returns its sessions. It owns its agent (the relay link and its
// goroutines); a Conn it accepted rides that link, so Close resets them,
// and Shutdown is the graceful end.
type Listener struct {
	a       agent.Agent
	q       *agent.SessionQueue
	addr    Addr
	address string
	e2ee    bool
	events  func(Event)
	cancel  context.CancelFunc

	mu      sync.Mutex
	conns   map[*Conn]struct{}
	drained chan struct{} // closed when conns empties (Shutdown waits)
	err     error         // the agent's end, once it ended by itself
	closed  bool
	ended   chan struct{} // closed when the agent's watcher returned
}

// Listen connects an agent named cfg.Agent serving service and returns
// its Listener. ctx bounds the first registration only: Listen returns
// once the relay accepted the service, or with the final refusal (CodeAuth,
// CodeUsage), retrying network errors until ctx ends (CodeUnreachable).
// After that the agent reconnects by itself until Close.
func Listen(ctx context.Context, cfg Config, service string, o ListenOptions) (*Listener, error) {
	svc, err := listenService(cfg, service, o)
	if err != nil {
		return nil, err
	}
	q := agent.NewSessionQueue(o.Backlog)
	svc.Queue = q
	table, err := agent.NewServiceTable([]agent.Service{svc})
	if err != nil {
		return nil, usage("Listen: " + err.Error())
	}
	acfg, err := agentConfig(cfg)
	if err != nil {
		return nil, err
	}
	l := &Listener{q: q, addr: Addr{Target: cfg.Agent + "/" + service}, e2ee: svc.E2EE == agentservices.E2EEOn,
		events: cfg.Events, conns: map[*Conn]struct{}{}, ended: make(chan struct{})}
	if o.Address != nil {
		l.address = o.Address.Address().String()
	}
	md := []string{agentservices.Header, table.Declaration(), agentservices.ModesHeader, "1"}
	for _, r := range table.Registrations() {
		md = append(md, agentservices.RegHeader, r)
	}
	l.a = agent.New(acfg,
		agent.WithMetadata(md...),
		agent.WithConnected(func(c agent.Connection) (*agent.Tunnel, error) {
			if err := accepted(c, svc); err != nil {
				return nil, err
			}
			l.agentEvent("connected")
			go func() {
				<-c.Done
				l.agentEvent("reconnecting")
			}()
			return &agent.Tunnel{Services: table}, nil
		}))
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	l.cancel = cancel
	stop := context.AfterFunc(ctx, cancel)
	err = l.a.Connect(life)
	if !stop() && err == nil {
		err = ctx.Err() // ctx ended as the agent connected: not registered within it
		l.a.Close()
	}
	if err != nil {
		cancel()
		_ = q.Close()
		return nil, listenError(ctx, err)
	}
	go l.watch()
	return l, nil
}

// listenService is the service o asks for, its mode chosen by the
// caller's state (ORGCUT): an address, organisation mode with cfg.Org,
// else plain.
func listenService(cfg Config, service string, o ListenOptions) (agent.Service, error) {
	if err := cfg.check(); err != nil {
		return agent.Service{}, err
	}
	switch {
	case !agentservices.ValidName(cfg.Agent):
		return agent.Service{}, usage(fmt.Sprintf("Listen: Config.Agent %q is no agent name (a DNS label starting with a letter)", cfg.Agent))
	case !agentservices.ValidName(service):
		return agent.Service{}, usage(fmt.Sprintf("Listen: service %q is no service name (a DNS label starting with a letter)", service))
	}
	s := agent.Service{Name: service, Kind: agentservices.TCP}
	switch {
	case o.Address != nil:
		if len(o.AllowGroups) > 0 || o.Publish != "" || o.Plain {
			return s, usage("Listen: an Address admits whoever holds it: no AllowGroups, Publish or Plain")
		}
		s.E2EE, s.NF1, s.Direct = agentservices.E2EEOn, o.Address, o.Direct
	case cfg.Org != nil && !o.Plain:
		if len(o.AllowGroups) == 0 {
			return s, usage("Listen: organisation mode needs AllowGroups (whose machines may connect), or Plain for a plain service")
		}
		s.E2EE, s.Org, s.AllowGroups, s.Group, s.Direct = agentservices.E2EEOn, cfg.Org, o.AllowGroups, o.Publish, o.Direct
	default:
		if len(o.AllowGroups) > 0 || o.Publish != "" || o.Direct != DirectOff {
			return s, usage("Listen: AllowGroups, Publish and Direct need organisation mode (Config.Org, without Plain)")
		}
		s.E2EE = agentservices.E2EEOff
	}
	return s, nil
}

// agentConfig is the agent of cfg: one relay credential, cfg's TLS.
func agentConfig(cfg Config) (agent.Config, error) {
	addr := cfg.AgentRelay
	if addr == "" {
		addr = cfg.Relay
	}
	if addr == "" {
		return agent.Config{}, usage("Listen: Config.AgentRelay (or Relay) names no relay")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	a := agent.Config{ServerAddr: addr, AgentID: cfg.Agent, APIKey: cfg.APIKey, TCPTunnel: true, Routes: []agent.Route{},
		Retries: 1 << 30, // until Listen's ctx ends, or a final refusal
		// Close refuses the sessions waiting and resets the accepted: the
		// agent's connection carries those answers before it ends
		// (TestListenerAnswersAtAccept), within this bound.
		Drain:  listenDrain,
		Logger: logger}
	if cfg.Plaintext {
		return a, nil
	}
	t := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.RelayTLS != nil {
		t = cfg.RelayTLS.Clone()
	}
	if cfg.ClientCert != nil {
		get := cfg.ClientCert
		t.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return get() }
	}
	a.TLS, a.TLSConfig = true, t
	return a, nil
}

// listenDrain bounds how long Close waits for its refusals and resets to
// leave on the agent's connection.
const listenDrain = 5 * time.Second

// accepted checks the relay accepted the service as declared: its mode
// as asked, never one the relay chose (ORGCUT).
func accepted(c agent.Connection, s agent.Service) error {
	vals := c.Header.Get(agentservices.Header)
	if len(vals) != 1 {
		return usage("Listen: the relay accepted no services (a relay before service declarations): update the relay")
	}
	got, err := agentservices.Parse(vals[0])
	d, ok := agentservices.Find(got, s.Name)
	switch {
	case err != nil || !ok || d.Kind != agentservices.TCP:
		return usage(fmt.Sprintf("Listen: the relay did not accept service %s as declared (%q)", s.Name, vals[0]))
	case d.E2EE != s.E2EE:
		return usage(fmt.Sprintf("Listen: the relay accepted service %s as e2ee=%s, declared %s", s.Name, d.E2EE, s.E2EE))
	}
	return nil
}

// listenError types a failed first registration.
func listenError(ctx context.Context, err error) error {
	if _, ok := errors.AsType[*Error](err); ok {
		return err
	}
	if ctx.Err() != nil {
		return &Error{Code: CodeUnreachable, Message: "Listen: not registered with the relay within ctx: " + err.Error(), Err: err}
	}
	if code := CodeOf(err); code != CodeUnreachable && code != 0 {
		return &Error{Code: code, Message: "Listen: " + err.Error(), Err: err}
	}
	return &Error{Code: CodeAuth, Message: "Listen: the relay refused the agent: " + err.Error(), Err: err}
}

// watch ends the listener's queue when its agent ended by itself (a final
// refusal, a takeover): Accept then returns why.
func (l *Listener) watch() {
	defer close(l.ended)
	<-l.a.Done()
	l.mu.Lock()
	if !l.closed && l.a.Err() != nil {
		l.err = &Error{Code: CodeOf(l.a.Err()), Message: "the listener's agent ended: " + l.a.Err().Error(), Err: l.a.Err()}
	}
	l.mu.Unlock()
	_ = l.q.Close()
}

func (l *Listener) agentEvent(state string) {
	if l.events != nil {
		l.events(Event{Kind: "agent", Reason: state, Target: l.addr.Target})
	}
}

// Accept waits for the next session and answers it open: a *Conn. After
// Close or Shutdown it returns net.ErrClosed; after the agent ended by
// itself, an *Error saying why.
func (l *Listener) Accept() (net.Conn, error) {
	nc, err := l.q.Accept()
	if err != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.err != nil {
			return nil, l.err
		}
		return nil, err
	}
	qc := nc.(*agent.QueueConn)
	var b [4]byte
	_, _ = rand.Read(b[:])
	c := &Conn{s: qc, done: qc.Done(), id: "s-" + hex.EncodeToString(b[:]), events: l.events, e2ee: l.e2ee, target: Target{Kind: AgentTarget, Agent: l.addr.Target}}
	if cl, ok := qc.Caller(); ok {
		c.caller = &cl
		c.remote = cl.MachineName
	}
	c.closers = append(c.closers, func() { l.forget(c) })
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = qc.Reset()
		return nil, net.ErrClosed
	}
	l.conns[c] = struct{}{}
	l.mu.Unlock()
	c.emit(Event{Kind: "open"})
	return c, nil
}

func (l *Listener) forget(c *Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.conns, c)
	if len(l.conns) == 0 && l.drained != nil {
		close(l.drained)
		l.drained = nil
	}
}

// Addr is the listener's address: <agent>/<service>.
func (l *Listener) Addr() net.Addr { return l.addr }

// Address is the nf1 address text when the listener serves under one
// (ListenOptions.Address), else "". It is the capability: whoever holds
// it may open the service.
func (l *Listener) Address() string { return l.address }

// Shutdown refuses new sessions (their clients get CodeRefused), waits
// for the accepted ones to end (their Close or Reset) or ctx, then ends
// the agent; the Conns still open at ctx's end are reset (ctx.Err()).
func (l *Listener) Shutdown(ctx context.Context) error {
	_ = l.q.Close()
	l.mu.Lock()
	var wait chan struct{}
	if len(l.conns) > 0 {
		if l.drained == nil {
			l.drained = make(chan struct{})
		}
		wait = l.drained
	}
	l.mu.Unlock()
	var err error
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	_ = l.Close()
	return err
}

// Close ends the agent now: sessions waiting are refused, accepted Conns
// reset (they ride its link).
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	conns := make([]*Conn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	_ = l.q.Close()
	for _, c := range conns {
		_ = c.Reset()
	}
	l.a.Close()
	l.cancel()
	<-l.ended
	return nil
}

// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package agentwire is the request metadata every relay client sends on its
// agent streams and the relay reads: the agent's labels and the client's
// own identity. One owner for both ends, so a sender and the relay cannot
// disagree on a key or an encoding again (pkg/agent sent labels as
// x-label-<k>, which no relay code read).
//
// The v1 session Hello replaces these keys (ClientInfo, Hello.labels).
package agentwire

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
)

// LabelsKey carries an agent's labels as one JSON object of strings, so a
// value may hold ',' and '=' (nfltr.machine.resources=cpu:16,mem:64GB).
const LabelsKey = "x-agent-labels"

// MoveKey, set to "1" in an agent's ConnectHTTP (and ConnectTCP) metadata,
// says the agent can move off a leaving relay replica make-before-break
// (pb.Move): the relay asks it to reconnect instead of letting it go.
const MoveKey = "x-agent-move"

// HeartbeatKey, in the relay's response headers on an agent stream
// (ConnectHTTP, AgentTunnel), is how often in milliseconds the relay sends a
// heartbeat on that stream when it has sent nothing else for that long. A
// relay without heartbeats, or one older than this key, sends none.
const HeartbeatKey = "x-relay-heartbeat-ms"

// HeartbeatAskKey, in an agent's stream metadata, is the heartbeat interval
// in milliseconds it asks for (its Liveness.Interval). A relay that honours
// it keeps it within its bounds and states what it keeps in HeartbeatKey;
// an older relay ignores it.
const HeartbeatAskKey = "x-agent-heartbeat-ms"

// LinkLivenessKey, set to "1" in the relay's response headers on an
// agent's ConnectHTTP stream, says the relay takes that agent's liveness
// from its agent link (dataplane.AgentLinkHeader) while the link is up: the
// agent need not answer the relay's heartbeats then, and the relay does not
// end the stream for their silence (an agent link that goes silent past its
// liveness ends the agent's streams instead). A relay without the key ends
// an agent whose heartbeats stop: the agent answers every one.
const LinkLivenessKey = "x-relay-link-liveness"

// HeartbeatPairs is the key/value pair carrying interval under key
// (HeartbeatKey or HeartbeatAskKey); none for no interval.
func HeartbeatPairs(key string, interval time.Duration) []string {
	if interval <= 0 {
		return nil
	}
	return []string{key, strconv.FormatInt(interval.Milliseconds(), 10)}
}

// Heartbeat reads the interval md carries under key; 0 when it carries none
// or nonsense (not a positive number of milliseconds up to an hour).
func Heartbeat(md map[string][]string, key string) time.Duration {
	vals := md[key]
	if len(vals) == 0 {
		return 0
	}
	ms, err := strconv.ParseInt(vals[0], 10, 64)
	if err != nil || ms <= 0 || ms > int64(time.Hour/time.Millisecond) {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// EncodeLabels is the LabelsKey value for labels, "" for none.
func EncodeLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	raw, _ := json.Marshal(labels) // a map of strings always encodes
	return string(raw)
}

// ParseLabels decodes one LabelsKey value: nil when it is empty or not a
// JSON object of strings.
func ParseLabels(raw string) map[string]string {
	var labels map[string]string
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &labels) != nil || len(labels) == 0 {
		return nil
	}
	return labels
}

// The agent-wire session handshake (nfltr.relay.v1 Hello/Welcome), binary
// metadata on every call to the relay's agent service: the client sends
// Hello, the relay answers Welcome or refuses the call.
const (
	HelloKey        = "nfltr-hello-bin"
	WelcomeKey      = "nfltr-welcome-bin"
	ProtocolVersion = 1
)

// ClientTooOld is the relay's refusal of a call without a protocol v1
// Hello: every client released before the hard cut.
const ClientTooOld = "this nfltr is too old for this relay: it does not speak relay protocol v1; run `nfltr update`"

// RelayTooOld is a v1 client's error for a reply without a Welcome: a relay
// released before the hard cut.
const RelayTooOld = "the relay does not speak relay protocol v1: it is older than this client; update the relay (a relay you run: install the release matching this nfltr)"

// MaxClientField bounds each identity value the relay accepts.
const MaxClientField = 64

// Client names a client program: "nfltr", or the binary of an SDK user.
type Client struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Build   string `json:"build,omitempty"` // VCS revision
}

// built is the binary's own identity, read on first use (not in init:
// every nfltr process pays for init, most never open a stream).
var built = sync.OnceValue(func() Client {
	c := Client{Name: strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return c
	}
	c.Version = bi.Main.Version
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			c.Build = s.Value[:min(12, len(s.Value))]
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if dirty && c.Build != "" {
		c.Build += "-dirty"
	}
	return c
})

// named is SetClient's name and version, nil until it is called.
var named atomic.Pointer[[2]string]

// SetClient names this process's client and its version; the build stays
// the binary's VCS revision. A binary calls it once at startup (nfltr:
// main); otherwise the name is the executable's and the version the main
// module's. allow:wrapper (a setter)
func SetClient(name, version string) { named.Store(&[2]string{name, version}) }

// Self is this process's client identity.
func Self() Client {
	c := built()
	if n := named.Load(); n != nil {
		c.Name, c.Version = n[0], n[1]
	}
	return c
}

// HelloPairs is c's Hello as request metadata key/value pairs (grpc
// metadata.Pairs, AppendToOutgoingContext).
func (c Client) HelloPairs() []string {
	b, _ := proto.Marshal(&relayv1.Hello{ProtocolVersion: ProtocolVersion, Client: &relayv1.ClientInfo{Name: c.Name, Version: c.Version, Build: c.Build}})
	return []string{HelloKey, string(b)}
}

// ParseHello reads a call's Hello from its request metadata (a grpc
// metadata.MD) and returns its client. It fails on a call without one, or
// with another protocol version. A client field is client input: one
// longer than MaxClientField or with a character outside [A-Za-z0-9._+()-]
// reads as "invalid", so it is safe as a metric label and in a listing.
func ParseHello(md map[string][]string) (Client, error) {
	vals := md[HelloKey]
	if len(vals) == 0 {
		return Client{}, errors.New("no hello")
	}
	var h relayv1.Hello
	if err := proto.Unmarshal([]byte(vals[0]), &h); err != nil {
		return Client{}, fmt.Errorf("hello: %w", err)
	}
	if h.GetProtocolVersion() != ProtocolVersion {
		return Client{}, fmt.Errorf("hello: protocol version %d, want %d", h.GetProtocolVersion(), ProtocolVersion)
	}
	ci := h.GetClient()
	return Client{Name: clientField(ci.GetName()), Version: clientField(ci.GetVersion()), Build: clientField(ci.GetBuild())}, nil
}

// WelcomePairs is the relay's Welcome as response header key/value pairs.
func WelcomePairs(relayVersion string) []string {
	b, _ := proto.Marshal(&relayv1.Welcome{ProtocolVersion: ProtocolVersion, RelayVersion: relayVersion})
	return []string{WelcomeKey, string(b)}
}

// HasWelcome reports whether response headers carry a protocol v1 Welcome.
func HasWelcome(md map[string][]string) bool {
	vals := md[WelcomeKey]
	var w relayv1.Welcome
	return len(vals) > 0 && proto.Unmarshal([]byte(vals[0]), &w) == nil && w.GetProtocolVersion() == ProtocolVersion
}

func clientField(v string) string {
	if len(v) > MaxClientField {
		return "invalid"
	}
	for _, r := range v {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._+()-", r)
		if !ok {
			return "invalid"
		}
	}
	return v
}

// LifetimeLabel is the connect label an agent process sets to declare how
// long its relay registration should live. Absent means durable: the registry
// row survives disconnects (stable URL, offline 503). The only declarable
// value is LifetimeEphemeral, for a per-run process whose id is never reused:
// the relay removes its row when its stream closes.
const (
	LifetimeLabel     = "nfltr.lifetime"
	LifetimeEphemeral = "ephemeral"
)

package machinecred

import "testing"

// A certificate saved by the relay's enrol-code --dir names the relay's
// gRPC host:port (relay_host "rpc-rpc-server:9090"); it is still the
// certificate for that relay's connections (2026-11-18, the kind site agent
// found no credential).
func TestSameRelayTakesAHostPort(t *testing.T) {
	for _, c := range []struct {
		host, server string
		want         bool
	}{
		{"rpc-rpc-server:9090", "rpc-rpc-server:9090", true},
		{"rpc-rpc-server", "rpc-rpc-server:9090", true},
		{"relay.example:9090", "https://relay.example", true},
		{"relay.example", "grpc.relay.example:443", true},
		{"other:9090", "rpc-rpc-server:9090", false},
	} {
		if got := sameRelay(c.host, c.server); got != c.want {
			t.Errorf("sameRelay(%q, %q) = %v, want %v", c.host, c.server, got, c.want)
		}
	}
}

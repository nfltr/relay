// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestModuleBoundary: the SDK links nothing of nfltr's but itself and the
// protocol module (the agent wire proto/pb included), the link layer
// (github.com/nfltr/link) and nfltr's quic-go fork that quiclink uses
// (github.com/nfltr/quic-go): an SDK user never compiles relay server code.
func TestModuleBoundary(t *testing.T) {
	checkDeps(t, "github.com/nfltr/relay/client/", "github.com/nfltr/relay/proto/", "github.com/nfltr/link/", "github.com/nfltr/quic-go/")
}

// TestRelayConnsGoThroughGRPCClient: every gRPC connection the SDK makes
// is grpcclient's, whose options send the Hello and the client generation
// (grpcclient.ClientIdentity), so no connect path can omit them.
func TestRelayConnsGoThroughGRPCClient(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			strings.HasPrefix(path, "grpcclient"+string(filepath.Separator)) {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, call := range []string{"grpc.NewClient(", "grpc.Dial(", "grpc.DialContext("} {
			if strings.Contains(string(b), call) {
				t.Errorf("%s calls %s: dial the relay with grpcclient (ClientIdentity)", path, call)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAgentDoesNotLinkWireGuard: wireguard-go and gvisor reach a program only
// through client/agent/wgexit (or client/wg), never through client/agent.
func TestAgentDoesNotLinkWireGuard(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./agent").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for p := range strings.FieldsSeq(string(out)) {
		if strings.HasPrefix(p, "gvisor.dev/") || strings.HasPrefix(p, "golang.zx2c4.com/wireguard") || p == "github.com/nfltr/relay/client/wg" {
			t.Errorf("client/agent links %s: keep WireGuard in client/agent/wgexit", p)
		}
	}
}

func TestSourceFilesCarryLicenseHeader(t *testing.T) {
	checkLicenseHeaders(t, ".")
}

func checkDeps(t *testing.T, allowed ...string) {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "-test", "-f", "{{.ImportPath}}", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for p := range strings.FieldsSeq(string(out)) {
		p = strings.TrimSuffix(strings.TrimSuffix(strings.Fields(p)[0], ".test"), "_test")
		if !strings.HasPrefix(p, "github.com/nfltr/") {
			continue
		}
		ok := false
		for _, a := range allowed {
			ok = ok || strings.HasPrefix(p+"/", a) || p == a
		}
		if !ok {
			t.Errorf("links %s", p)
		}
	}
}

func checkLicenseHeaders(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		switch filepath.Ext(path) {
		case ".go", ".proto", ".yaml":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.SplitN(string(data), "\n", 4)
		if !strings.Contains(strings.Join(lines[:min(3, len(lines))], "\n"), "SPDX-License-Identifier: Apache-2.0") {
			t.Errorf("%s: no SPDX-License-Identifier: Apache-2.0 header in its first lines", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/nfltr/relay/client/machinecred"
)

// A program talking to the relay as this machine: the certificate
// `nfltr config login` saved in the nfltr config directory, renewed in the
// background, presented on the relay's HTTP API (RelayTLS is the same
// credential for a gRPC dial).
func ExampleForRelay() {
	home, _ := os.UserConfigDir()
	dir := filepath.Join(home, "nfltr")
	cred := machinecred.ForRelay(dir, "grpc.nfltr.xyz:443")
	if cred == nil {
		fmt.Println("this machine is not enrolled with that relay: run `nfltr config login`")
		return
	}
	ctx := context.Background()
	defer cred.Run(ctx, slog.Default())() // renews until ctx ends; stop waits for the renewer
	self, err := machinecred.Machines("https://nfltr.xyz", cred.HTTPClient())(ctx, "")
	if err != nil {
		fmt.Println(cred.Refusal(err)) // ErrRefused when the relay refused the certificate
		return
	}
	fmt.Println("this machine is", self)
}

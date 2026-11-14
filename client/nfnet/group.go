// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nfltr/relay/proto/wire/dataplane"
)

// A group dial names a service by organisation group, <service>@<group>
// (nfltr docs/decisions/service-discovery-2026-11-12.md section 3): the
// relay picks one online instance per open, the client checks the server
// is a machine of the group serving the service (its certificate's OU, the
// negotiated ALPN), never which machine. Organisation mode only.

// groupRetryWait spaces the opens of a group dial whose last refusal named
// no certificate to exclude (the agent ended the handshake before sending
// one: no_application_protocol), as a held open is.
const groupRetryWait = 250 * time.Millisecond

// retryGroup runs open for a group dial until it is not a refusal of the
// end-to-end check (CodeE2EEPinMismatch): each refused certificate's
// machine is excluded from the next open's pick (pb.TCPData.exclude, at
// most dataplane.MaxExclude), until ctx ends. When the relay then finds no
// instance left (every one refused) or ctx ends, the answer is the last
// refusal with the instances tried. Any other failure is the relay's or the
// agent's answer, the same on every instance, and returned as it is.
// Another target runs open once.
func retryGroup(ctx context.Context, t Target, open func(exclude []string) error) error {
	if t.Kind != GroupTarget {
		return open(nil)
	}
	var exclude, tried []string
	var last *Error
	final := func() error {
		last.Message = fmt.Sprintf("the server is not a machine of group %s serving %s: %d instance(s) tried: %s",
			t.Group, t.Service, len(tried), strings.Join(tried, ", "))
		return last
	}
	for {
		err := open(exclude)
		e, isE := errors.AsType[*Error](err)
		switch {
		case isE && e.Code == CodeE2EEPinMismatch:
		case last != nil && isE && e.Code == CodeNotFound:
			return final() // none left but the refused ones
		case last != nil && isE:
			e.Message += fmt.Sprintf("; %d refused before it: %s", len(tried), strings.Join(tried, ", "))
			return err
		default:
			return err
		}
		last = e
		who := e.peer
		if who == "" {
			who = "an instance"
		}
		tried = append(tried, who+" ("+e.Message+")")
		added := e.peer != "" && !slices.Contains(exclude, e.peer) && len(exclude) < dataplane.MaxExclude
		if added {
			exclude = append(exclude, e.peer)
		}
		wait := time.Duration(0)
		if !added {
			wait = groupRetryWait
		}
		select {
		case <-ctx.Done():
			return final()
		case <-time.After(wait):
		}
	}
}

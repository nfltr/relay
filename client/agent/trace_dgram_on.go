// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package agent

import "github.com/nfltr/relay/client/internal/dgtrace"

// traceBind records an end's bind of its association to the direct path
// (relay spec/DatagramAssoc.tla BindA, BindC) in client/dgram's trace,
// for a session that carries an association (its receiver set).
func (d *sessionDatagrams) traceBind(ev string) {
	if d.on.Load() != nil {
		dgtrace.Line(`{"ev":"` + ev + `"}`)
	}
}

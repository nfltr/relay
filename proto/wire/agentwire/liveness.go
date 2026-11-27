// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agentwire

// Liveness and its presets are link API (github.com/nfltr/link
// liveness.go): these names are the link's. The nfltr CLI,
// its YAML and env, and the relay chart only map names onto that table.

import "github.com/nfltr/link"

// Liveness is how a connection notices its peer is gone without a FIN.
// On an agent's relay connection the relay sends the frames (its
// heartbeat): the agent asks for Interval, the relay states the interval it
// keeps, and the agent waits DeadAfter(stated).
type Liveness = link.Liveness

// The presets (link.LivenessDefault and its siblings).
var (
	LivenessDefault    = link.LivenessDefault
	LivenessFast       = link.LivenessFast
	LivenessNAT        = link.LivenessNAT
	LivenessDatacenter = link.LivenessDatacenter
	LivenessMobile     = link.LivenessMobile
	LivenessPresets    = link.LivenessPresets
)

// Bounds Validate enforces: every relay keeps an interval in
// [MinLivenessInterval, MaxLivenessInterval].
const (
	MinLivenessInterval = link.MinLivenessInterval
	MaxLivenessInterval = link.MaxLivenessInterval
)

// ParseLiveness reads a preset name, raw values or both (link.ParseLiveness).
// allow:wrapper
func ParseLiveness(spec string) (Liveness, error) { return link.ParseLiveness(spec) }

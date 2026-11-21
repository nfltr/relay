// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package agent

import "time"

type roundTrace struct{}

func traceRound() roundTrace                                        { return roundTrace{} }
func (roundTrace) start(int)                                        {}
func (roundTrace) sync(time.Duration)                               {}
func (roundTrace) dial(time.Duration, time.Duration, time.Duration) {}
func (roundTrace) result(string)                                    {}
func (roundTrace) end()                                             {}

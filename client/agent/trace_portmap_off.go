// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package agent

type portMapTrace struct{}

func (*portMapTrace) line(string, string, bool, uint32) {}
func (*portMapTrace) end()                              {}

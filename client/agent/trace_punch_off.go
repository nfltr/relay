// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package agent

type punchTrace struct{}

func tracePunch([]string) punchTrace  { return punchTrace{} }
func (punchTrace) learn(string, bool) {}
func (punchTrace) up(string, bool)    {}
func (punchTrace) fail(string)        {}
func (punchTrace) end(string)         {}

// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package agent

type punchTrace struct{}

func tracePunch([]string, []string) punchTrace { return punchTrace{} }
func (punchTrace) learn(string, bool, bool)    {}
func (punchTrace) up(string, bool)             {}
func (punchTrace) closeLoser(string)           {}
func (punchTrace) settle()                     {}
func (punchTrace) fail(string, bool, error)    {}
func (punchTrace) end(string)                  {}

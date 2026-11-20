// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package tlsend

func (c *Conn) trace(string, int) {}

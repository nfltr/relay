// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package agent

func (d *sessionDatagrams) traceBind(string) {}

// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !enroltrace

// Package audittrace records the issuer's steps of spec/MoveAudit.tla
// (relay spec/README.md "AuditLog and MoveAudit traces"). Built only with
// -tags enroltrace (on.go, AUDITTRACE=<dir>); here it compiles away.
package audittrace

// Line records one step.
func Line(map[string]any) {}

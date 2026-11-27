// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine

import "github.com/nfltr/relay/client/orgaudit"

// The audit's internals, for the external tests (audit_test.go): a
// process's kill (its owner lock freed), a close line without its owner
// file's prune, an owner file's line without its open line.
const OwnersDir = ownersDir

func KillOwner(m *Machine)                     { m.own.release() }
func WriteAudit(m *Machine, r orgaudit.Record) { m.writeAudit(r) }
func AddOwned(m *Machine, session string)      { m.own.add(m.dir, session) }

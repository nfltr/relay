// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid_test

import (
	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/orgid"
)

// An Identity is what client/agent takes for an organisation service and
// for a client's direct paths.
var (
	_ agent.Org           = (*orgid.Identity)(nil)
	_ agent.DirectMachine = (*orgid.Identity)(nil)
)

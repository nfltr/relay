// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

// e2eeShareBindings are the agent's rows of github.com/nfltr/relay-core
// spec/proverif/e2ee_share.pv (its relay.* BIND ids; relay-core's
// TestE2EEShareModelBindings lists them in shareForeignRows and fails when
// the model's differ).
var e2eeShareBindings = map[string]func(t *testing.T){
	// AgentEnforcing's h(cred) = h(pw) (agent-skips-credential): a visitor
	// with no credential, the wrong one, or one of another kind
	"relay.agent.cred": TestSharePolicyEnforcedPerRequest,
}

// TestE2EEShareModelBindingsAgent runs the agent's rows (`make spec-bindings`).
func TestE2EEShareModelBindingsAgent(t *testing.T) {
	for id, row := range e2eeShareBindings {
		t.Run(id, row)
	}
}

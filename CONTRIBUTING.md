# Contributing

1. Open an issue before a large change, so we can agree on the shape first.
2. Keep a change to one module when you can; a change that needs both lands
   `proto/` first.
3. Run `make ci` (what `.github/workflows/ci.yml` runs, read from it; `make hooks`
   installs a pre-push hook that runs it for pushes to main and tags), or
   `make build vet test test-race` (and `make fuzz-short` when you touch
   a parser) before sending a pull request.
4. Every source file starts with the licence header:

   ```go
   // Copyright 2026 nfltr
   // SPDX-License-Identifier: Apache-2.0
   ```

   `make proto-gen` adds it to generated code; `TestSourceFilesCarryLicenseHeader`
   fails without it.
5. Wire changes are additive: never renumber or reuse a proto field, and add
   a new feature name rather than changing what an existing one means.

By contributing you agree that your contribution is licensed under the
Apache License 2.0.

## Verify the design with TLA+ before writing code

A change to a protocol, the wire format, concurrency, storage or a
cross-process state machine, whose bugs would be silent (lost, duplicated or
reordered data; a session, lease or grant that never ends or is used twice; a
revocation that does not take effect), starts as a TLA+ spec of the design in
`spec/` of the module that owns the state machine (the agent's frame streams are modelled in github.com/nfltr/relay-core `spec/AgentLink.tla`; change that spec first). Check it with TLC before any code: the invariants and liveness
properties hold, `-coverage 1` shows every action taken, and a planted
mutant of each failure the design prevents is caught. Code starts only after
that check passes. The spec change lands before or with the code, and the
trace recorder then validates the implementation against the spec.

Each layer's spec states what the layer above may assume; the agent and client specs assume only what the link and the relay core guarantee. Every bug found
becomes a mutant the checker must catch. The small checks run in `make ci`;
the larger configs, liveness and trace checks run nightly. Not for CLI,
docs, handlers, config or value transforms: tests and fuzzing cover those.

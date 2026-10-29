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

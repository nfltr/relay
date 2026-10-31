# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

MODULES := proto client

.PHONY: build vet test test-race fuzz-short proto-gen proto-report check-gosec check-semgrep check-no-legacy-name tidy
build:
	@for m in $(MODULES); do (cd $$m && go build ./...) || exit 1; done

vet:
	@for m in $(MODULES); do (cd $$m && go vet ./...) || exit 1; done

test:
	@for m in $(MODULES); do (cd $$m && go test -count=1 ./...) || exit 1; done

test-race:
	@for m in $(MODULES); do (cd $$m && go test -count=1 -race ./...) || exit 1; done

# FUZZTIME per target (default 10s).
fuzz-short:
	./scripts/fuzz-short.sh

# Needs buf and the protoc-gen-go, protoc-gen-go-grpc, protoc-gen-grpc-gateway plugins.
proto-gen:
	./scripts/proto-gen.sh

# buf lint + breaking of proto/pb (the agent wire) vs PROTO_BASELINE; report only.
proto-report:
	./scripts/proto-report.sh

# Pinned SAST gated by scripts/{gosec,semgrep}-baseline.txt (semgrep needs docker).
check-gosec:
	./scripts/check-gosec.sh

check-semgrep:
	./scripts/check-semgrep.sh

# scripts/check-identity.sh (the pre-push hook's) refuses what it should.
.PHONY: test-identity
test-identity:
	./scripts/check-identity_test.sh

# The relay's old name stays out of tracked files (see the script).
check-no-legacy-name:
	./scripts/check-no-legacy-name.sh

tidy:
	@for m in $(MODULES); do (cd $$m && GOWORK=off go mod tidy) || exit 1; done

CI_WORKFLOW_FILE := .github/workflows/ci.yml
# ci: what the GitHub workflow runs on a push (CI_WORKFLOW_FILE), run here.
# GitHub Actions is not a gate; this is, before a push (the pre-push hook)
# and after it (nfltr's Linux CI runner). scripts/ci.sh reads the steps from
# the workflow file itself, so the two cannot drift; a pass on a clean tree
# is stamped and not rerun for the same tree.
# hooks: install the pre-push hook (scripts/pre-push): `make ci` on the
# exact commit pushed to main or a tag; bypass only with
# NFLTR_CI_BYPASS=<reason> (logged to <git-common-dir>/ci-bypass.log).
.PHONY: ci hooks
ci:
	@CI_WORKFLOW=$(CI_WORKFLOW_FILE) ./scripts/ci.sh
hooks:
	@h="$$(git rev-parse --git-path hooks)/pre-push"; \
	if [ -e "$$h" ] && ! grep -q 'scripts/pre-push' "$$h"; then echo "hooks: $$h exists and is not this one; move it away first" >&2; exit 1; fi; \
	printf '#!/bin/sh\n# make hooks: scripts/pre-push of the checkout pushing (else of %s)\ns="$$(git rev-parse --show-toplevel)/scripts/pre-push"\n[ -x "$$s" ] || s=%s/scripts/pre-push\nexec "$$s" "$$@"\n' "$(CURDIR)" "$(CURDIR)" >"$$h" && chmod +x "$$h" && echo "hooks: installed $$h"

# Fails when a _test.go file assigns a package-level variable of its package
# (allow-list with reasons: scripts/testknobs-allow.txt). The tool lives in
# proto (stdlib only) and runs from the repository root over both modules.
.PHONY: check-testknobs stress-race
check-testknobs:
	@d=$$(mktemp -d) && (cd proto && GOWORK=off go build -o $$d/testknobs ./internal/tools/testknobs) && $$d/testknobs -allow scripts/testknobs-allow.txt client proto; rc=$$?; rm -rf $$d; exit $$rc

# link's debug mode (-tags linkdebug): vet with the tag, and the tests of the
# packages that import link with the tag (no -race: scripts/test-linkdebug.sh);
# fails on any "link debug:" report (leakcheck).
.PHONY: test-linkdebug
test-linkdebug:
	./scripts/test-linkdebug.sh client proto

# test-race, then test-linkdebug beside fuzz-short (the CI step).
.PHONY: test-ci
test-ci:
	./scripts/test-ci.sh

# linkvet (github.com/nfltr/link/linkvet at the version scripts/check-linkvet.sh
# pins) over the non-test code: fails on a finding scripts/linkvet-allow.txt
# does not list (each entry with a reason) and on a stale entry.
.PHONY: check-linkvet
check-linkvet:
	./scripts/check-linkvet.sh ./client/... ./proto/...

# stress-race PKGS='./client/agent ./proto/wire/chunking' [COUNT=50]: the
# packages' tests repeated under the race detector (paths from the repository
# root; each is run in its module).
COUNT ?= 50
stress-race:
	@test -n "$(PKGS)" || { echo "stress-race: PKGS='<packages>' is required, e.g. make stress-race PKGS=./client/agent" >&2; exit 2; }
	@for p in $(PKGS); do m=$${p#./}; m=$${m%%/*}; (cd $$m && go test -race -count=$(COUNT) ./$${p#./$$m/} ) || exit 1; done

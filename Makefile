# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

MODULES := proto client

.PHONY: build vet test test-race fuzz-short proto-gen proto-report check-gosec check-semgrep check-no-legacy-name tidy
build:
	@for m in $(MODULES); do (cd $$m && go build ./...) || exit 1; done

vet:
	@for m in $(MODULES); do (cd $$m && go vet ./...) || exit 1; done

# check-fmt: gofmt (the toolchain's, not one on PATH) changes no tracked Go
# file (vendor/ aside); go vet and the tests accept unformatted code.
check-fmt:
	@out="$$("$$(go env GOROOT)/bin/gofmt" -l $$(git ls-files '*.go' | grep -v '^vendor/'))"; \
	if [ -n "$$out" ]; then echo "gofmt would change:"; echo "$$out"; exit 1; fi

test:
	@for m in $(MODULES); do (cd $$m && go test -count=1 ./...) || exit 1; done

test-race:
	@for m in $(MODULES); do (cd $$m && go test -count=1 -race ./...) || exit 1; done

# test-under-load: PKGS with -count LOAD_COUNT (5) on a starved machine
# (scripts/test-under-load.sh, the same file in link, relay and relay-core):
# a test that waits a fixed time for what a busy machine does later fails
# here; wait for the event or state instead, with a bound only against a hang.
LOAD_COUNT ?= 5
.PHONY: test-under-load
test-under-load:
	@test -n "$(PKGS)" || { echo "test-under-load: PKGS='<packages>' is required" >&2; exit 2; }
	@./scripts/test-under-load.sh $(LOAD_COUNT) $(PKGS)

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
# hooks: install the pre-push hook (scripts/pre-push): a push to main or a
# tag needs nfltr's Linux runner's green result for that sha; bypass only with
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

# The TLA+ models (spec/README.md): spec checks them, spec-mutants checks
# each bug put back is caught (both in make ci); spec-traces checks the
# traces the tests record under -tags relaytrace against them (nightly);
# spec-cltraces is its per-push slice (the stuck-handler test's CallLifecycle
# traces, about 10 s; in make ci); spec-astraces another (the A2A E2EE
# session tests' A2ASession traces, about 10 s; in make ci).
.PHONY: spec spec-mutants spec-traces spec-cltraces spec-astraces spec-proverif spec-bindings
spec:
	./scripts/spec.sh check
spec-mutants:
	./scripts/spec.sh mutants
spec-traces:
	./scripts/spec.sh traces
spec-cltraces:
	./scripts/spec.sh cltraces
spec-astraces:
	./scripts/spec.sh astraces
# The ProVerif models (spec/proverif/README.md): every line of
# spec/proverif/expect.txt, mutants included (in make ci).
spec-proverif:
	./spec/proverif/run.sh
# The models' bindings against the code (spec/proverif/README.md
# "Bindings"): each BIND id a model lists has a test row that changes that
# field of an honest message, as a relay can, and requires a refusal; the
# test fails when a model's ids and its rows differ (in make ci).
spec-bindings:
	cd client && go test -count=1 -run 'ModelBindings' ./rpcclient/ ./agent/ ./agent/wgexit/

# test-go-mutants (in make ci, about a minute): every planted bug of a Go
# mutant list (client/agent/testdata/org_mutants.txt: the agent's
# organisation mode) makes its test fail (scripts/go-mutants.sh).
.PHONY: test-go-mutants
test-go-mutants:
	./scripts/go-mutants.sh client/agent/testdata/org_mutants.txt

# Spec drift (scripts/check-spec-drift.sh, a copy of nfltr's, kept
# identical; its test is nfltr's scripts/check_spec_drift_test.sh): every
# spec README's code-map entry exists, and the commits since origin/main
# that change a file a code map lists change that spec too or carry
# `Spec-Reviewed: <spec> <reason>`. The pre-push hook checks the pushed range.
.PHONY: check-spec-drift
check-spec-drift:
	./scripts/check-spec-drift.sh maps
	./scripts/check-spec-drift.sh ci

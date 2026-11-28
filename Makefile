# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

MODULES := proto client org

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
# A nested module's: PKGS='-C client .'.
LOAD_COUNT ?= 5
.PHONY: test-under-load
test-under-load:
	@test -n "$(PKGS)" || { echo "test-under-load: PKGS='<packages>' is required" >&2; exit 2; }
	@./scripts/test-under-load.sh $(LOAD_COUNT) $(PKGS)
# stress-flaky: every known-flaky test of scripts/flaky-tests.txt -race -count
# STRESS_COUNT (10) under test-under-load (scripts/stress-flaky.sh); a release
# candidate runs it on the Mac (`taskpolicy -b make stress-flaky`).
.PHONY: stress-flaky
stress-flaky:
	@./scripts/stress-flaky.sh

# FUZZTIME per target (default 10s).
fuzz-short:
	./scripts/fuzz-short.sh

# Needs buf and the protoc-gen-go, protoc-gen-go-grpc, protoc-gen-grpc-gateway plugins.
proto-gen:
	./scripts/proto-gen.sh

# buf lint + breaking of proto/pb (the agent wire) vs PROTO_BASELINE; report only.
proto-report:
	./scripts/proto-report.sh

# The exported API of each module against its latest release tag
# (<module>/vX.Y.Z; apidiff, pinned in scripts/check-api.sh): the changes
# must be the ones api/<module>-<tag>.txt lists, which is what the
# module's next release makes on purpose (docs/v1-api-review.md). A change
# on purpose: record it there, then UPDATE=1 make check-api. Needs the
# tags (a full clone) and module downloads for the old side.
.PHONY: check-api test-check-api
# test-check-api: check-api fails, never passes, in a clone without the tags.
test-check-api:
	./scripts/check-api_test.sh

check-api: test-check-api
	@for m in $(MODULES); do ./scripts/check-api.sh $$m $$m/ $$m || exit 1; done

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
	./scripts/check-no-legacy-name_test.sh
	./scripts/check-no-legacy-name.sh

tidy:
	@for m in $(MODULES); do (cd $$m && GOWORK=off go mod tidy) || exit 1; done

CI_WORKFLOW_FILE := .github/workflows/ci.yml
# ci: what the GitHub workflow runs on a push (CI_WORKFLOW_FILE), run here.
# GitHub Actions is not a gate; make ci on the operator's Mac is (the build
# box is deleted, 2026-11-25). scripts/ci.sh reads the steps from
# the workflow file itself, so the two cannot drift; a pass on a clean tree
# is stamped and not rerun for the same tree.
# hooks: install the pre-push hook (scripts/pre-push): a push to main or a
# tag needs a green make ci result for that sha (scripts/ci.sh records it)
# or this clone's stamp for its tree; bypass only with
# NFLTR_CI_BYPASS=<reason> (logged to <git-common-dir>/ci-bypass.log).
.PHONY: ci hooks
ci:
	@CI_WORKFLOW=$(CI_WORKFLOW_FILE) ./scripts/ci.sh
hooks:
	@h="$$(git rev-parse --git-path hooks)/pre-push"; \
	if [ -e "$$h" ] && ! grep -q 'scripts/pre-push' "$$h"; then echo "hooks: $$h exists and is not this one; move it away first" >&2; exit 1; fi; \
	printf '#!/bin/sh\n# make hooks: scripts/pre-push of the checkout pushing (else of %s)\ns="$$(git rev-parse --show-toplevel)/scripts/pre-push"\n[ -x "$$s" ] || s=%s/scripts/pre-push\nexec "$$s" "$$@"\n' "$(CURDIR)" "$(CURDIR)" >"$$h" && chmod +x "$$h" && echo "hooks: installed $$h"

# wasm-nf1: the nf1 handshake built for js/wasm (client/nf1/internal/jsclient)
# reproducibly, its sha256 printed, run once under node; fails over budget or
# when it links the relay dial (scripts/wasm-nf1.sh; nfltr
# docs/decisions/browser-peer-2026-11-16.md, lane BP1). The budgets are the
# size measured at go1.27.4 + 5 % (8106361 raw, 2164581 gzip -9 -n). WASM_OUT=<dir>
# keeps nf1.wasm.
WASM_NF1_MAX_BYTES ?= 8511679
WASM_NF1_MAX_GZIP_BYTES ?= 2272810
.PHONY: wasm-nf1
wasm-nf1:
	@WASM_NF1_MAX_BYTES=$(WASM_NF1_MAX_BYTES) WASM_NF1_MAX_GZIP_BYTES=$(WASM_NF1_MAX_GZIP_BYTES) ./scripts/wasm-nf1.sh

# browser-bundle: the nf1 browser extension (browser/, lane BP4) built
# reproducibly into browser/dist (BROWSER_OUT): twice, equal SHA256SUMS
# listings (the code pin, BIND:browser.bundle), nf1.wasm under the
# wasm-nf1 budgets; BROWSER_SUMS=<release SHA256SUMS> also checks the build
# is the release's (scripts/browser-bundle.sh).
.PHONY: browser-bundle
browser-bundle:
	@WASM_NF1_MAX_BYTES=$(WASM_NF1_MAX_BYTES) WASM_NF1_MAX_GZIP_BYTES=$(WASM_NF1_MAX_GZIP_BYTES) ./scripts/browser-bundle.sh

# browser-e2e: Playwright (TypeScript, browser/e2e) drives the unpacked
# extension in Chromium against browser/e2e/harness (a relay core of the
# version its go.mod names, nf1.websocket on, this checkout's agents):
# session bytes, every close code's class, retries, a relay restart
# mid-session, the direct path, the HTTP view. In docker
# (browser/e2e/Dockerfile: the Playwright image of package.json's version),
# the same on a Mac and the Linux runner; $0, offline but for the image and
# module downloads; not in make ci (`make browser-e2e`).
# Iterating on a Mac: build e2e/.harness/harness for it and run
# ./node_modules/.bin/playwright test -c e2e/playwright.config.ts in browser/.
.PHONY: browser-e2e
browser-e2e: browser-bundle
	cd browser && ./node_modules/.bin/tsc --noEmit -p .
	cd browser/e2e/harness && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$$(docker version -f '{{.Server.Arch}}')" go build -o ../.harness/linux/harness .
	id="$$(docker build -q -f browser/e2e/Dockerfile browser)" && rc=0 && docker run --rm --init "$$id" || rc=$$?; docker rmi "$$id" >/dev/null 2>&1; exit $$rc

# Fails when a _test.go file assigns a package-level variable of its package
# (allow-list with reasons: scripts/testknobs-allow.txt). The tool lives in
# proto (stdlib only) and runs from the repository root over both modules.
.PHONY: check-testknobs stress-race
check-testknobs:
	@d=$$(mktemp -d) && (cd proto && GOWORK=off go build -o $$d/testknobs ./internal/tools/testknobs) && $$d/testknobs -allow scripts/testknobs-allow.txt client proto org; rc=$$?; rm -rf $$d; exit $$rc

# link's debug mode (-tags linkdebug): vet with the tag, and the tests of the
# packages that import link with the tag (no -race: scripts/test-linkdebug.sh);
# fails on any "link debug:" report (leakcheck).
.PHONY: test-linkdebug
test-linkdebug:
	./scripts/test-linkdebug.sh client proto org

# linkvet (github.com/nfltr/link/linkvet at the version scripts/check-linkvet.sh
# pins) over the non-test code: fails on a finding scripts/linkvet-allow.txt
# does not list (each entry with a reason) and on a stale entry.
.PHONY: check-linkvet
check-linkvet:
	./scripts/check-linkvet.sh ./client/... ./proto/... ./org/...

# stress-race PKGS='./client/agent ./proto/wire/chunking' [COUNT=50]: the
# packages' tests repeated under the race detector (paths from the repository
# root; each is run in its module).
COUNT ?= 50
stress-race:
	@test -n "$(PKGS)" || { echo "stress-race: PKGS='<packages>' is required, e.g. make stress-race PKGS=./client/agent" >&2; exit 2; }
	@for p in $(PKGS); do m=$${p#./}; m=$${m%%/*}; (cd $$m && go test -race -count=$(COUNT) ./$${p#./$$m/} ) || exit 1; done

# The TLA+ models (spec/README.md): spec checks them, spec-mutants checks
# each bug put back is caught (both in make ci); spec-traces checks the
# traces the tests record under -tags relaytrace against them, and the
# issuer's app enrolment, certificate (spec-enrol-traces) and organisation
# move (spec-orgmove-traces) traces, nightly (CI_NIGHTLY relay=spec-traces;
# spec-enrol-traces stayed red unscheduled after lane SEAMLESS);
# spec-cltraces is its per-push slice (the stuck-handler test's CallLifecycle
# traces, about 10 s; in make ci); spec-astraces another (the A2A E2EE
# session tests' A2ASession traces, about 10 s; in make ci); spec-dgtraces
# another (client/dgram's DatagramAssoc traces; in make ci); spec-bptraces
# another (client/p2p's browser direct path BrowserPeer traces; in make ci).
.PHONY: spec spec-mutants spec-traces spec-cltraces spec-astraces spec-dgtraces spec-ptraces spec-stoptraces spec-tetraces spec-bptraces spec-cctraces spec-proverif spec-bindings
spec:
	./scripts/spec.sh check
spec-mutants:
	./scripts/spec.sh mutants
spec-traces:
	./scripts/spec.sh traces
	./scripts/spec-appenrol.sh traces
	./scripts/spec-enrol.sh replicas
	./scripts/spec-enrol.sh fresh
	./scripts/spec-enrol.sh live
	./scripts/spec-enrol.sh traces
	./scripts/spec-orgmove.sh live
	./scripts/spec-orgmove.sh traces
	./scripts/spec-people.sh traces
	PROVERIF_FULL=1 ./spec/proverif/run.sh
	./scripts/spec-grant.sh traces
	./scripts/spec-onegroup.sh traces
	./scripts/spec-rootheld.sh full
spec-cltraces:
	./scripts/spec.sh cltraces
spec-astraces:
	./scripts/spec.sh astraces
# client/rpcclient's two-agent and concurrent-sender calls against
# spec/TraceCallCredit.tla, TraceCallCreditBoth.tla and
# TraceCallCreditSenders.tla (about 25 s on the runner; nightly: spec-traces runs it).
spec-cctraces:
	./scripts/spec.sh ccruns
# client/dgram's association traces against spec/TraceDatagramAssoc.tla
# (about 10 s; in make ci).
spec-dgtraces:
	./scripts/spec.sh dgtraces
# client/agent's punch traces against spec/TraceDirectPunch.tla (a few
# seconds; in make ci).
spec-ptraces:
	./scripts/spec.sh ptraces
spec-bptraces:
	./scripts/spec.sh bptraces
# client/agent's SENDCUT stop traces against spec/TraceAgentStop.tla
# (about 15 s; in make ci; spec-traces runs every stop test and fixture).
spec-stoptraces:
	./scripts/spec.sh stoptraces
# client/tlsend's session ends over a link session against
# spec/TraceTLSEnd.tla, with its fixtures (a few seconds; in make ci).
spec-tetraces:
	./scripts/spec.sh tetraces
# The ProVerif models (spec/proverif/README.md): every line of
# spec/proverif/expect.txt, mutants included (in make ci; a mutant's line
# only the queries it changes, every query nightly in spec-traces).
spec-proverif: test-cicache test-fetch-tla
	./spec/proverif/run.sh

# scripts/cicache.sh, the result cache of the TLC runs, ProVerif models and
# Go mutant lists above (a hit skips a check whose inputs did not change):
# its soundness test, ahead of the first check that uses it.
.PHONY: test-cicache
test-cicache:
	./scripts/cicache_test.sh

# scripts/fetch-tla.sh: concurrent fetchers sharing one cache never see
# another's partial download; a good cache is used with no fetch.
.PHONY: test-fetch-tla
test-fetch-tla:
	./scripts/fetch-tla_test.sh
# The models' bindings against the code (spec/proverif/README.md
# "Bindings"): each BIND id a model lists has a test row that changes that
# field of an honest message, as a relay can, and requires a refusal; the
# test fails when a model's ids and its rows differ (in make ci).
spec-bindings:
	cd client && go test -count=1 -run 'ModelBindings' ./rpcclient/ ./p2p/ ./agent/ ./capaddr/ ./nf1/ ./orgid/ ./nfnet/ ./appenrol/ ./orgaudit/
	cd org && go test -count=1 -run 'ModelBindings' ./orgpki/ ./orgissuer/

# test-go-mutants (in make ci, about a minute): every planted bug of a Go
# mutant list (client/agent/testdata/org_mutants.txt: the agent's
# organisation mode; client/agent/testdata/queue_mutants.txt: its session
# queue; client/orgid/testdata/mutants.txt: the organisation
# checks; client/machinecred/testdata/mutants.txt: the relay credential's
# key and certificate read as one pair; client/pairfile/testdata/mutants.txt: a
# key and certificate replaced as one pair; client/nf1/testdata/mutants.txt: the nf1 transport;
# client/nfnet/testdata/mutants.txt: a session's end under end-to-end TLS;
# client/tlsend/testdata/mutants.txt: tlsend Close's direct-path exemption;
# client/appenrol/testdata/mutants.txt: the sign-in nonce;
# client/agent/testdata/direct_dgram_mutants.txt: the direct path's
# datagrams; client/agent/testdata/nf1_anon_mutants.txt: sessions to an
# address served with no account;
# client/agent/testdata/direct_once_mutants.txt: an nf1 session's
# per-epoch channels (direct_once.pv);
# client/agent/testdata/direct_end_mutants.txt: a direct-path session's
# end at the agent; org/*/testdata/mutants.txt: the organisation issuer, its
# machine and issuer stores and enrolment) makes its test fail
# (scripts/go-mutants.sh).
GO_MUTANT_LISTS = \
	client/agent/testdata/org_mutants.txt \
	client/agent/testdata/queue_mutants.txt \
	client/orgid/testdata/mutants.txt \
	client/orgaudit/testdata/mutants.txt \
	client/machinecred/testdata/mutants.txt \
	client/pairfile/testdata/mutants.txt \
	client/appenrol/testdata/mutants.txt \
	client/nf1/testdata/mutants.txt \
	client/nfnet/testdata/mutants.txt \
	client/tlsend/testdata/mutants.txt \
	client/p2p/testdata/browser_mutants.txt \
	client/agent/testdata/direct_dgram_mutants.txt \
	client/agent/testdata/nf1_anon_mutants.txt \
	client/agent/testdata/direct_once_mutants.txt \
	client/agent/testdata/direct_end_mutants.txt \
	org/orgpki/testdata/mutants.txt \
	org/orgmachine/testdata/mutants.txt \
	org/orgenrol/testdata/mutants.txt \
	org/orgissuer/testdata/mutants.txt
.PHONY: test-go-mutants check-go-mutants
test-go-mutants:
	for l in $(GO_MUTANT_LISTS); do ./scripts/go-mutants.sh $$l || exit 1; done

# check-go-mutants (seconds, first in make ci's static job): each list's lines
# still name a whole line found exactly once and an existing test
# (go-mutants.sh --check), so a stale mutant fails before the mutant job;
# its fixture of a stale line must fail.
check-go-mutants:
	./scripts/go-mutants.sh --check $(GO_MUTANT_LISTS)
	@! ./scripts/go-mutants.sh --check scripts/testdata/go-mutants-stale.txt >/dev/null || { echo "check-go-mutants: a stale line passed" >&2; exit 1; }

# spec-enrol-ci (in make ci, a few minutes): the organisation certificates'
# lifecycle (renewal over the relay's mailboxes, revocation, root rotation;
# spec/enrol/README.md): the invariants (EnrolLoss.cfg's too), every
# mutant (the temporal ones on LiveSpec), the witnesses and the trace
# fixtures; the liveness properties' full check (spec-enrol.sh live:
# EnrolLive.cfg, 7 min, and EnrolLoss.cfg) is nightly, in spec-traces; spec-enrol-traces: the tests
# of org/orgpki, orgmachine and orgenrol built -tags enroltrace, each trace
# checked by spec/enrol/TraceEnrol.tla; spec-enrol-coverage: TLC -coverage 1
# on each config, failing on an action never taken.
.PHONY: spec-enrol-ci spec-enrol-traces spec-enrol-coverage spec-orgmove-ci spec-orgmove-traces spec-orgmove-repeat
spec-enrol-ci:
	./scripts/spec-enrol.sh ci
spec-enrol-traces:
	./scripts/spec-enrol.sh traces
spec-enrol-coverage:
	./scripts/spec-enrol.sh coverage

# spec-orgmove-ci (in make ci, about a minute): moving an organisation's
# issuer to another machine (spec/orgmove/README.md): the invariants,
# MoveCompletes, every mutant, the witnesses and -coverage 1;
# spec-orgmove-traces: the tests of org/orgpki, orgissuer and orgenrol built
# -tags enroltrace against spec/orgmove/TraceOrgMove.tla;
# spec-orgmove-repeat: two moves in a row (about a minute, not in make ci).
spec-orgmove-ci:
	./scripts/spec-orgmove.sh ci
spec-orgmove-traces:
	./scripts/spec-orgmove.sh traces
spec-orgmove-repeat:
	./scripts/spec-orgmove.sh repeat

# spec-pair-ci (in make ci, seconds): a machine's key and certificate
# replaced as one pair, crash-safe at every step (spec/pair/README.md): the
# invariant, ReaderCompletes, every mutant, the witnesses, -coverage 1, and
# client/pairfile's tests built -tags pairtrace against
# spec/pair/TraceMachinePair.tla with the trace fixtures.
.PHONY: spec-pair-ci
spec-pair-ci:
	./scripts/spec-pair.sh ci

# spec-appenrol-ci (in make ci, about a minute): an app's device enrolled
# for a person, by sign-in or an admin code, its renewal bounded by the
# sign-in, revocation by person and by app (spec/appenrol/README.md): the
# invariants, every mutant, the witnesses, -coverage 1 and the trace
# fixtures; spec-appenrol-traces: the tests of org/orgpki and orgenrol
# built -tags enroltrace, each trace checked by
# spec/appenrol/TraceAppEnrol.tla (nightly: spec-traces runs it).
.PHONY: spec-appenrol-ci spec-appenrol-traces
spec-appenrol-ci:
	./scripts/spec-appenrol.sh ci
spec-appenrol-traces:
	./scripts/spec-appenrol.sh traces

# spec-onegroup-ci (in make ci, under a minute): the issuer's half of one
# set of groups, the root's move orders (spec/onegroup/README.md): the
# invariants, every mutant, the witnesses, -coverage 1, the trace fixtures
# and the move tests' traces; every test's traces nightly (spec-traces).
.PHONY: spec-onegroup-ci
spec-onegroup-ci:
	./scripts/spec-onegroup.sh ci

# spec-rootheld-ci (in make ci): the root-held member log, a design
# (spec/rootheld/README.md): every invariant, mutant, witness, coverage and
# the liveness config.
.PHONY: spec-rootheld-ci
spec-rootheld-ci:
	./scripts/spec-rootheld.sh ci

# spec-grant-ci (in make ci): time-limited, approved access to a service
# (spec/grant/README.md): the invariants, the liveness config, every
# mutant, the witnesses, -coverage 1 and the rejected trace fixtures
# (TraceGrant.tla; the tests' traces: spec-traces, nightly).
.PHONY: spec-grant-ci
spec-grant-ci:
	./scripts/spec-grant.sh ci

# Early-exit pipes under pipefail (scripts/check-grepq.sh, a copy of
# nfltr's, kept identical): `producer | grep -q` reads SIGPIPE (141) as "not
# found"; the self-test reproduces the race.
.PHONY: check-grepq
check-grepq:
	./scripts/check-grepq.sh self-test
	./scripts/check-grepq.sh
# Spec drift (scripts/check-spec-drift.sh, a copy of nfltr's, kept
# identical; its test is nfltr's scripts/check_spec_drift_test.sh): every
# spec README's code-map entry exists, and the commits since origin/main
# that change a file a code map lists change that spec too or carry
# `Spec-Reviewed: <spec> <reason>`. The pre-push hook checks the pushed range.
# check-spec-actions (no Java, < 1 s): every enrol and orgmove model step in
# its README action table, every trace spec's line kind still recorded.
.PHONY: check-spec-actions
check-spec-actions:
	./scripts/check-spec-actions.sh

.PHONY: check-spec-drift
check-spec-drift:
	./scripts/check-spec-drift.sh maps
	./scripts/check-spec-drift.sh ci

# spec-people-ci (in make ci, about two minutes): the people layer
# (spec/people/README.md): persons, roles, invites, offboarding and its
# reach bound: the invariants with -coverage 1, every mutant, the
# witnesses, the trace fixtures; the tests' traces (org/orgpki and orgenrol,
# -tags enroltrace) against TracePeople.tla in spec-traces (nightly).
.PHONY: spec-people-ci
spec-people-ci:
	./scripts/spec-people.sh ci

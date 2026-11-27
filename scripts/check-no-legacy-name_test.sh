#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# check-no-legacy-name_test.sh: scripts/check-no-legacy-name.sh refuses a
# retired name in any spelling, the wire's package name included, and
# passes gRPC.
# Offline, in a temp repository, with the stand-in name "xyzserver".
set -euo pipefail
check="$(cd "$(dirname "$0")" && pwd)/check-no-legacy-name.sh"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
unset "${!GIT_@}"
cd "$t"
git init -q .
export LEGACY_ROOT="$t" LEGACY_PREFIX=xyz LEGACY_LEN=9
LEGACY_SHA256=$(printf %s xyzserver | shasum -a 256 | cut -d' ' -f1)
export LEGACY_SHA256
fail=0
expect() { # expect <0|1> <line>
	printf '%s\n' "$2" >f.txt
	git add f.txt
	if "$check" >/dev/null 2>&1; then got=0; else got=1; fi
	[ "$got" = "$1" ] || { echo "FAIL: $2: exit $got, want $1" >&2; fail=1; }
}
expect 0 "the relay"
expect 1 "xyzserver"
expect 1 "connects to the XYZ Server"
expect 1 "metric xyz_server_proxy_total"
expect 1 "header X-Xyz-Server-Transactionid"
expect 1 "func TestXyzServer_dial"
expect 1 "/etc/xyz-server/machines"
expect 0 "the gxyz server and GXYZ_SERVER"
expect 1 "package xyzserver;"
expect 1 "path /xyzserver.Dispatcher/RelayTunnel"
expect 1 "xyzserver.drainBy"
expect 1 "XyzServer.Dispatcher"
[ "$fail" = 0 ] && echo "check-no-legacy-name_test: ok"
exit "$fail"

#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# check-no-legacy-name: the relay is "the relay", not its old name, in every
# tracked file: rpc, an optional "-" or "_", then server, in any case
# (the pattern below). grpc_server / GRPC_SERVER (gRPC) do not match.
# Kept: the agent wire's proto package `rpcserver` and what derives from it
# (generated proto/pb/*.pb.go, full names like rpcserver.Dispatcher, method
# paths /rpcserver.Dispatcher/...), /var/lib/rpcserver, and this script.
# A line is reported when it still matches with those removed.
set -euo pipefail

cd "$(dirname "$0")/.."
pattern='(?<!g)rpc[-_]?server'
rc=0
hits="$(git grep -I -n -P -i "$pattern" -- . \
	':!scripts/check-no-legacy-name.sh' ':!proto/pb/*.pb.go')" || rc=$?
[ "$rc" -le 1 ] || { echo "check-no-legacy-name: git grep failed ($rc)" >&2; exit 1; }
bad="$(printf '%s\n' "$hits" | perl -ne '
	next unless /\S/;
	my ($loc, $text) = /^([^:]*:\d+:)(.*)$/ or next;
	$text =~ s{package rpcserver;|rpcserver\.(?=[A-Z])|/rpcserver\.|/var/lib/rpcserver}{}g;
	print "$loc$text\n" if $text =~ /(?<!g)rpc[-_]?server/i;
')"
if [ -n "$bad" ]; then
	printf '%s\n' "$bad" >&2
	echo "check-no-legacy-name: the relay's old name above; say \"relay\" (relay:9090 for its address)" >&2
	exit 1
fi
echo "check-no-legacy-name: ok"

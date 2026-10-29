#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

# proto-gen: regenerate the Go code of the v1 protos (proto/nfltr/**) with buf
# and the local plugins (protoc-gen-go, protoc-gen-go-grpc,
# protoc-gen-grpc-gateway from `go install`, looked up in $(go env GOPATH)/bin
# first), add the licence header to the generated files, then lint the protos.
# proto/pb/service.proto (the agent wire, outside the buf module) is
# generated with protoc and protoc-gen-go, protoc-gen-go-grpc.
# Generated files sit beside each .proto. Needs network once for the
# googleapis dependency (buf caches it).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
gobin="$(go env GOPATH)/bin"
export PATH="$gobin:$PATH"
buf="${BUF:-$(command -v buf || true)}"
if [ -z "$buf" ]; then
	echo "proto-gen: buf not found (https://buf.build/docs/installation, or BUF=/path/to/buf)" >&2
	exit 1
fi
cd "$root/proto"
"$buf" generate
find nfltr -name '*.go' | while read -r f; do
	if ! head -3 "$f" | grep -q SPDX-License-Identifier; then
		{ printf '// Copyright 2026 nfltr\n// SPDX-License-Identifier: Apache-2.0\n\n'; cat "$f"; } >"$f.tmp" && mv "$f.tmp" "$f"
	fi
done
"$buf" lint
command -v protoc >/dev/null || { echo "proto-gen: protoc not found (needed for proto/pb)" >&2; exit 1; }
(cd pb && protoc --proto_path=. --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. service.proto)

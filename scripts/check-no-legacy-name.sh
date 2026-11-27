#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# check-no-legacy-name: the relay is "the relay" in every tracked file, never
# a retired name. The name is held as its SHA-256 so this file does not spell
# it: each line is lowercased with "-", "_" and blanks dropped, and every
# LEGACY_LEN-letter run that starts with LEGACY_PREFIX (not right after a
# "g", so gRPC passes) is hashed. No exception: the agent wire's proto
# package is nfltr.relay.v1 (client generation 4).
# The LEGACY_* variables and LEGACY_ROOT are for check-no-legacy-name_test.sh.
set -euo pipefail

cd "${LEGACY_ROOT:-$(dirname "$0")/..}"
git ls-files -z | python3 -c '
import hashlib, os, re, sys

H = os.environ.get("LEGACY_SHA256", "1468bfcae720733489ba9fd7781df0662fa748cb1ca85f67ac195e7f5a65b890")
P = os.environ.get("LEGACY_PREFIX", "rpc")
N = int(os.environ.get("LEGACY_LEN", "9"))
SEP = re.compile(r"[-_\s]")


def legacy(s):
    return hashlib.sha256(s.encode()).hexdigest() == H


bad = []
for path in sys.stdin.read().split("\0"):
    if not path or not os.path.isfile(path):
        continue
    data = open(path, "rb").read()
    if b"\0" in data:
        continue
    for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if P not in line.lower():
            continue
        s = SEP.sub("", line.lower())
        i = s.find(P)
        while i >= 0:
            if (i == 0 or s[i - 1] != "g") and legacy(s[i:i + N]):
                bad.append("%s:%d: %s" % (path, n, line.strip()))
                break
            i = s.find(P, i + 1)
if bad:
    print("\n".join(bad), file=sys.stderr)
    print("check-no-legacy-name: the relay by a retired name above; say \"relay\" (relay:9090 for its address)", file=sys.stderr)
    sys.exit(1)
print("check-no-legacy-name: ok")
'

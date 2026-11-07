#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# fetch-proverif.sh prints the path of a ProVerif 2.05 binary for the
# symbolic (Dolev-Yao) models (spec/proverif/README.md). ProVerif ships as
# source only, so it is built once, with a pinned OCaml 4.14.2 built from
# source too, into $RELAY_PROVERIF_CACHE (default ~/.cache/relay-proverif);
# both tarballs are checked against their pinned sha256. Needs a C compiler,
# make and curl (the Linux runner has them); offline after the first run.
# Nothing it fetches or builds is committed.
set -eu
cache=${RELAY_PROVERIF_CACHE:-$HOME/.cache/relay-proverif}
mkdir -p "$cache"
pv=$cache/proverif2.05/proverif
if [ -x "$pv" ]; then
	echo "$pv"
	exit 0
fi

# get URL SHA256 FILE: download URL to FILE unless it is there with SHA256.
get() {
	if [ -f "$3" ] && [ "$(shasum -a 256 "$3" | cut -d' ' -f1)" = "$2" ]; then return; fi
	curl -fsSL --retry 3 -o "$3.part" "$1"
	got=$(shasum -a 256 "$3.part" | cut -d' ' -f1)
	if [ "$got" != "$2" ]; then
		rm -f "$3.part"
		echo "fetch-proverif: $1: sha256 $got, want $2" >&2
		exit 1
	fi
	mv "$3.part" "$3"
}

get https://caml.inria.fr/pub/distrib/ocaml-4.14/ocaml-4.14.2.tar.gz \
	93b4f3ba39d559a963fc10744563b4c6e92e9ffb540ce89e5c5ebf76086b99f3 "$cache/ocaml-4.14.2.tar.gz"
get https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz \
	4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4 "$cache/proverif2.05.tar.gz"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
ocaml=$cache/ocaml-4.14.2-root
if [ ! -x "$ocaml/bin/ocamlopt" ]; then
	echo "fetch-proverif: building OCaml 4.14.2 (once, minutes)" >&2
	rm -rf "$cache/ocaml-4.14.2" "$ocaml"
	(cd "$cache" && tar xzf ocaml-4.14.2.tar.gz)
	(cd "$cache/ocaml-4.14.2" &&
		./configure -q --prefix="$ocaml" --disable-ocamldoc --disable-debugger --disable-ocamltest >/dev/null &&
		make -s -j"$jobs" world.opt >/dev/null &&
		make -s install >/dev/null) >&2
	rm -rf "$cache/ocaml-4.14.2"
fi
echo "fetch-proverif: building ProVerif 2.05 (once)" >&2
rm -rf "$cache/proverif2.05"
(cd "$cache" && tar xzf proverif2.05.tar.gz)
(cd "$cache/proverif2.05" && PATH=$ocaml/bin:$PATH ./build -nointeract >/dev/null) >&2
[ -x "$pv" ] || { echo "fetch-proverif: build produced no $pv" >&2; exit 1; }
echo "$pv"

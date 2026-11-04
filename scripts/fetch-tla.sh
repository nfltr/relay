#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# fetch-tla.sh prints the java to run and the tla2tools.jar for the TLA+
# model (spec/README.md), each fetched once into $RELAY_TLA_CACHE (default $LINK_TLA_CACHE, else
# ~/.cache/link-tla) and checked against its pinned sha256. A java on PATH
# that runs is used as it is; else a pinned Temurin JRE is fetched.
# Nothing it fetches is committed.
set -eu
cache=${RELAY_TLA_CACHE:-${LINK_TLA_CACHE:-$HOME/.cache/link-tla}}
mkdir -p "$cache"

# get URL SHA256 FILE: download URL to FILE unless it is there with SHA256.
get() {
	if [ -f "$3" ] && [ "$(shasum -a 256 "$3" | cut -d' ' -f1)" = "$2" ]; then return; fi
	curl -fsSL --retry 3 -o "$3.part" "$1"
	got=$(shasum -a 256 "$3.part" | cut -d' ' -f1)
	if [ "$got" != "$2" ]; then
		rm -f "$3.part"
		echo "fetch-tla: $1: sha256 $got, want $2" >&2
		exit 1
	fi
	mv "$3.part" "$3"
}

# TLA+ tools 1.8.0, master 090e85c of 2026-10-30 (the Json module's
# ndJsonDeserialize, POSTCONDITION). Upstream rebuilds its v1.8.0 release
# asset on every master commit, so a pin of that URL breaks: the jar comes
# from an immutable, versioned bundle of that build instead, the TLA+ VS Code
# extension 2026.10.301552 on Open VSX (extension/tools/tla2tools.jar).
jar=$cache/tla2tools-1.8.0.jar
jarsum=011267fca25d0752cf18894dd585cd28b96960c112ea8a20b823ea770e7e10cd
if [ ! -f "$jar" ] || [ "$(shasum -a 256 "$jar" | cut -d' ' -f1)" != "$jarsum" ]; then
	vsix=$cache/tlaplus.vscode-ide-2026.10.301552.vsix
	get https://open-vsx.org/api/tlaplus/vscode-ide/2026.10.301552/file/tlaplus.vscode-ide-2026.10.301552.vsix \
		89adb8d05d3136f74a4a33c97ae35b04730cdb3fb551b81d4299ba5b56c3c5a8 "$vsix"
	if command -v unzip >/dev/null 2>&1; then
		unzip -p "$vsix" extension/tools/tla2tools.jar >"$jar.part"
	else
		python3 -I -c 'import sys, zipfile; sys.stdout.buffer.write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]))' \
			"$vsix" extension/tools/tla2tools.jar >"$jar.part"
	fi
	got=$(shasum -a 256 "$jar.part" | cut -d' ' -f1)
	if [ "$got" != "$jarsum" ]; then
		rm -f "$jar.part"
		echo "fetch-tla: $vsix: tla2tools.jar sha256 $got, want $jarsum" >&2
		exit 1
	fi
	mv "$jar.part" "$jar"
fi

java=${JAVA:-java}
if ! "$java" -version >/dev/null 2>&1; then
	jre=jdk-21.0.13%2B9
	case $(uname -s)/$(uname -m) in
	Darwin/arm64) f=OpenJDK21U-jre_aarch64_mac_hotspot_21.0.13_9.tar.gz sum=225bab0a09491ef06835488cd942f5d2befa9a0410a2484f0c8bbcf7506ec09a ;;
	Linux/x86_64) f=OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz sum=a535a1df9c6284d9618872984e026ae0352d1f7e9e0605425c0e6114f47351dd ;;
	*) echo "fetch-tla: no java runs and no pinned JRE for $(uname -s)/$(uname -m): set JAVA" >&2; exit 1 ;;
	esac
	get "https://github.com/adoptium/temurin21-binaries/releases/download/$jre/$f" "$sum" "$cache/$f"
	dir=$cache/jre-21.0.13_9
	if [ ! -d "$dir" ]; then
		mkdir -p "$dir.part" && tar -xzf "$cache/$f" -C "$dir.part" && mv "$dir.part" "$dir"
	fi
	java=$(find "$dir" -path '*/bin/java' -type f | head -1)
fi
echo "$java"
echo "$jar"

#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

# fetch-tla.sh prints the java to run (its heap capped, below), the
# tla2tools.jar and the CommunityModules jar (third line) for the TLA+
# models (spec/), each fetched once into $RELAY_TLA_CACHE (default $LINK_TLA_CACHE, else ~/.cache/link-tla,
# one cache for every nfltr repository) and checked against its pinned sha256.
# A java on PATH that runs is used as it is; else a pinned Temurin JRE is
# fetched. Nothing it fetches is committed. The same file in nfltr, link,
# relay, relay-core and relay-server; its test is scripts/fetch-tla_test.sh.
#
# Fetchers run at once (parallel CI jobs, runners sharing one cache): each
# writes its own mktemp file beside the target, checks the pinned sha256 and
# renames it into place (rename(2) is atomic, over a good file too), so no
# fetcher ever sees another's partial download.
set -eu
cache=${RELAY_TLA_CACHE:-${LINK_TLA_CACHE:-$HOME/.cache/link-tla}}
mkdir -p "$cache"

# have SHA256 FILE: FILE is there with SHA256.
have() { [ -f "$2" ] && [ "$(shasum -a 256 "$2" | cut -d' ' -f1)" = "$1" ]; }

# keep TMP SHA256 FILE WHAT: rename TMP onto FILE if it has SHA256.
keep() {
	got=$(shasum -a 256 "$1" | cut -d' ' -f1)
	if [ "$got" != "$2" ]; then
		rm -f "$1"
		echo "fetch-tla: $4: sha256 $got, want $2" >&2
		exit 1
	fi
	mv -f "$1" "$3"
}

# get URL SHA256 FILE: download URL to FILE unless it is there with SHA256.
get() {
	if have "$2" "$3"; then return; fi
	tmp=$(mktemp "$3.XXXXXX")
	curl -fsSL --retry 3 -o "$tmp" "$1" || { rm -f "$tmp"; exit 1; }
	keep "$tmp" "$2" "$3" "$1"
}

# TLA+ tools 1.8.0, master 090e85c of 2026-10-30 (the Json module's
# ndJsonDeserialize, POSTCONDITION). Upstream rebuilds its v1.8.0 release
# asset on every master commit, so a pin of that URL breaks: the jar comes
# from an immutable, versioned bundle of that build instead, the TLA+ VS Code
# extension 2026.10.301552 on Open VSX (extension/tools/tla2tools.jar).
jar=$cache/tla2tools-1.8.0.jar
jarsum=011267fca25d0752cf18894dd585cd28b96960c112ea8a20b823ea770e7e10cd
if ! have "$jarsum" "$jar"; then
	vsix=$cache/tlaplus.vscode-ide-2026.10.301552.vsix
	get https://open-vsx.org/api/tlaplus/vscode-ide/2026.10.301552/file/tlaplus.vscode-ide-2026.10.301552.vsix \
		89adb8d05d3136f74a4a33c97ae35b04730cdb3fb551b81d4299ba5b56c3c5a8 "$vsix"
	tmp=$(mktemp "$jar.XXXXXX")
	if command -v unzip >/dev/null 2>&1; then
		unzip -p "$vsix" extension/tools/tla2tools.jar >"$tmp" || { rm -f "$tmp"; exit 1; }
	else
		python3 -I -c 'import sys, zipfile; sys.stdout.buffer.write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]))' \
			"$vsix" extension/tools/tla2tools.jar >"$tmp" || { rm -f "$tmp"; exit 1; }
	fi
	keep "$tmp" "$jarsum" "$jar" "$vsix: tla2tools.jar"
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
		tmp=$(mktemp -d "$dir.XXXXXX")
		tar -xzf "$cache/$f" -C "$tmp" || { rm -rf "$tmp"; exit 1; }
		# Another fetcher's dir landed first: mv moved ours into it, drop it.
		mv "$tmp" "$dir" && rm -rf "${dir:?}/${tmp##*/}"
	fi
	java=$(find "$dir" -path '*/bin/java' -type f | head -1)
fi
# CommunityModules (VectorClocks' CausalOrder: the merged hub/node traces).
cm=$cache/CommunityModules-deps-202505152026.jar
get https://github.com/tlaplus/CommunityModules/releases/download/202505152026/CommunityModules-deps.jar \
	044e8ecdfbca92d51d7eb4469422c2a7da1fe25dc8ad39c4a90e6622d6da4d99 "$cm"

# The java printed runs that java with its heap capped: TLC_RAM_PERCENT (25,
# Java's own default) of CI_MEM_BUDGET_MB (scripts/ci.sh: this make ci job's
# share of the runner's memory), else of the cgroup's memory.max, else of
# the machine's, over TLC_JVMS (the JVMs its caller runs at once, 1). Java
# sizes each JVM by the whole container: four TLCs at once beside two other
# make ci jobs ran a 5 GiB runner out of memory (lane CIMEM). One wrapper
# per java in the cache, rewritten (renamed into place) every run.
w=$cache/java-$(printf '%s' "$java" | cksum | cut -d' ' -f1)
tmp=$(mktemp "$w.XXXXXX")
q=$(printf '%s' "$java" | sed "s/'/'\\\\''/g")
cat >"$tmp" <<EOF
#!/bin/sh
# scripts/fetch-tla.sh's java, its heap capped (see there).
m=\${CI_MEM_BUDGET_MB:-\$(awk '\$1 ~ /^[0-9]+\$/ { print int(\$1 / 1048576) }' /sys/fs/cgroup/memory.max 2>/dev/null)}
p=\${TLC_RAM_PERCENT:-25} n=\${TLC_JVMS:-1}
if [ -n "\$m" ]; then h=-Xmx\$((m * p / 100 / n))m; else h=-XX:MaxRAMPercentage=\$((p / n)); fi
exec '$q' "\$h" "\$@"
EOF
chmod 755 "$tmp"
mv -f "$tmp" "$w"

echo "$w"
echo "$jar"
echo "$cm"

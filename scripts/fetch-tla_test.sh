#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

# fetch-tla_test.sh: scripts/fetch-tla.sh against a stand-in curl that serves
# fake jars slowly, from a copy of the script with its pins set to the fakes'
# sha256 (JAVA=true: no JRE is fetched). Eight fetchers at once into one
# empty cache all succeed with the right bytes and leave no temp file (a
# shared .part path failed them: one truncated or renamed another's partial
# download); a good cache is used with no fetch; a bad download fails and
# leaves nothing behind; the java printed caps the heap. FETCH_TLA=<script>
# tests another copy. The same file
# in nfltr, link, relay, relay-core and relay-server.
set -eu
script=${FETCH_TLA:-$(dirname "$0")/fetch-tla.sh}
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "fetch-tla_test: $*" >&2; exit 1; }
sum() { shasum -a 256 "$1" | cut -d' ' -f1; }

mkdir "$t/serve" "$t/bin" "$t/cache"
printf 'fake tla2tools\n' >"$t/tla2tools.jar"
python3 -I -c 'import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z: z.write(sys.argv[2], "extension/tools/tla2tools.jar")' \
	"$t/serve/tlaplus.vscode-ide-2026.10.301552.vsix" "$t/tla2tools.jar"
printf 'fake community modules\n' >"$t/serve/CommunityModules-deps.jar"
J=$(sum "$t/tla2tools.jar")
V=$(sum "$t/serve/tlaplus.vscode-ide-2026.10.301552.vsix")
C=$(sum "$t/serve/CommunityModules-deps.jar")

sed -e "s/^jarsum=.*/jarsum=$J/" \
	-e "s/[0-9a-f]\{64\} \"\\\$vsix\"/$V \"\$vsix\"/" \
	-e "s/[0-9a-f]\{64\} \"\\\$cm\"/$C \"\$cm\"/" "$script" >"$t/fetch-tla.sh"
grep -q "^jarsum=$J\$" "$t/fetch-tla.sh" && grep -q "$V \"\$vsix\"" "$t/fetch-tla.sh" &&
	grep -q "$C \"\$cm\"" "$t/fetch-tla.sh" || fail "could not set the pins in a copy of $script"

# The stand-in curl: `curl ... -o FILE URL` writes $t/serve/<URL's last
# segment> into FILE in two parts with a pause between, so fetchers overlap.
cat >"$t/bin/curl" <<EOF
#!/bin/sh
[ -e "$t/curl-fails" ] && exit 22
while [ \$# -gt 1 ]; do [ "\$1" = -o ] && out=\$2; shift; done
src="$t/serve/\${1##*/}"
[ -f "\$src" ] || exit 22
head -c 8 "\$src" >"\$out"
sleep 1
tail -c +9 "\$src" >>"\$out"
EOF
chmod +x "$t/bin/curl" "$t/fetch-tla.sh"
run() { PATH="$t/bin:$PATH" JAVA=true RELAY_TLA_CACHE="$t/cache" "$t/fetch-tla.sh"; }

check_cache() {
	[ "$(sum "$t/cache/tla2tools-1.8.0.jar")" = "$J" ] || fail "$1: tla2tools jar has the wrong bytes"
	[ "$(sum "$t/cache/CommunityModules-deps-202505152026.jar")" = "$C" ] || fail "$1: CommunityModules jar has the wrong bytes"
	left=$(cd "$t/cache" && ls | grep -vxE 'java-[0-9]+|tla2tools-1\.8\.0\.jar|CommunityModules-deps-202505152026\.jar|tlaplus\.vscode-ide-2026\.10\.301552\.vsix' || true)
	[ -z "$left" ] || fail "$1: left in the cache: $left"
}

# Eight fetchers at once into one empty cache.
pids=
i=0
while [ $i -lt 8 ]; do
	run >"$t/out.$i" 2>"$t/err.$i" &
	pids="$pids $!"
	i=$((i + 1))
done
i=0
for p in $pids; do
	wait "$p" || fail "concurrent fetcher $i failed: $(cat "$t/err.$i")"
	[ "$(sed -n 2p "$t/out.$i")" = "$t/cache/tla2tools-1.8.0.jar" ] || fail "fetcher $i printed $(cat "$t/out.$i")"
	[ "$(sed -n 3p "$t/out.$i")" = "$t/cache/CommunityModules-deps-202505152026.jar" ] || fail "fetcher $i printed $(cat "$t/out.$i")"
	i=$((i + 1))
done
check_cache "8 concurrent fetchers"

# A good cache is used as it is: no fetch.
: >"$t/curl-fails"
run >/dev/null 2>"$t/err" || fail "a good cache still fetched: $(cat "$t/err")"
# A corrupt jar is rebuilt from the cached vsix, still with no fetch.
printf 'torn' >"$t/cache/tla2tools-1.8.0.jar"
run >/dev/null 2>"$t/err" || fail "a corrupt jar was not rebuilt from the cached vsix: $(cat "$t/err")"
check_cache "rebuilt jar"
rm -f "$t/curl-fails"

# The java printed caps the heap: TLC_RAM_PERCENT (25) of CI_MEM_BUDGET_MB
# over TLC_JVMS, the caller's arguments after it (a quote in the path kept).
printf '#!/bin/sh\necho "$@"\n' >"$t/bin/it's java"
chmod +x "$t/bin/it's java"
j=$(PATH="$t/bin:$PATH" JAVA="$t/bin/it's java" RELAY_TLA_CACHE="$t/cache" "$t/fetch-tla.sh" | sed -n 1p) || fail "fetch with a stand-in java failed"
[ "$(CI_MEM_BUDGET_MB=4096 "$j" -cp x)" = "-Xmx1024m -cp x" ] || fail "heap cap: $(CI_MEM_BUDGET_MB=4096 "$j" -cp x)"
[ "$(CI_MEM_BUDGET_MB=4000 TLC_RAM_PERCENT=60 TLC_JVMS=3 "$j" -cp x)" = "-Xmx800m -cp x" ] || fail "heap cap over 3 JVMs: $(CI_MEM_BUDGET_MB=4000 TLC_RAM_PERCENT=60 TLC_JVMS=3 "$j" -cp x)"

# A download with the wrong sha256 fails and leaves nothing behind.
rm -f "$t/cache/CommunityModules-deps-202505152026.jar"
printf 'tampered\n' >"$t/serve/CommunityModules-deps.jar"
if run >/dev/null 2>"$t/err"; then fail "a download with the wrong sha256 was kept"; fi
grep -q 'sha256' "$t/err" || fail "a bad download did not name its sha256: $(cat "$t/err")"
left=$(cd "$t/cache" && ls | grep '^CommunityModules' || true)
[ -z "$left" ] || fail "a bad download left: $left"

echo "fetch-tla_test: ok"

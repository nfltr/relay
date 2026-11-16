#!/bin/sh
# check-spec-actions.sh: every TLA+ model's steps against its README action
# table, both ways (the same check as nfltr's scripts/check-spec-actions.sh).
# A step is a top-level definition of the model that primes or keeps a
# variable (not Next, not a temporal formula); a table is a markdown table
# whose first header cell is "Action" under a heading naming `<Model>.tla`.
# Fails on a step no table names, or a row naming no definition of the model
# (its CONSTANTS aside). Then the recorders' hook points: every line kind a
# trace spec reads (E.ev = "X", Line("X")) is still written by the Go its
# recorder lives in (non-test files), else a removed hook point would leave
# the trace check vacuous for it. No Java; in make ci (make check-spec-actions).
set -eu
cd "$(dirname "$0")/.."
# <dir> <models> <heading substring, or - for `<Model>.tla`>
models='enrol Enrol -
enrol Join -
enrol RevokePush -
orgmove OrgMove -
orgmove OrgHolds -
orgmove OrgHosted -'

# steps <tla>: the model's step names.
steps() {
	awk '
		function flush() { if (name != "" && act && !tmp && name != "Next") print name; name = "" }
		/^[A-Z][A-Za-z0-9_]*(\(.*\))? ==/ { flush(); name = $1; sub(/\(.*/, "", name); act = 0; tmp = /\[\]\[/; next }
		/^(=+$|-+ MODULE)/ { flush() }
		name != "" && /UNCHANGED|'"'"' *(=|\\in)/ { act = 1 }
		name != "" && /\[\]\[|~>|<>\[\]|\[\]<>|^ *WF_|^ *SF_/ { tmp = 1 }
		END { flush() }' "$1"
}

# rows <readme> <heading>: the names in the first column of the action
# tables under a level-2 or level-3 heading containing <heading>.
rows() {
	awk -v h="$2" '
		/^## / { h2 = $0; h3 = "" }
		/^### / { h3 = $0 }
		/^#+ / { in_t = 0 }
		/^\| *[Aa]ction *\|/ { in_t = index(h2, h) > 0 || index(h3, h) > 0; next }
		in_t && !/^\|/ { in_t = 0 }
		in_t && /^\| *[`A-Z]/ { split($0, c, "|"); s = c[2]
			# backticked names, or (no backticks) every capitalized word
			if (index(s, "`")) { re = "`[A-Z][A-Za-z0-9_]*"; o = 1 } else { re = "[A-Z][A-Za-z0-9_]*"; o = 0 }
			while (match(s, re)) { print substr(s, RSTART + o, RLENGTH - o); s = substr(s, RSTART + RLENGTH) } }' "$1"
}

echo "$models" | while read -r dir ms head; do
	readme=spec/$dir/README.md
	files=""
	for m in $(echo "$ms" | tr , ' '); do files="$files spec/$dir/$m.tla"; done
	acts=$(for f in $files; do steps "$f"; done | sort -u)
	if [ "$head" = - ]; then tab=$(rows "$readme" "\`$ms.tla\`" | sort -u); else tab=$(rows "$readme" "$(echo "$head" | tr - ' ')" | sort -u); fi
	consts=$(for f in $files; do awk '/^CONSTANTS?/ { c = 1 } c && (/^[A-Z][A-Za-z]* ==/ || /^VARIABLES?/) { c = 0 } c' "$f"; done | grep -oE '^ +[A-Z][A-Za-z0-9_]*' | tr -d ' ' || true)
	for a in $acts; do
		echo "$tab" | grep -qx "$a" || { echo "$ms: step $a is not in $readme's action table"; echo x >>"${TMPDIR:-/tmp}/spec-actions.$$"; }
	done
	for a in $tab; do
		# shellcheck disable=SC2086 # files are words
		grep -qE "^$a(\(.*\))? ==" $files || echo "$consts" | grep -qx "$a" ||
			{ echo "$readme: $ms's action $a is not defined in $files"; echo x >>"${TMPDIR:-/tmp}/spec-actions.$$"; }
	done
done
# <trace spec> <recorder dirs> <line kinds written only by tests or fixtures>
recorders='enrol/TraceEnrol.tla org/orgpki,client/orgid -
enrol/TraceRevokePush.tla org/orgenrol -
orgmove/TraceOrgMove.tla org/orgpki,org/orgissuer -'
set -f # the pathspecs below are git's, not the shell's
echo "$recorders" | while read -r spec dirs only; do
	paths=""
	for d in $(echo "$dirs" | tr , ' '); do paths="$paths $d/*.go"; done
	for n in $(grep -oE '(E\.ev|ev) = "[A-Za-z]+"|Line\("[A-Za-z]+"\)' "spec/$spec" | grep -oE '"[A-Za-z]+"' | tr -d '"' | sort -u); do
		case ",$only," in *",$n,"*) continue ;; esac
		# shellcheck disable=SC2086 # paths are words
		git grep -q -F "\"$n\"" -- $paths ':!*_test.go' ||
			{ echo "spec/$spec: no recorder in $dirs writes line kind $n"; echo x >>"${TMPDIR:-/tmp}/spec-actions.$$"; }
	done
done
set +f
if [ -s "${TMPDIR:-/tmp}/spec-actions.$$" ]; then
	rm -f "${TMPDIR:-/tmp}/spec-actions.$$"
	exit 1
fi
echo "spec actions: every step mapped, every recorder hook point present"

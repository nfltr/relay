#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# check-identity.sh <object> [<remote sha>]: this repository is public and
# takes only commits authored and committed as `nfltr <oss@nfltr.xyz>`
# with no Co-Authored-By line, and annotated tags tagged so. Fails, naming
# each, on such a commit among those <object> (a commit or annotated tag)
# brings: <remote sha>..<object> when the remote has <remote sha>, else
# every commit no remote-tracking ref has. scripts/pre-push runs it on
# every ref pushed; scripts/check-identity_test.sh tests it.
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <object> [<remote sha>]" >&2; exit 2; }
want='nfltr <oss@nfltr.xyz>'
obj=$1 base=${2:-}
bad=0
if [ "$(git cat-file -t "$obj")" = tag ]; then
	body=$(git cat-file tag "$obj")
	tagger=$(printf '%s\n' "$body" | sed -n 's/^tagger \(.*>\) [0-9]* [-+][0-9]*$/\1/p')
	[ "$tagger" = "$want" ] || { echo "tag $obj: tagger $tagger, want $want" >&2; bad=1; }
	if printf '%s\n' "$body" | sed '1,/^$/d' | grep -qi '^co-authored-by:'; then
		echo "tag $obj: Co-Authored-By in its message" >&2
		bad=1
	fi
fi
commit=$(git rev-parse "$obj^{commit}")
range=("$commit" --not --remotes)
case "$base" in *[!0]*) git cat-file -e "$base^{commit}" 2>/dev/null && range=("$base..$commit") ;; esac
git log --format='%x1e%H%x1f%an <%ae>%x1f%cn <%ce>%x1f%B' "${range[@]}" -- |
	awk -v want="$want" 'BEGIN { RS = "\036"; FS = "\037"; bad = 0 }
	NF == 0 { next }
	{
		if ($2 != want) { print $1 ": author " $2 ", want " want; bad = 1 }
		if ($3 != want) { print $1 ": committer " $3 ", want " want; bad = 1 }
		if (tolower($4) ~ /(^|\n)co-authored-by:/) { print $1 ": Co-Authored-By in its message"; bad = 1 }
	}
	END { exit bad }' >&2 || bad=1
exit $bad

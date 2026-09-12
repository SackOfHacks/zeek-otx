#!/bin/bash
#
# Fails if install-so2.sh's OTX_REV pin no longer covers the code it installs.
#
# The installer clones this repository and runs the pinned revision as root,
# hourly, on every sensor. The pin therefore has to be bumped in the same pass
# as any change to the code it pins -- which is exactly what did not happen when
# three security PRs merged and left the pin two fixes behind, with the
# installer's own verification step still passing.
set -euo pipefail

INSTALLER="install-so2.sh"

# Paths whose contents the pin is responsible for: the tree that ends up on a
# sensor and runs there.
#
# The installer itself is deliberately not in this list. It runs from the user's
# own clone of main, never from the pinned tree, so a change to it reaches
# people without the pin moving -- and including it would make the check
# self-defeating, since bumping the pin edits the installer and would therefore
# always leave the installer newer than the pin.
PINNED_PATHS=(scripts)

pin=$(sed -n 's/^OTX_REV="${OTX_REV:-\([0-9a-f]\{40\}\)}"$/\1/p' "$INSTALLER")
if [ -z "$pin" ]; then
	echo "FAIL: could not find a 40-character OTX_REV pin in $INSTALLER." >&2
	exit 1
fi
echo "Pin: $pin"

if ! git cat-file -e "${pin}^{commit}" 2>/dev/null; then
	echo "FAIL: $pin is not a commit in this repository." >&2
	exit 1
fi

if ! git merge-base --is-ancestor "$pin" HEAD; then
	echo "FAIL: $pin is not an ancestor of HEAD, so installs would get code" >&2
	echo "      that is not on this branch." >&2
	exit 1
fi

if ! git diff --quiet "$pin" HEAD -- "${PINNED_PATHS[@]}"; then
	echo "FAIL: installed code has changed since the pinned revision $pin." >&2
	echo "      Bump OTX_REV in $INSTALLER, or those changes never reach a" >&2
	echo "      sensor. Changed since the pin:" >&2
	git diff --stat "$pin" HEAD -- "${PINNED_PATHS[@]}" >&2
	exit 1
fi

echo "OK: the pin covers every file the installer deploys."

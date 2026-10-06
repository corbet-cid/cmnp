#!/usr/bin/env bash
# The verified job runtime supplies the tool, source identity and check selection.
set -euo pipefail
: "${CCID_BIN:?Missing verified ccid job runtime}"
: "${CI_COMMIT_SHA:?Missing verified source commit}"
: "${CHECKS:?Missing declared check selection}"
test -x "$CCID_BIN"
if [[ -z ${CI_CACHE_ROOT:-}${CARGO_HOME:-}${CARGO_TARGET_DIR:-}${CARGO_BUILD_TARGET_DIR:-} ]]; then
  echo 'Repository jobs require an explicit persistent Cargo cache root' >&2
  exit 2
fi
export CCID_SOURCE_REVISION="$CI_COMMIT_SHA"
"$CCID_BIN" render --repo "$PWD" --check
# ccid owns resource admission, the existing target lock and selected commands.
exec "$CCID_BIN" check --repo "$PWD" --check "$CHECKS"

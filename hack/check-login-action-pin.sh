#!/usr/bin/env bash
# Every workflow must pin docker/login-action to the same full commit SHA.
#
# registry-login.yaml exercises that pin against a throwaway registry, so the
# publishing workflows must use the one it tested. The check reads every
# `uses:` value under the workflows directory, quoted or not, ignores comments,
# and fails when there is no reference, more than one distinct reference, or a
# reference that is not a 40-character hexadecimal commit.
#
# Usage: hack/check-login-action-pin.sh [workflows directory]
set -euo pipefail

dir="${1:-.github/workflows}"

# Drop comment lines and trailing comments, then keep the value of every `uses:`
# that names docker/login-action, with or without quotes around it.
refs="$(
  find "${dir}" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 \
    | xargs -0 sed -nE \
        -e '/^[[:space:]]*#/d' \
        -e 's/[[:space:]]+#.*$//' \
        -e "s/^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*[\"']?(docker\\/login-action@[^\"'[:space:]]+)[\"']?[[:space:]]*\$/\\2/p" \
    | sort -u
)"

count="$(printf '%s\n' "${refs}" | grep -c . || true)"
if [ "${count}" -eq 0 ]; then
  echo "::error::no docker/login-action reference found under ${dir}"
  exit 1
fi
if [ "${count}" -ne 1 ]; then
  echo "::error::workflows pin different docker/login-action references; update them together:"
  printf '%s\n' "${refs}"
  exit 1
fi

sha="${refs#docker/login-action@}"
if ! printf '%s' "${sha}" | grep -qE '^[0-9a-fA-F]{40}$'; then
  echo "::error::docker/login-action must be pinned to a full commit SHA, found ${refs}"
  exit 1
fi

echo "docker/login-action is pinned to ${sha} in every workflow"

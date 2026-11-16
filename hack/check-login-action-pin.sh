#!/usr/bin/env bash
# Every workflow must pin docker/login-action to the same full commit SHA.
#
# registry-login.yaml exercises that pin against a throwaway registry, so the
# publishing workflows must use the one it tested. The check reads every
# step's `uses:` value under the workflows directory, quoted or not, ignores comments,
# and fails when there is no reference, more than one distinct reference, or a
# reference that is not a 40-character hexadecimal commit.
#
# Usage: hack/check-login-action-pin.sh [workflows directory]
# Requires Mike Farah's yq v4.
set -euo pipefail

dir="${1:-.github/workflows}"

# Read jobs.*.steps[].uses, matching workflow keys case-insensitively.
# JSON strings keep each complete reference on one line, even for block scalars.
refs="$(
  find "${dir}" -type f \( -name '*.yml' -o -name '*.yaml' \) -exec yq -N -o=json -I=0 '
    .[]   | select((key | downcase) == "jobs") |
    .[][] | select((key | downcase) == "steps") |
    .[][] | select((key | downcase) == "uses") |
    explode(.) | select(tag == "!!str") |
    select(test("(?i)^docker/login-action@")) |
    sub("(?i)^docker/login-action@"; "docker/login-action@")
  ' {} + | LC_ALL=C sort -u
)"

if [[ -z "${refs}" ]]; then
  echo "::error::no docker/login-action reference found under ${dir}"
  exit 1
fi
if [[ "${refs}" == *$'\n'* ]]; then
  echo "::error::workflows pin different docker/login-action references; update them together:"
  printf '%s\n' "${refs}"
  exit 1
fi

pin_pattern='^"docker/login-action@([0-9a-fA-F]{40})"$'
if ! [[ "${refs}" =~ ${pin_pattern} ]]; then
  echo "::error::docker/login-action must be pinned to a full commit SHA, found ${refs}"
  exit 1
fi

echo "docker/login-action is pinned to ${BASH_REMATCH[1]} in every workflow"

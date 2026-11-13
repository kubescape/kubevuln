#!/usr/bin/env bash
# Focused cases for hack/check-login-action-pin.sh. Each case writes a small
# workflows directory and checks the exit code and the reported reason.
set -euo pipefail

check="$(cd "$(dirname "$0")" && pwd)/check-login-action-pin.sh"
sha="8aa5831fb8d48d8f76594c7ddde61ae58019f550"
other="3d3c42e5aac5ba805825da76410c181273ba90b1"
failures=0

run_case() {
  local name="$1" want_status="$2" want_text="$3"
  local dir out status
  dir="$(mktemp -d)"
  cat > "${dir}/a.yaml"
  set +e
  out="$("${check}" "${dir}" 2>&1)"
  status=$?
  set -e
  if [ "${status}" -ne "${want_status}" ] || ! printf '%s' "${out}" | grep -q -- "${want_text}"; then
    echo "FAIL ${name}: exit ${status} (want ${want_status}), output:"
    printf '%s\n' "${out}" | sed 's/^/  /'
    failures=$((failures + 1))
  else
    echo "ok   ${name}"
  fi
  rm -rf "${dir}"
}

run_case "one pin, unquoted and quoted" 0 "pinned to ${sha}" <<EOT
jobs:
  a:
    steps:
      - uses: docker/login-action@${sha} # v4.8.0
      - name: quoted
        uses: "docker/login-action@${sha}"
      - uses: 'docker/login-action@${sha}'
EOT

run_case "a comment naming another reference is ignored" 0 "pinned to ${sha}" <<EOT
# was uses: docker/login-action@${other}
jobs:
  a:
    steps:
      - uses: docker/login-action@${sha} # uses: docker/login-action@v4
EOT

run_case "two different pins" 1 "different docker/login-action references" <<EOT
jobs:
  a:
    steps:
      - uses: docker/login-action@${sha}
      - uses: "docker/login-action@${other}"
EOT

run_case "a tag is not a pin" 1 "full commit SHA" <<EOT
jobs:
  a:
    steps:
      - uses: docker/login-action@v4.8.0
EOT

run_case "a branch is not a pin" 1 "full commit SHA" <<EOT
jobs:
  a:
    steps:
      - uses: 'docker/login-action@main'
EOT

run_case "a short SHA is not a pin" 1 "full commit SHA" <<EOT
jobs:
  a:
    steps:
      - uses: docker/login-action@8aa5831
EOT

run_case "no reference at all" 1 "no docker/login-action reference" <<EOT
jobs:
  a:
    steps:
      - uses: actions/checkout@${other} # v7.0.1
      # - uses: docker/login-action@${sha}
EOT

if [ "${failures}" -ne 0 ]; then
  echo "${failures} case(s) failed"
  exit 1
fi
echo "all cases passed"

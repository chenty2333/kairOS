#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  run-directed-loop.sh \
    --arch <arch> \
    --suite <make-test-target> \
    --rounds <count> \
    --timeout-sec <seconds> \
    [--qemu-smp <count>] \
    [--expected-online <count>] \
    [--label <text>]
EOF
}

arch=""
suite=""
rounds=""
timeout_sec=""
qemu_smp=""
expected_online=""
label=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)
      arch="${2:-}"
      shift 2
      ;;
    --suite)
      suite="${2:-}"
      shift 2
      ;;
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      timeout_sec="${2:-}"
      shift 2
      ;;
    --qemu-smp)
      qemu_smp="${2:-}"
      shift 2
      ;;
    --expected-online)
      expected_online="${2:-}"
      shift 2
      ;;
    --label)
      label="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${arch}" || -z "${suite}" || -z "${rounds}" || -z "${timeout_sec}" ]]; then
  usage >&2
  exit 2
fi

re_uint='^[0-9]+$'
if [[ ! "${rounds}" =~ ${re_uint} ]] || (( rounds < 1 )); then
  echo "--rounds must be an integer >= 1" >&2
  exit 2
fi
if [[ ! "${timeout_sec}" =~ ${re_uint} ]] || (( timeout_sec < 1 )); then
  echo "--timeout-sec must be an integer >= 1" >&2
  exit 2
fi
if [[ -n "${qemu_smp}" ]] && ([[ ! "${qemu_smp}" =~ ${re_uint} ]] || (( qemu_smp < 1 ))); then
  echo "--qemu-smp must be an integer >= 1" >&2
  exit 2
fi
if [[ -n "${expected_online}" ]] && ([[ ! "${expected_online}" =~ ${re_uint} ]] || (( expected_online < 1 ))); then
  echo "--expected-online must be an integer >= 1" >&2
  exit 2
fi

if [[ -z "${label}" ]]; then
  label="${arch} ${suite}"
  if [[ -n "${qemu_smp}" ]]; then
    label+=" smp=${qemu_smp}"
  fi
fi

for i in $(seq 1 "${rounds}"); do
  printf '%s: round %s/%s\n' "${label}" "${i}" "${rounds}"
  make_cmd=(make --no-print-directory "ARCH=${arch}")
  if [[ -n "${qemu_smp}" ]]; then
    make_cmd+=("QEMU_SMP=${qemu_smp}")
  fi
  make_cmd+=("TEST_TIMEOUT=${timeout_sec}" "${suite}")
  "${make_cmd[@]}"

  latest="$(ls -1dt build/runs/* 2>/dev/null | head -n 1 || true)"
  if [[ -z "${latest}" ]]; then
    echo "No isolated run found after ${label} round ${i}" >&2
    exit 2
  fi
  python3 scripts/impl/assert-result-pass.py "${latest}/result.json" --require-structured
  if [[ -n "${expected_online}" ]]; then
    python3 scripts/impl/assert-aarch64-smp.py \
      --run-dir "${latest}" \
      --arch "${arch}" \
      --expected-online "${expected_online}"
  fi
done

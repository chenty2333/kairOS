#!/usr/bin/env bash
set -euo pipefail

ARCH="${ARCH:-riscv64}"
DEBUG_LEVELS="${DEBUG_LEVELS:-0 1}"
PCP_MODES="${PCP_MODES:-0 1 2}"
TOOLCHAIN_MODES="${TOOLCHAIN_MODES:-auto gcc clang}"
RUN_SOAK="${RUN_SOAK:-1}"
SOAK_TIMEOUT="${SOAK_TIMEOUT:-300}"
FAIL=0

run_case() {
  local tc_mode="$1"
  local dbg="$2"
  local pcp="$3"
  local extra="-DCONFIG_KERNEL_TESTS=1 -DCONFIG_PMM_PCP_MODE=${pcp}"
  if [[ "$dbg" == "1" ]]; then
    extra="${extra} -DCONFIG_DEBUG=1"
  fi

  echo "=== ARCH=${ARCH} TOOLCHAIN_MODE=${tc_mode} DEBUG=${dbg} PCP_MODE=${pcp} ==="
  if make ARCH="${ARCH}" TOOLCHAIN_MODE="${tc_mode}" TEST_EXTRA_CFLAGS="${extra}" test; then
    echo "PASS: test TOOLCHAIN_MODE=${tc_mode} DEBUG=${dbg} PCP_MODE=${pcp}"
  else
    echo "FAIL: test TOOLCHAIN_MODE=${tc_mode} DEBUG=${dbg} PCP_MODE=${pcp}"
    FAIL=1
  fi

  if [[ "${RUN_SOAK}" == "1" && "$pcp" == "2" && "$dbg" == "0" ]]; then
    echo "=== SOAK ARCH=${ARCH} TOOLCHAIN_MODE=${tc_mode} PCP_MODE=${pcp} TIMEOUT=${SOAK_TIMEOUT}s ==="
    if make ARCH="${ARCH}" TOOLCHAIN_MODE="${tc_mode}" \
        SOAK_EXTRA_CFLAGS="${extra}" SOAK_TIMEOUT="${SOAK_TIMEOUT}" test-soak; then
      echo "PASS: soak TOOLCHAIN_MODE=${tc_mode} PCP_MODE=${pcp}"
    else
      echo "FAIL: soak TOOLCHAIN_MODE=${tc_mode} PCP_MODE=${pcp}"
      FAIL=1
    fi
  fi
}

for tc_mode in $TOOLCHAIN_MODES; do
  for dbg in $DEBUG_LEVELS; do
    for pcp in $PCP_MODES; do
      run_case "$tc_mode" "$dbg" "$pcp"
    done
  done
done

exit "${FAIL}"

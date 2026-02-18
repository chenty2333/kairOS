#!/usr/bin/env bash
set -euo pipefail

CPUS="${CPUS:-1 2 4}"
DEBUG_LEVELS="${DEBUG_LEVELS:-0 1}"
ARCH="${ARCH:-riscv64}"
FAIL=0

for smp in $CPUS; do
  for dbg in $DEBUG_LEVELS; do
    echo "=== ARCH=$ARCH SMP=$smp CONFIG_DEBUG=$dbg ==="
    EXTRA="-DCONFIG_KERNEL_TESTS=1"
    if [ "$dbg" = "1" ]; then EXTRA="$EXTRA -DCONFIG_DEBUG=1"; fi
    if make ARCH="$ARCH" SMP="$smp" EXTRA_CFLAGS="$EXTRA" test; then
      echo "PASS: SMP=$smp DEBUG=$dbg"
    else
      echo "FAIL: SMP=$smp DEBUG=$dbg"
      FAIL=1
    fi
  done
done

exit $FAIL

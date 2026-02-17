#!/usr/bin/env bash

set -euo pipefail

QEMU_CMD="${QEMU_CMD:-}"
TEST_TIMEOUT="${TEST_TIMEOUT:-180}"
TEST_LOG="${TEST_LOG:-build/test.log}"

if [[ -z "${QEMU_CMD}" ]]; then
    echo "test: QEMU_CMD is empty" >&2
    exit 2
fi

if ! command -v timeout >/dev/null 2>&1; then
    echo "test: timeout command is required" >&2
    exit 2
fi

mkdir -p "$(dirname "${TEST_LOG}")"
rm -f "${TEST_LOG}"

echo "test: running qemu (timeout=${TEST_TIMEOUT}s)"
echo "test: log -> ${TEST_LOG}"

set +e
timeout --foreground "${TEST_TIMEOUT}s" bash -lc "${QEMU_CMD}" >"${TEST_LOG}" 2>&1
qemu_rc=$?
set -e

has_fail_markers=0
has_pass_marker=0
has_done_marker=0

if grep -Eiq "driver tests: [1-9][0-9]* failures|panic\\(|panic:|User exception|Kernel exception" "${TEST_LOG}"; then
    has_fail_markers=1
fi

if grep -Fq "driver tests: all passed" "${TEST_LOG}"; then
    has_pass_marker=1
fi

if grep -Fq "Tests complete. Stopping system..." "${TEST_LOG}"; then
    has_done_marker=1
fi

if [[ ${has_fail_markers} -eq 1 ]]; then
    echo "test: detected failure markers in log" >&2
    tail -n 120 "${TEST_LOG}" >&2 || true
    exit 1
fi

if [[ ${has_pass_marker} -eq 1 && ${has_done_marker} -eq 1 ]]; then
    if [[ ${qemu_rc} -eq 124 ]]; then
        echo "test: PASS (markers found, qemu timed out after completion)"
    else
        echo "test: PASS (qemu_rc=${qemu_rc})"
    fi
    exit 0
fi

if [[ ${qemu_rc} -eq 124 ]]; then
    echo "test: timeout after ${TEST_TIMEOUT}s" >&2
    tail -n 120 "${TEST_LOG}" >&2 || true
    exit 1
fi

if [[ ${has_pass_marker} -eq 0 ]]; then
    echo "test: missing pass marker: driver tests: all passed" >&2
else
    echo "test: missing completion marker" >&2
fi
tail -n 120 "${TEST_LOG}" >&2 || true
exit 1

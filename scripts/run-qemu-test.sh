#!/usr/bin/env bash

set -euo pipefail

QEMU_CMD="${QEMU_CMD:-}"
TEST_TIMEOUT="${TEST_TIMEOUT:-180}"
TEST_LOG="${TEST_LOG:-build/test.log}"
TEST_REQUIRE_MARKERS="${TEST_REQUIRE_MARKERS:-1}"
TEST_EXPECT_TIMEOUT="${TEST_EXPECT_TIMEOUT:-0}"
TEST_BOOT_MARKER="${TEST_BOOT_MARKER:-SMP: [0-9]+ CPUs active|init: started /init|BusyBox v}"

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
echo "test: require_markers=${TEST_REQUIRE_MARKERS} expect_timeout=${TEST_EXPECT_TIMEOUT}"

set +e
timeout --signal=TERM --kill-after=5s "${TEST_TIMEOUT}s" \
    bash -lc "${QEMU_CMD}" >"${TEST_LOG}" 2>&1
qemu_rc=$?
set -e

has_fail_markers=0
has_pass_marker=0
has_done_marker=0
has_boot_marker=0
has_summary_marker=0
has_summary_pass=0

if grep -Eiq "driver tests: [1-9][0-9]* failures|mm tests: [1-9][0-9]* failures|sched_stress: [1-9][0-9]* failures|sched_stress: .* FAIL:|panic\\(|panic:|User exception|Kernel exception|Trap dump|Inst page fault|sepc=0x0000000000000000|Zombie Rescheduling|ASSERT failed|pcp list corruption|PCP integrity failure|disabling PCP on cpu" "${TEST_LOG}"; then
    has_fail_markers=1
fi

if grep -Eiq "TEST_SUMMARY: failed=[0-9]+" "${TEST_LOG}"; then
    has_summary_marker=1
fi
if grep -Fq "TEST_SUMMARY: failed=0" "${TEST_LOG}"; then
    has_summary_pass=1
fi

if grep -Fq "driver tests: all passed" "${TEST_LOG}"; then
    has_pass_marker=1
fi

if grep -Fq "Tests complete. Stopping system..." "${TEST_LOG}"; then
    has_done_marker=1
fi

if grep -Eiq "${TEST_BOOT_MARKER}" "${TEST_LOG}"; then
    has_boot_marker=1
fi

if [[ ${has_fail_markers} -eq 1 ]]; then
    echo "test: detected failure markers in log" >&2
    tail -n 120 "${TEST_LOG}" >&2 || true
    exit 1
fi

if [[ "${TEST_REQUIRE_MARKERS}" -eq 0 ]]; then
    if [[ ${has_boot_marker} -eq 0 ]]; then
        echo "test: missing boot marker (${TEST_BOOT_MARKER})" >&2
        tail -n 120 "${TEST_LOG}" >&2 || true
        exit 1
    fi

    if [[ "${TEST_EXPECT_TIMEOUT}" -eq 1 ]]; then
        if [[ ${qemu_rc} -eq 124 ]]; then
            echo "test: PASS (soak timeout reached without failure markers)"
            exit 0
        fi
        if [[ ${qemu_rc} -eq 0 && ${has_pass_marker} -eq 1 && ${has_done_marker} -eq 1 ]]; then
            echo "test: PASS (soak completed early with success markers)"
            exit 0
        fi
        echo "test: expected timeout (${TEST_TIMEOUT}s) or successful completion markers, got qemu_rc=${qemu_rc}" >&2
        tail -n 120 "${TEST_LOG}" >&2 || true
        exit 1
    fi

    if [[ ${qemu_rc} -eq 0 ]]; then
        echo "test: PASS (qemu_rc=0, boot marker found)"
        exit 0
    fi
    echo "test: qemu exited unexpectedly (qemu_rc=${qemu_rc})" >&2
    tail -n 120 "${TEST_LOG}" >&2 || true
    exit 1
fi

if [[ ${has_summary_marker} -eq 1 ]]; then
    if [[ ${has_summary_pass} -eq 1 && ${has_done_marker} -eq 1 ]]; then
        if [[ ${qemu_rc} -eq 124 && "${TEST_EXPECT_TIMEOUT}" -eq 1 ]]; then
            echo "test: PASS (summary found, expected timeout)"
        else
            echo "test: PASS (qemu_rc=${qemu_rc}, summary passed)"
        fi
        exit 0
    fi
elif [[ ${has_pass_marker} -eq 1 && ${has_done_marker} -eq 1 ]]; then
    if [[ ${qemu_rc} -eq 124 && "${TEST_EXPECT_TIMEOUT}" -eq 1 ]]; then
        echo "test: PASS (markers found, expected timeout)"
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
    if [[ ${has_summary_marker} -eq 1 ]]; then
        echo "test: summary indicates failures" >&2
    else
        echo "test: missing pass marker: driver tests: all passed" >&2
    fi
else
    echo "test: missing completion marker" >&2
fi
tail -n 120 "${TEST_LOG}" >&2 || true
exit 1

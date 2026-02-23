#!/usr/bin/env bash

set -euo pipefail

QEMU_CMD="${QEMU_CMD:-}"
TEST_TIMEOUT="${TEST_TIMEOUT:-180}"
TEST_LOG="${TEST_LOG:-build/test.log}"
TEST_REQUIRE_MARKERS="${TEST_REQUIRE_MARKERS:-1}"
TEST_EXPECT_TIMEOUT="${TEST_EXPECT_TIMEOUT:-0}"
TEST_BOOT_MARKER="${TEST_BOOT_MARKER:-SMP: [0-9]+ CPUs active|init: started /init|BusyBox v}"
TEST_BUILD_ROOT="${TEST_BUILD_ROOT:-$(dirname "$TEST_LOG")}"
TEST_ARCH="${TEST_ARCH:-unknown}"
TEST_RUN_ID="${TEST_RUN_ID:-$(basename "$TEST_BUILD_ROOT")}"
TEST_MANIFEST="${TEST_MANIFEST:-${TEST_BUILD_ROOT}/manifest.json}"
TEST_RESULT="${TEST_RESULT:-${TEST_BUILD_ROOT}/result.json}"
TEST_QEMU_PID_FILE="${TEST_QEMU_PID_FILE:-${TEST_BUILD_ROOT}/test-runner.pid}"

json_quote() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

json_bool() {
    if [[ "$1" -eq 1 ]]; then
        echo "true"
    else
        echo "false"
    fi
}

write_manifest() {
    local start_time_utc="$1"
    local git_sha="unknown"
    if command -v git >/dev/null 2>&1; then
        git_sha="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    fi

    cat >"${TEST_MANIFEST}" <<JSON
{
  "schema_version": 1,
  "run_id": $(json_quote "${TEST_RUN_ID}"),
  "arch": $(json_quote "${TEST_ARCH}"),
  "build_root": $(json_quote "${TEST_BUILD_ROOT}"),
  "command": "run-qemu-test.sh",
  "qemu_cmd": $(json_quote "${QEMU_CMD}"),
  "git_sha": $(json_quote "${git_sha}"),
  "start_time_utc": $(json_quote "${start_time_utc}"),
  "host_pid": $$,
  "test_log": $(json_quote "${TEST_LOG}")
}
JSON
}

write_result() {
    local end_time_utc="$1"
    local duration_ms="$2"
    local status="$3"
    local reason="$4"
    local exit_code="$5"
    local qemu_rc="$6"
    local summary_failed="$7"
    local has_fail_markers="$8"
    local has_pass_marker="$9"
    local has_done_marker="${10}"
    local has_boot_marker="${11}"
    local has_summary_marker="${12}"

    cat >"${TEST_RESULT}" <<JSON
{
  "schema_version": 1,
  "run_id": $(json_quote "${TEST_RUN_ID}"),
  "status": $(json_quote "${status}"),
  "reason": $(json_quote "${reason}"),
  "exit_code": ${exit_code},
  "qemu_exit_code": ${qemu_rc},
  "summary_failed": ${summary_failed},
  "log_path": $(json_quote "${TEST_LOG}"),
  "end_time_utc": $(json_quote "${end_time_utc}"),
  "duration_ms": ${duration_ms},
  "markers": {
    "has_fail_markers": $(json_bool "${has_fail_markers}"),
    "has_pass_marker": $(json_bool "${has_pass_marker}"),
    "has_done_marker": $(json_bool "${has_done_marker}"),
    "has_boot_marker": $(json_bool "${has_boot_marker}"),
    "has_summary_marker": $(json_bool "${has_summary_marker}")
  }
}
JSON
}

if [[ -z "${QEMU_CMD}" ]]; then
    echo "test: QEMU_CMD is empty" >&2
    exit 2
fi

if ! command -v timeout >/dev/null 2>&1; then
    echo "test: timeout command is required" >&2
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "test: python3 is required for manifest/result JSON output" >&2
    exit 2
fi

mkdir -p "$(dirname "${TEST_LOG}")" "$(dirname "${TEST_MANIFEST}")" "$(dirname "${TEST_RESULT}")" "$(dirname "${TEST_QEMU_PID_FILE}")"
rm -f "${TEST_LOG}"

start_ms="$(date +%s%3N)"
start_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
write_manifest "${start_time_utc}"

if [[ -f "${TEST_QEMU_PID_FILE}" ]]; then
    old_pid="$(cat "${TEST_QEMU_PID_FILE}" 2>/dev/null || true)"
    if [[ "${old_pid}" =~ ^[0-9]+$ ]] && kill -0 "${old_pid}" >/dev/null 2>&1; then
        end_ms="$(date +%s%3N)"
        end_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        duration_ms="$((end_ms - start_ms))"
        write_result "${end_time_utc}" "${duration_ms}" "error" "existing_qemu_pid" 2 2 -1 0 0 0 0 0
        echo "test: existing qemu pid is still running (${old_pid})" >&2
        exit 2
    fi
    rm -f "${TEST_QEMU_PID_FILE}"
fi

echo "test: running qemu (timeout=${TEST_TIMEOUT}s)"
echo "test: log -> ${TEST_LOG}"
echo "test: require_markers=${TEST_REQUIRE_MARKERS} expect_timeout=${TEST_EXPECT_TIMEOUT}"
echo "test: manifest -> ${TEST_MANIFEST}"
echo "test: result -> ${TEST_RESULT}"

wrapped_qemu_cmd=""
printf -v wrapped_qemu_cmd 'echo "$$" > %q; exec %s' "${TEST_QEMU_PID_FILE}" "${QEMU_CMD}"

set +e
timeout --signal=TERM --kill-after=5s "${TEST_TIMEOUT}s" \
    bash -lc "${wrapped_qemu_cmd}" >"${TEST_LOG}" 2>&1
qemu_rc=$?
set -e
rm -f "${TEST_QEMU_PID_FILE}"

has_fail_markers=0
has_pass_marker=0
has_done_marker=0
has_boot_marker=0
has_summary_marker=0
summary_failed=-1

if grep -Fq "driver tests: all passed" "${TEST_LOG}"; then
    has_pass_marker=1
fi

if grep -Fq "Tests complete. Stopping system..." "${TEST_LOG}"; then
    has_done_marker=1
fi

if grep -Eiq "${TEST_BOOT_MARKER}" "${TEST_LOG}"; then
    has_boot_marker=1
fi

summary_line="$(grep -Eo 'TEST_SUMMARY: failed=[0-9]+' "${TEST_LOG}" | tail -n 1 || true)"
if [[ -n "${summary_line}" ]]; then
    has_summary_marker=1
    summary_failed="${summary_line##*=}"
fi

if grep -Eiq "driver tests: [1-9][0-9]* failures|mm tests: [1-9][0-9]* failures|sched_stress: [1-9][0-9]* failures|sched_stress: .* FAIL:|panic\\(|panic:|User exception|Kernel exception|Trap dump|Inst page fault|sepc=0x0000000000000000|Zombie Rescheduling|ASSERT failed|pcp list corruption|PCP integrity failure|disabling PCP on cpu" "${TEST_LOG}"; then
    has_fail_markers=1
fi

status="fail"
reason="unknown"
exit_code=1

if [[ "${TEST_REQUIRE_MARKERS}" -eq 0 ]]; then
    if [[ ${has_boot_marker} -eq 0 ]]; then
        status="fail"
        reason="missing_boot_marker"
    elif [[ "${TEST_EXPECT_TIMEOUT}" -eq 1 ]]; then
        if [[ ${has_summary_marker} -eq 1 ]]; then
            if [[ "${summary_failed}" -eq 0 && ( ${qemu_rc} -eq 124 || ( ${qemu_rc} -eq 0 && ${has_done_marker} -eq 1 ) ) ]]; then
                status="pass"
                reason="summary_passed"
                exit_code=0
            else
                status="fail"
                reason="summary_failed_or_exit_mismatch"
            fi
        elif [[ ${qemu_rc} -eq 124 && ${has_fail_markers} -eq 0 ]]; then
            status="pass"
            reason="expected_timeout"
            exit_code=0
        elif [[ ${qemu_rc} -eq 0 && ${has_pass_marker} -eq 1 && ${has_done_marker} -eq 1 ]]; then
            status="pass"
            reason="completed_early_with_markers"
            exit_code=0
        elif [[ ${has_fail_markers} -eq 1 ]]; then
            status="fail"
            reason="failure_markers_detected"
        else
            status="fail"
            reason="unexpected_exit_in_soak"
        fi
    else
        if [[ ${has_summary_marker} -eq 1 ]]; then
            if [[ "${summary_failed}" -eq 0 && ${qemu_rc} -eq 0 ]]; then
                status="pass"
                reason="summary_passed"
                exit_code=0
            else
                status="fail"
                reason="summary_failed"
            fi
        elif [[ ${qemu_rc} -eq 0 && ${has_fail_markers} -eq 0 ]]; then
            status="pass"
            reason="qemu_exit_zero"
            exit_code=0
        elif [[ ${has_fail_markers} -eq 1 ]]; then
            status="fail"
            reason="failure_markers_detected"
        elif [[ ${qemu_rc} -eq 124 ]]; then
            status="timeout"
            reason="timeout"
        else
            status="fail"
            reason="unexpected_exit"
        fi
    fi
else
    if [[ ${has_summary_marker} -eq 1 ]]; then
        if [[ "${summary_failed}" -eq 0 && ${has_done_marker} -eq 1 ]]; then
            status="pass"
            reason="summary_passed"
            exit_code=0
        elif [[ "${summary_failed}" -gt 0 ]]; then
            status="fail"
            reason="summary_failed"
        else
            status="fail"
            reason="summary_missing_done_marker"
        fi
    elif [[ ${has_pass_marker} -eq 1 && ${has_done_marker} -eq 1 ]]; then
        status="pass"
        reason="legacy_markers_passed"
        exit_code=0
    elif [[ ${has_fail_markers} -eq 1 ]]; then
        status="fail"
        reason="failure_markers_detected"
    elif [[ ${qemu_rc} -eq 124 ]]; then
        status="timeout"
        reason="timeout"
    else
        status="fail"
        reason="missing_pass_markers"
    fi
fi

if [[ "${status}" != "pass" && "${status}" != "error" ]]; then
    exit_code=1
fi

end_ms="$(date +%s%3N)"
end_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
duration_ms="$((end_ms - start_ms))"
write_result "${end_time_utc}" "${duration_ms}" "${status}" "${reason}" "${exit_code}" "${qemu_rc}" "${summary_failed}" "${has_fail_markers}" "${has_pass_marker}" "${has_done_marker}" "${has_boot_marker}" "${has_summary_marker}"

if [[ "${status}" == "pass" ]]; then
    echo "test: PASS (${reason}, qemu_rc=${qemu_rc})"
    exit 0
fi

echo "test: ${status} (${reason}, qemu_rc=${qemu_rc})" >&2
tail -n 120 "${TEST_LOG}" >&2 || true
exit "${exit_code}"

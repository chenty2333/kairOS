#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KAIROS_ROOT_DIR="${KAIROS_ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
# shellcheck source=scripts/lib/lock.sh
source "${SCRIPT_DIR}/lib/lock.sh"

QEMU_CMD="${QEMU_CMD:-}"
TEST_TIMEOUT="${TEST_TIMEOUT:-180}"
TEST_LOG="${TEST_LOG:-build/test.log}"
TEST_REQUIRE_MARKERS="${TEST_REQUIRE_MARKERS:-1}"
TEST_EXPECT_TIMEOUT="${TEST_EXPECT_TIMEOUT:-0}"
TEST_REQUIRE_STRUCTURED="${TEST_REQUIRE_STRUCTURED:-auto}"
TEST_BOOT_MARKER="${TEST_BOOT_MARKER:-SMP: ([0-9]+ CPU active|[0-9]+ CPUs active|[0-9]+/[0-9]+ CPUs active)|init: started /init|BusyBox v}"
TEST_FATAL_MARKER="${TEST_FATAL_MARKER:-panic\\(|panic:|User exception|Kernel exception|Trap dump|Inst page fault|ASSERT failed|sepc=0x0000000000000000}"
TEST_FAILURE_MARKER="${TEST_FAILURE_MARKER:-driver tests: [1-9][0-9]* failures|mm tests: [1-9][0-9]* failures|sched_stress: [1-9][0-9]* failures|sched_stress: .* FAIL:|vfs_ipc_tests: .* failed|socket_tests: .* failed|device_virtio_tests: .* failed|syscall_trap_tests: .* failed|tty_tests: .* failed|soak_tests: .* failed}"
TEST_REQUIRED_MARKER_REGEX="${TEST_REQUIRED_MARKER_REGEX:-}"
TEST_REQUIRED_MARKERS_ALL="${TEST_REQUIRED_MARKERS_ALL:-}"
TEST_FORBIDDEN_MARKER_REGEX="${TEST_FORBIDDEN_MARKER_REGEX:-}"
TEST_OPTIONAL_MARKERS_IF_PRESENT="${TEST_OPTIONAL_MARKERS_IF_PRESENT:-}"
TEST_BUILD_ROOT="${TEST_BUILD_ROOT:-$(dirname "$TEST_LOG")}"
TEST_ARCH="${TEST_ARCH:-unknown}"
TEST_RUN_ID="${TEST_RUN_ID:-$(basename "$TEST_BUILD_ROOT")}"
TEST_MANIFEST="${TEST_MANIFEST:-${TEST_BUILD_ROOT}/manifest.json}"
TEST_RESULT="${TEST_RESULT:-${TEST_BUILD_ROOT}/result.json}"
TEST_QEMU_PID_FILE="${TEST_QEMU_PID_FILE:-${TEST_BUILD_ROOT}/test-runner.pid}"
TEST_BUILD_DIR="${TEST_BUILD_DIR:-${TEST_BUILD_ROOT}/${TEST_ARCH}}"
TEST_LOCK_FILE="${TEST_LOCK_FILE:-${TEST_BUILD_DIR}/.locks/qemu.lock}"
TEST_LOCK_WAIT="${TEST_LOCK_WAIT:-0}"
TEST_UEFI_BOOT_MODE="${UEFI_BOOT_MODE:-}"
TEST_QEMU_UEFI_BOOT_MODE="${QEMU_UEFI_BOOT_MODE:-}"

if [[ "${TEST_REQUIRE_STRUCTURED}" == "auto" ]]; then
    if [[ "${TEST_REQUIRE_MARKERS}" == "1" ]]; then
        TEST_REQUIRE_STRUCTURED=1
    else
        TEST_REQUIRE_STRUCTURED=0
    fi
fi

if [[ "${TEST_REQUIRE_MARKERS}" == "1" ]] && [[ -z "${TEST_OPTIONAL_MARKERS_IF_PRESENT}" ]]; then
    TEST_OPTIONAL_MARKERS_IF_PRESENT=$'boot: limine loaded base revision=.*\tboot: limine loaded base revision=[0-9]+\nboot: limine executable .*\tboot: limine executable media=[0-9]+ part=[0-9]+ path=.* string=.* rev=[0-9]+\nboot: limine date_at_boot=.*\tboot: limine date_at_boot=-?[0-9]+ rev=[0-9]+\nboot: limine perf .*\tboot: limine perf reset=[0-9]+us init=[0-9]+us exec=[0-9]+us rev=[0-9]+\nboot: limine smbios .*\tboot: limine smbios rev=[0-9]+ entry32=.* entry64=.*\nboot: limine efi memmap .*\tboot: limine efi memmap rev=[0-9]+ size=[0-9]+ desc_size=[0-9]+ desc_ver=[0-9]+\nboot: limine riscv bsp hartid=.*\tboot: limine riscv bsp hartid=[0-9]+ rev=[0-9]+'
fi

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

json_int_or_null() {
    local value="$1"
    if [[ "${value}" =~ ^-?[0-9]+$ ]] && [[ "${value}" -ge 0 ]]; then
        echo "${value}"
    else
        echo "null"
    fi
}

extract_structured_result() {
    python3 - "$TEST_LOG" <<'PY'
import json
import re
import sys

log_path = sys.argv[1]
pattern = re.compile(r"TEST_RESULT_JSON:\s*(\{.*\})")
raw_json = None

try:
    with open(log_path, "r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            match = pattern.search(line)
            if match:
                raw_json = match.group(1).strip()
except FileNotFoundError:
    print("missing -1 -1 -1 -1")
    sys.exit(0)

if raw_json is None:
    print("missing -1 -1 -1 -1")
    sys.exit(0)

try:
    obj = json.loads(raw_json)
except Exception:
    print("invalid -1 -1 -1 -1")
    sys.exit(0)

def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None

schema = as_int(obj.get("schema_version"))
failed = as_int(obj.get("failed"))
done = obj.get("done")
enabled_mask = as_int(obj.get("enabled_mask"))

if schema is None or failed is None or not isinstance(done, bool):
    print("invalid -1 -1 -1 -1")
    sys.exit(0)

if enabled_mask is None:
    enabled_mask = -1

print(f"ok {schema} {failed} {1 if done else 0} {enabled_mask}")
PY
}

extract_summary_result() {
    python3 - "$TEST_LOG" <<'PY'
import re
import sys

log_path = sys.argv[1]
pattern = re.compile(r"TEST_SUMMARY:\s*failed=([0-9]+)\s*$")
raw_failed = None
saw_summary_prefix = False

try:
    with open(log_path, "r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            if "TEST_SUMMARY:" not in line:
                continue
            saw_summary_prefix = True
            match = pattern.search(line.strip())
            if match:
                raw_failed = int(match.group(1))
except FileNotFoundError:
    print("missing -1")
    sys.exit(0)

if raw_failed is not None:
    print(f"ok {raw_failed}")
elif saw_summary_prefix:
    print("invalid -1")
else:
    print("missing -1")
PY
}

extract_first_smoke_fail_reason() {
    local log_path="$1"
    local line=""

    if [[ ! -f "${log_path}" ]]; then
        echo ""
        return 0
    fi

    line="$(
        awk '
            match($0, /^[[:space:]]*SMOKE_FAIL_FIRST:[A-Za-z0-9_.-]+[[:space:]]*$/) {
                m = $0
                sub(/^[[:space:]]*/, "", m)
                sub(/[[:space:]]*$/, "", m)
                print m
                exit 0
            }
        ' "${log_path}" || true
    )"
    if [[ -z "${line}" ]]; then
        line="$(
            awk '
                match($0, /^[[:space:]]*SMOKE_FAIL:[A-Za-z0-9_.-]+[[:space:]]*$/) {
                    m = $0
                    sub(/^[[:space:]]*/, "", m)
                    sub(/[[:space:]]*$/, "", m)
                    print m
                    exit 0
                }
            ' "${log_path}" || true
        )"
    fi

    if [[ -n "${line}" ]]; then
        echo "${line#*:}"
        return 0
    fi
    echo ""
}

extract_qemu_signal_meta() {
    local log_path="$1"
    local line=""

    if [[ -f "${log_path}" ]]; then
        line="$(grep -Eo 'terminating on signal [0-9]+( from pid [0-9]+)?' "${log_path}" | tail -n 1 || true)"
    fi

    if [[ "${line}" =~ signal[[:space:]]+([0-9]+)[[:space:]]+from[[:space:]]+pid[[:space:]]+([0-9]+) ]]; then
        printf '%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
        return 0
    fi
    if [[ "${line}" =~ signal[[:space:]]+([0-9]+) ]]; then
        printf '%s -1\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    printf '%s %s\n' "-1" "-1"
}

detect_pre_qemu_failure_reason() {
    local log_path="$1"

    if [[ ! -f "${log_path}" ]]; then
        echo "pre_qemu_failure_no_log"
        return 0
    fi

    if grep -Eiq 'ld(\.lld)?: error:|undefined symbol:|collect2: error:' "${log_path}"; then
        echo "build_fail_link"
        return 0
    fi

    if grep -Eiq 'Error: toolchain failed \(rc=[0-9]+\)|stamps/(musl|compiler-rt|busybox|tcc)\.stamp.*Error [0-9]+' "${log_path}"; then
        echo "build_fail_toolchain"
        return 0
    fi

    if grep -Eiq 'make(\[[0-9]+\])?: \*\*\* .* Error [0-9]+' "${log_path}"; then
        echo "build_fail_make"
        return 0
    fi

    echo "pre_qemu_failure"
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
  "uefi_boot_mode": $(json_quote "${TEST_UEFI_BOOT_MODE}"),
  "qemu_uefi_boot_mode": $(json_quote "${TEST_QEMU_UEFI_BOOT_MODE}"),
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
    local verdict_source="$7"
    local has_boot_marker="$8"
    local has_fatal_markers="$9"
    local has_failure_markers="${10}"
    local structured_status="${11}"
    local structured_schema="${12}"
    local structured_failed="${13}"
    local structured_done="${14}"
    local structured_enabled_mask="${15}"
    local summary_status="${16}"
    local summary_failed="${17}"
    local has_required_markers="${18}"
    local has_forbidden_markers="${19}"
    local qemu_exit_signal="${20}"
    local qemu_term_signal="${21}"
    local qemu_term_sender_pid="${22}"

    cat >"${TEST_RESULT}" <<JSON
{
  "schema_version": 1,
  "run_id": $(json_quote "${TEST_RUN_ID}"),
  "status": $(json_quote "${status}"),
  "reason": $(json_quote "${reason}"),
  "verdict_source": $(json_quote "${verdict_source}"),
  "exit_code": ${exit_code},
  "qemu_exit_code": ${qemu_rc},
  "signals": {
    "qemu_exit_signal": $(json_int_or_null "${qemu_exit_signal}"),
    "qemu_term_signal": $(json_int_or_null "${qemu_term_signal}"),
    "qemu_term_sender_pid": $(json_int_or_null "${qemu_term_sender_pid}")
  },
  "log_path": $(json_quote "${TEST_LOG}"),
  "end_time_utc": $(json_quote "${end_time_utc}"),
  "duration_ms": ${duration_ms},
  "structured": {
    "status": $(json_quote "${structured_status}"),
    "schema_version": $(json_int_or_null "${structured_schema}"),
    "failed": $(json_int_or_null "${structured_failed}"),
    "done": $(json_bool "${structured_done}"),
    "enabled_mask": $(json_int_or_null "${structured_enabled_mask}")
  },
  "summary": {
    "status": $(json_quote "${summary_status}"),
    "failed": $(json_int_or_null "${summary_failed}")
  },
  "markers": {
    "has_boot_marker": $(json_bool "${has_boot_marker}"),
    "has_fatal_markers": $(json_bool "${has_fatal_markers}"),
    "has_failure_markers": $(json_bool "${has_failure_markers}"),
    "has_required_markers": $(json_bool "${has_required_markers}"),
    "has_forbidden_markers": $(json_bool "${has_forbidden_markers}")
  }
}
JSON
}

run_test_main() {
    local start_ms start_time_utc end_ms end_time_utc duration_ms
    local old_pid wrapped_qemu_cmd qemu_rc
    local has_boot_marker has_fatal_markers has_failure_markers
    local has_required_markers has_forbidden_markers has_optional_markers
    local optional_marker_failed_rule
    local qemu_exit_signal qemu_term_signal qemu_term_sender_pid
    local structured_status structured_schema structured_failed structured_done structured_enabled_mask
    local summary_status summary_failed
    local smoke_fail_reason
    local pre_qemu_reason
    local status reason exit_code verdict_source
    local allow_signal_override

    mkdir -p "${TEST_BUILD_ROOT}" \
        "$(dirname "${TEST_LOG}")" \
        "$(dirname "${TEST_MANIFEST}")" \
        "$(dirname "${TEST_RESULT}")" \
        "$(dirname "${TEST_QEMU_PID_FILE}")"
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
            write_result "${end_time_utc}" "${duration_ms}" "error" "existing_qemu_pid" 2 2 "infra" 0 0 0 "missing" -1 -1 0 -1 "missing" -1 1 0 -1 -1 -1
            echo "test: existing qemu pid is still running (${old_pid})" >&2
            return 2
        fi
        rm -f "${TEST_QEMU_PID_FILE}"
    fi

    echo "test: running qemu (timeout=${TEST_TIMEOUT}s)"
    echo "test: log -> ${TEST_LOG}"
    echo "test: require_markers=${TEST_REQUIRE_MARKERS} expect_timeout=${TEST_EXPECT_TIMEOUT} require_structured=${TEST_REQUIRE_STRUCTURED}"
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

    has_boot_marker=0
    has_fatal_markers=0
    has_failure_markers=0
    has_required_markers=1
    has_forbidden_markers=0
    has_optional_markers=1
    optional_marker_failed_rule=""

    if grep -Eiq "${TEST_BOOT_MARKER}" "${TEST_LOG}"; then
        has_boot_marker=1
    fi

    if grep -Eiq "${TEST_FATAL_MARKER}" "${TEST_LOG}"; then
        has_fatal_markers=1
    fi

    if grep -Eiq "${TEST_FAILURE_MARKER}" "${TEST_LOG}"; then
        has_failure_markers=1
    fi
    if [[ -n "${TEST_REQUIRED_MARKER_REGEX}" ]] &&
        ! grep -Eiq "${TEST_REQUIRED_MARKER_REGEX}" "${TEST_LOG}"; then
        has_required_markers=0
    fi
    if [[ ${has_required_markers} -eq 1 && -n "${TEST_REQUIRED_MARKERS_ALL}" ]]; then
        while IFS= read -r required; do
            if [[ -z "${required}" ]]; then
                continue
            fi
            if ! grep -Eiq "${required}" "${TEST_LOG}"; then
                has_required_markers=0
                break
            fi
        done <<< "${TEST_REQUIRED_MARKERS_ALL}"
    fi
    if [[ ${has_required_markers} -eq 1 && -n "${TEST_OPTIONAL_MARKERS_IF_PRESENT}" ]]; then
        while IFS=$'\t' read -r present required; do
            if [[ -z "${present}" || -z "${required}" ]]; then
                continue
            fi
            if grep -Eiq "${present}" "${TEST_LOG}" &&
                ! grep -Eiq "${required}" "${TEST_LOG}"; then
                has_optional_markers=0
                optional_marker_failed_rule="${required}"
                break
            fi
        done <<< "${TEST_OPTIONAL_MARKERS_IF_PRESENT}"
    fi
    if [[ -n "${TEST_FORBIDDEN_MARKER_REGEX}" ]] &&
        grep -Eiq "${TEST_FORBIDDEN_MARKER_REGEX}" "${TEST_LOG}"; then
        has_forbidden_markers=1
    fi

    qemu_exit_signal=-1
    if [[ ${qemu_rc} -gt 128 && ${qemu_rc} -le 255 ]]; then
        qemu_exit_signal="$((qemu_rc - 128))"
    fi
    read -r qemu_term_signal qemu_term_sender_pid < <(extract_qemu_signal_meta "${TEST_LOG}")

    structured_status="missing"
    structured_schema=-1
    structured_failed=-1
    structured_done=0
    structured_enabled_mask=-1
    read -r structured_status structured_schema structured_failed structured_done structured_enabled_mask < <(extract_structured_result)
    summary_status="missing"
    summary_failed=-1
    read -r summary_status summary_failed < <(extract_summary_result)
    smoke_fail_reason="$(extract_first_smoke_fail_reason "${TEST_LOG}")"
    pre_qemu_reason=""

    status="fail"
    reason="unknown"
    exit_code=1
    verdict_source="structured"

    if [[ ${has_forbidden_markers} -eq 1 ]]; then
        status="fail"
        reason="forbidden_markers_detected"
    elif [[ "${TEST_REQUIRE_STRUCTURED}" -eq 1 ]]; then
        verdict_source="structured"
        if [[ "${structured_status}" == "missing" ]]; then
            pre_qemu_reason="$(detect_pre_qemu_failure_reason "${TEST_LOG}")"
            status="infra_fail"
            if [[ "${pre_qemu_reason}" != "pre_qemu_failure" ]]; then
                reason="${pre_qemu_reason}"
            elif [[ ${qemu_rc} -eq 124 ]]; then
                reason="timeout_without_structured"
            else
                reason="missing_structured_result"
            fi
        elif [[ "${structured_status}" == "invalid" ]]; then
            status="infra_fail"
            reason="invalid_structured_result"
        elif [[ "${structured_done}" -ne 1 ]]; then
            status="infra_fail"
            reason="structured_done_false"
        elif [[ "${summary_status}" == "missing" ]]; then
            status="infra_fail"
            reason="missing_test_summary"
        elif [[ "${summary_status}" == "invalid" ]]; then
            status="infra_fail"
            reason="invalid_test_summary"
        elif [[ "${summary_failed}" -ne "${structured_failed}" ]]; then
            status="infra_fail"
            reason="summary_result_mismatch"
        elif [[ "${structured_failed}" -gt 0 ]]; then
            status="fail"
            if [[ -n "${smoke_fail_reason}" ]]; then
                reason="smoke_${smoke_fail_reason}"
            else
                reason="structured_failed"
            fi
        elif [[ ${has_required_markers} -eq 0 ]]; then
            status="fail"
            reason="required_markers_missing"
        elif [[ ${has_optional_markers} -eq 0 ]]; then
            status="fail"
            reason="optional_markers_invalid"
        elif [[ ${qemu_rc} -eq 0 ]]; then
            status="pass"
            reason="structured_passed"
        elif [[ ${qemu_rc} -eq 124 ]]; then
            status="pass"
            reason="structured_passed_timeout_exit"
        elif [[ ${qemu_rc} -eq 2 ]]; then
            status="pass"
            reason="structured_passed_qemu_reset_exit"
        else
            status="fail"
            reason="unexpected_exit_after_structured"
        fi
    elif [[ ${has_required_markers} -eq 0 ]]; then
        status="fail"
        reason="required_markers_missing"
    elif [[ ${has_optional_markers} -eq 0 ]]; then
        status="fail"
        reason="optional_markers_invalid"
    else
        verdict_source="unstructured"
        if [[ ${has_fatal_markers} -eq 1 ]]; then
            status="fail"
            reason="fatal_markers_detected"
        elif [[ "${TEST_EXPECT_TIMEOUT}" -eq 1 ]]; then
            if [[ ${qemu_rc} -eq 124 ]]; then
                status="pass"
                reason="expected_timeout"
            elif [[ ${qemu_rc} -eq 0 ]]; then
                status="pass"
                reason="qemu_exit_zero"
            else
                status="fail"
                reason="unexpected_exit_in_soak"
            fi
        else
            if [[ ${qemu_rc} -eq 0 ]]; then
                status="pass"
                reason="qemu_exit_zero"
            elif [[ ${qemu_rc} -eq 124 ]]; then
                status="timeout"
                reason="timeout"
            else
                status="fail"
                reason="unexpected_exit"
            fi
        fi
    fi

    allow_signal_override=1
    if [[ "${TEST_REQUIRE_STRUCTURED}" -eq 1 ]] &&
        [[ "${structured_status}" == "ok" ]] &&
        [[ "${structured_done}" -eq 1 ]] &&
        [[ "${structured_failed}" -gt 0 ]]; then
        allow_signal_override=0
    fi
    if [[ "${TEST_REQUIRE_STRUCTURED}" -eq 0 ]] && [[ ${has_fatal_markers} -eq 1 ]]; then
        allow_signal_override=0
    fi
    if [[ ${allow_signal_override} -eq 1 ]] &&
        [[ "${status}" != "pass" ]] &&
        [[ ${qemu_exit_signal} -gt 0 ]] &&
        [[ ${qemu_rc} -ne 124 ]]; then
        status="infra_fail"
        verdict_source="infra"
        if [[ ${qemu_exit_signal} -eq 15 ]]; then
            reason="external_sigterm"
        elif [[ ${qemu_exit_signal} -eq 9 ]]; then
            reason="external_sigkill"
        else
            reason="external_signal"
        fi
    fi

    if [[ "${status}" == "pass" ]]; then
        exit_code=0
    elif [[ "${status}" == "error" || "${status}" == "infra_fail" ]]; then
        exit_code=2
    else
        exit_code=1
    fi

    end_ms="$(date +%s%3N)"
    end_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    duration_ms="$((end_ms - start_ms))"
    write_result "${end_time_utc}" "${duration_ms}" "${status}" "${reason}" "${exit_code}" "${qemu_rc}" "${verdict_source}" "${has_boot_marker}" "${has_fatal_markers}" "${has_failure_markers}" "${structured_status}" "${structured_schema}" "${structured_failed}" "${structured_done}" "${structured_enabled_mask}" "${summary_status}" "${summary_failed}" "${has_required_markers}" "${has_forbidden_markers}" "${qemu_exit_signal}" "${qemu_term_signal}" "${qemu_term_sender_pid}"

    if [[ "${status}" == "pass" ]]; then
        echo "test: PASS (${reason}, qemu_rc=${qemu_rc})"
        return 0
    fi

    echo "test: ${status} (${reason}, qemu_rc=${qemu_rc})" >&2
    if [[ "${reason}" == "optional_markers_invalid" ]] &&
        [[ -n "${optional_marker_failed_rule}" ]]; then
        echo "test: optional marker rule failed: ${optional_marker_failed_rule}" >&2
    fi
    tail -n 120 "${TEST_LOG}" >&2 || true
    return "${exit_code}"
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

if ! [[ "${TEST_TIMEOUT}" =~ ^[0-9]+$ ]]; then
    echo "test: TEST_TIMEOUT must be a non-negative integer" >&2
    exit 2
fi

if ! [[ "${TEST_REQUIRE_STRUCTURED}" =~ ^[01]$ ]]; then
    echo "test: TEST_REQUIRE_STRUCTURED must be 0, 1 or auto" >&2
    exit 2
fi

mkdir -p \
    "$(dirname "${TEST_LOG}")" \
    "$(dirname "${TEST_MANIFEST}")" \
    "$(dirname "${TEST_RESULT}")" \
    "$(dirname "${TEST_QEMU_PID_FILE}")" \
    "$(dirname "${TEST_LOCK_FILE}")"

trap 'rm -f "${TEST_QEMU_PID_FILE}" || true' EXIT

set +e
KAIROS_LOCK_WAIT="${TEST_LOCK_WAIT}" kairos_lock_with_file "${TEST_LOCK_FILE}" run_test_main
rc=$?
set -e

if [[ "${rc}" -eq 0 ]]; then
    exit 0
fi

if kairos_lock_is_busy_rc "${rc}"; then
    start_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    write_manifest "${start_time_utc}"
    end_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    write_result \
        "${end_time_utc}" \
        0 \
        "error" \
        "lock_busy" \
        2 \
        2 \
        "infra" \
        0 \
        0 \
        0 \
        "missing" \
        -1 \
        -1 \
        0 \
        -1 \
        "missing" \
        -1 \
        1 \
        0 \
        -1 \
        -1 \
        -1
    echo "test: manifest -> ${TEST_MANIFEST}"
    echo "test: result -> ${TEST_RESULT}"
    echo "test: lock_busy lock=${TEST_LOCK_FILE}" >&2
    exit 2
fi

exit "${rc}"

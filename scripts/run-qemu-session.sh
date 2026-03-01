#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KAIROS_ROOT_DIR="${KAIROS_ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
# shellcheck source=scripts/lib/lock.sh
source "${SCRIPT_DIR}/lib/lock.sh"

QEMU_CMD="${QEMU_CMD:-}"
SESSION_KIND="${SESSION_KIND:-run}"
SESSION_TIMEOUT="${SESSION_TIMEOUT:-0}"
SESSION_LOG="${SESSION_LOG:-build/session.log}"
SESSION_BOOT_MARKER="${SESSION_BOOT_MARKER:-SMP: ([0-9]+ CPU active|[0-9]+ CPUs active|[0-9]+/[0-9]+ CPUs active)|init: started /init|BusyBox v}"
SESSION_REQUIRE_BOOT="${SESSION_REQUIRE_BOOT:-1}"
SESSION_EXPECT_TIMEOUT="${SESSION_EXPECT_TIMEOUT:-0}"
SESSION_FAIL_REGEX="${SESSION_FAIL_REGEX:-panic\\(|panic:|User exception|Kernel exception|Trap dump|Inst page fault|ASSERT failed}"
SESSION_FILTER_CMD="${SESSION_FILTER_CMD:-}"
SESSION_BUILD_ROOT="${SESSION_BUILD_ROOT:-$(dirname "$SESSION_LOG")}"
SESSION_ARCH="${SESSION_ARCH:-unknown}"
SESSION_RUN_ID="${SESSION_RUN_ID:-$(basename "$SESSION_BUILD_ROOT")}"
SESSION_MANIFEST="${SESSION_MANIFEST:-${SESSION_BUILD_ROOT}/manifest.json}"
SESSION_RESULT="${SESSION_RESULT:-${SESSION_BUILD_ROOT}/result.json}"
SESSION_QEMU_PID_FILE="${SESSION_QEMU_PID_FILE:-${SESSION_BUILD_ROOT}/qemu.pid}"
SESSION_BUILD_DIR="${SESSION_BUILD_DIR:-${SESSION_BUILD_ROOT}/${SESSION_ARCH}}"
SESSION_LOCK_FILE="${SESSION_LOCK_FILE:-${SESSION_BUILD_DIR}/.locks/qemu.lock}"
SESSION_LOCK_WAIT="${SESSION_LOCK_WAIT:-0}"
SESSION_UEFI_BOOT_MODE="${UEFI_BOOT_MODE:-}"
SESSION_QEMU_UEFI_BOOT_MODE="${QEMU_UEFI_BOOT_MODE:-}"
SESSION_TTY_STATE=""

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

prepare_interactive_tty() {
    if ! [[ -t 0 ]]; then
        return
    fi
    if ! command -v stty >/dev/null 2>&1; then
        return
    fi

    # Avoid being stopped by TTIN/TTOU/TSTP when this session runs in a
    # background process group under an interactive parent.
    SESSION_TTY_STATE="$(
        (trap '' TTIN TTOU TSTP; stty -g </dev/tty 2>/dev/null) || true
    )"
    if [[ -z "${SESSION_TTY_STATE}" ]]; then
        return
    fi

    # Guest binary output can contain XON/XOFF bytes and accidentally pause host tty output.
    (trap '' TTIN TTOU TSTP; stty -ixon -ixoff </dev/tty 2>/dev/null) || true
}

restore_interactive_tty() {
    if [[ -z "${SESSION_TTY_STATE}" ]]; then
        return
    fi
    if ! [[ -t 0 ]]; then
        return
    fi
    if ! command -v stty >/dev/null 2>&1; then
        return
    fi
    (trap '' TTIN TTOU TSTP; stty "${SESSION_TTY_STATE}" </dev/tty 2>/dev/null) || true
}

validate_boot_drive_cmd() {
    local cmd="$1"
    local boot_spec boot_path

    if [[ "${cmd}" =~ -drive[[:space:]]+id=boot,file=([^,[:space:]]+),format=raw,if=none ]]; then
        boot_spec="${BASH_REMATCH[1]}"
        if [[ "${boot_spec}" == fat:rw:* ]]; then
            boot_path="${boot_spec#fat:rw:}"
            if [[ ! -d "${boot_path}" ]]; then
                echo "run: bootfs missing (${boot_path})" >&2
                return 1
            fi
            return 0
        fi

        boot_path="${boot_spec}"
        if [[ ! -f "${boot_path}" ]]; then
            echo "run: boot image missing (${boot_path})" >&2
            return 1
        fi
        return 0
    fi

    return 0
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

write_manifest() {
    local start_time_utc="$1"
    local git_sha="unknown"
    if command -v git >/dev/null 2>&1; then
        git_sha="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    fi

    cat >"${SESSION_MANIFEST}" <<JSON
{
  "schema_version": 1,
  "kind": $(json_quote "${SESSION_KIND}"),
  "run_id": $(json_quote "${SESSION_RUN_ID}"),
  "arch": $(json_quote "${SESSION_ARCH}"),
  "build_root": $(json_quote "${SESSION_BUILD_ROOT}"),
  "command": "run-qemu-session.sh",
  "qemu_cmd": $(json_quote "${QEMU_CMD}"),
  "uefi_boot_mode": $(json_quote "${SESSION_UEFI_BOOT_MODE}"),
  "qemu_uefi_boot_mode": $(json_quote "${SESSION_QEMU_UEFI_BOOT_MODE}"),
  "git_sha": $(json_quote "${git_sha}"),
  "start_time_utc": $(json_quote "${start_time_utc}"),
  "host_pid": $$,
  "session_log": $(json_quote "${SESSION_LOG}")
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
    local has_fail_markers="$7"
    local has_boot_marker="$8"
    local qemu_exit_signal="$9"
    local qemu_term_signal="${10}"
    local qemu_term_sender_pid="${11}"

    cat >"${SESSION_RESULT}" <<JSON
{
  "schema_version": 1,
  "kind": $(json_quote "${SESSION_KIND}"),
  "run_id": $(json_quote "${SESSION_RUN_ID}"),
  "status": $(json_quote "${status}"),
  "reason": $(json_quote "${reason}"),
  "exit_code": ${exit_code},
  "qemu_exit_code": ${qemu_rc},
  "signals": {
    "qemu_exit_signal": $(json_int_or_null "${qemu_exit_signal}"),
    "qemu_term_signal": $(json_int_or_null "${qemu_term_signal}"),
    "qemu_term_sender_pid": $(json_int_or_null "${qemu_term_sender_pid}")
  },
  "log_path": $(json_quote "${SESSION_LOG}"),
  "end_time_utc": $(json_quote "${end_time_utc}"),
  "duration_ms": ${duration_ms},
  "markers": {
    "has_fail_markers": $(json_bool "${has_fail_markers}"),
    "has_boot_marker": $(json_bool "${has_boot_marker}")
  }
}
JSON
}

run_session_main() {
    local start_ms start_time_utc end_ms end_time_utc duration_ms
    local old_pid wrapped_qemu_cmd qemu_rc has_boot_marker has_fail_markers
    local qemu_exit_signal qemu_term_signal qemu_term_sender_pid
    local effective_qemu_signal
    local status reason exit_code
    local had_errexit_timeout

    rm -f "${SESSION_LOG}"
    start_ms="$(date +%s%3N)"
    start_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    if ! validate_boot_drive_cmd "${QEMU_CMD}"; then
        write_manifest "${start_time_utc}"
        end_ms="$(date +%s%3N)"
        end_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        duration_ms="$((end_ms - start_ms))"
        write_result "${end_time_utc}" "${duration_ms}" "error" "missing_boot_media" 2 2 0 0 -1 -1 -1
        echo "run: manifest -> ${SESSION_MANIFEST}"
        echo "run: result -> ${SESSION_RESULT}"
        return 2
    fi

    write_manifest "${start_time_utc}"

    if [[ -f "${SESSION_QEMU_PID_FILE}" ]]; then
        old_pid="$(cat "${SESSION_QEMU_PID_FILE}" 2>/dev/null || true)"
        if [[ "${old_pid}" =~ ^[0-9]+$ ]] && kill -0 "${old_pid}" >/dev/null 2>&1; then
            end_ms="$(date +%s%3N)"
            end_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
            duration_ms="$((end_ms - start_ms))"
            write_result "${end_time_utc}" "${duration_ms}" "error" "existing_qemu_pid" 2 2 0 0 -1 -1 -1
            echo "run: existing qemu pid is still running (${old_pid})" >&2
            return 2
        fi
        rm -f "${SESSION_QEMU_PID_FILE}"
    fi

    echo "run: kind=${SESSION_KIND} timeout=${SESSION_TIMEOUT}s"
    echo "run: log -> ${SESSION_LOG}"
    echo "run: manifest -> ${SESSION_MANIFEST}"
    echo "run: result -> ${SESSION_RESULT}"

    wrapped_qemu_cmd=""
    printf -v wrapped_qemu_cmd 'echo "$$" > %q; exec %s' "${SESSION_QEMU_PID_FILE}" "${QEMU_CMD}"

    prepare_interactive_tty
    had_errexit_timeout=0
    if [[ $- == *e* ]]; then
        had_errexit_timeout=1
        set +e
    fi
    if [[ "${SESSION_TIMEOUT}" -gt 0 ]]; then
        if [[ -n "${SESSION_FILTER_CMD}" ]]; then
            timeout --signal=TERM --kill-after=5s "${SESSION_TIMEOUT}s" \
                bash -lc "${wrapped_qemu_cmd}" 2>&1 | bash -lc "${SESSION_FILTER_CMD}" | tee -a "${SESSION_LOG}"
            qemu_rc=${PIPESTATUS[0]}
        else
            timeout --signal=TERM --kill-after=5s "${SESSION_TIMEOUT}s" \
                bash -lc "${wrapped_qemu_cmd}" 2>&1 | tee -a "${SESSION_LOG}"
            qemu_rc=${PIPESTATUS[0]}
        fi
    else
        if [[ -n "${SESSION_FILTER_CMD}" ]]; then
            bash -lc "${wrapped_qemu_cmd}" 2>&1 | bash -lc "${SESSION_FILTER_CMD}" | tee -a "${SESSION_LOG}"
            qemu_rc=${PIPESTATUS[0]}
        else
            bash -lc "${wrapped_qemu_cmd}" 2>&1 | tee -a "${SESSION_LOG}"
            qemu_rc=${PIPESTATUS[0]}
        fi
    fi
    if [[ "${had_errexit_timeout}" -eq 1 ]]; then
        set -e
    fi

    has_boot_marker=0
    has_fail_markers=0

    if grep -Eiq "${SESSION_BOOT_MARKER}" "${SESSION_LOG}"; then
        has_boot_marker=1
    fi
    if grep -Eiq "${SESSION_FAIL_REGEX}" "${SESSION_LOG}"; then
        has_fail_markers=1
    fi

    qemu_exit_signal=-1
    if [[ ${qemu_rc} -gt 128 && ${qemu_rc} -le 255 ]]; then
        qemu_exit_signal="$((qemu_rc - 128))"
    fi
    read -r qemu_term_signal qemu_term_sender_pid < <(extract_qemu_signal_meta "${SESSION_LOG}")
    effective_qemu_signal="${qemu_exit_signal}"
    if [[ ${effective_qemu_signal} -le 0 ]] &&
        [[ ${qemu_term_signal} -gt 0 ]] &&
        [[ ${qemu_rc} -ne 124 ]]; then
        effective_qemu_signal="${qemu_term_signal}"
    fi

    status="fail"
    reason="unexpected_exit"
    exit_code=1

    if [[ "${SESSION_EXPECT_TIMEOUT}" -eq 1 ]]; then
        if [[ ${has_fail_markers} -eq 1 ]]; then
            status="fail"
            reason="failure_markers_detected"
        elif [[ ${qemu_rc} -eq 124 ]]; then
            status="pass"
            reason="expected_timeout"
            exit_code=0
        elif [[ ${qemu_rc} -eq 0 ]]; then
            if [[ "${SESSION_REQUIRE_BOOT}" -eq 1 && ${has_boot_marker} -eq 0 ]]; then
                status="fail"
                reason="missing_boot_marker"
            else
                status="pass"
                reason="completed_before_timeout"
                exit_code=0
            fi
        fi
    else
        if [[ ${has_fail_markers} -eq 1 ]]; then
            status="fail"
            reason="failure_markers_detected"
        elif [[ ${qemu_rc} -eq 124 ]]; then
            status="timeout"
            reason="timeout"
        elif [[ ${qemu_rc} -eq 0 ]]; then
            if [[ "${SESSION_REQUIRE_BOOT}" -eq 1 && ${has_boot_marker} -eq 0 ]]; then
                status="fail"
                reason="missing_boot_marker"
            else
                status="pass"
                reason="qemu_exit_zero"
                exit_code=0
            fi
        fi
    fi

    if [[ ${has_fail_markers} -eq 0 ]] && [[ "${status}" != "pass" ]] && [[ ${effective_qemu_signal} -gt 0 ]] && [[ ${qemu_rc} -ne 124 ]]; then
        status="error"
        exit_code=2
        if [[ ${effective_qemu_signal} -eq 15 ]]; then
            reason="external_sigterm"
        elif [[ ${effective_qemu_signal} -eq 9 ]]; then
            reason="external_sigkill"
        else
            reason="external_signal"
        fi
    fi

    end_ms="$(date +%s%3N)"
    end_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    duration_ms="$((end_ms - start_ms))"
    write_result "${end_time_utc}" "${duration_ms}" "${status}" "${reason}" "${exit_code}" "${qemu_rc}" "${has_fail_markers}" "${has_boot_marker}" "${qemu_exit_signal}" "${qemu_term_signal}" "${qemu_term_sender_pid}"

    if [[ "${status}" == "pass" ]]; then
        echo "run: PASS (${reason}, qemu_rc=${qemu_rc})"
        return 0
    fi

    echo "run: ${status} (${reason}, qemu_rc=${qemu_rc})" >&2
    tail -n 120 "${SESSION_LOG}" >&2 || true
    return "${exit_code}"
}

if [[ -z "${QEMU_CMD}" ]]; then
    echo "run: QEMU_CMD is empty" >&2
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "run: python3 is required for manifest/result JSON output" >&2
    exit 2
fi

if ! [[ "${SESSION_TIMEOUT}" =~ ^[0-9]+$ ]]; then
    echo "run: SESSION_TIMEOUT must be a non-negative integer" >&2
    exit 2
fi

mkdir -p \
    "$(dirname "${SESSION_LOG}")" \
    "$(dirname "${SESSION_MANIFEST}")" \
    "$(dirname "${SESSION_RESULT}")" \
    "$(dirname "${SESSION_QEMU_PID_FILE}")" \
    "$(dirname "${SESSION_LOCK_FILE}")"

trap 'rm -f "${SESSION_QEMU_PID_FILE}" || true; restore_interactive_tty' EXIT

set +e
KAIROS_LOCK_WAIT="${SESSION_LOCK_WAIT}" kairos_lock_with_file "${SESSION_LOCK_FILE}" run_session_main
rc=$?
set -e

if [[ "${rc}" -eq 0 ]]; then
    exit 0
fi

if kairos_lock_is_busy_rc "${rc}"; then
    start_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    write_manifest "${start_time_utc}"
    end_time_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    write_result "${end_time_utc}" 0 "error" "lock_busy" 2 2 0 0 -1 -1 -1
    echo "run: manifest -> ${SESSION_MANIFEST}"
    echo "run: result -> ${SESSION_RESULT}"
    echo "run: lock_busy (lock: ${SESSION_LOCK_FILE})" >&2
    exit 2
fi

exit "${rc}"

#!/usr/bin/env bash
#
# cmd.sh - Shared command execution helpers for Kairos orchestration.
#

kairos_run() {
    if [[ "${KAIROS_VERBOSE:-0}" == "1" ]]; then
        printf '+'
        printf ' %q' "$@"
        printf '\n'
    fi
    "$@"
}

kairos_run_tagged() {
    local tag="$1"
    shift

    local log_dir="${KAIROS_ROOT_DIR}/build/${KAIROS_ARCH}/logs"
    local log_file="${log_dir}/${tag}.log"
    mkdir -p "$log_dir"
    : >"$log_file"

    set +e
    kairos_run "$@" 2>&1 | tee -a "$log_file"
    local rc=${PIPESTATUS[0]}
    set -e

    if ((rc != 0)); then
        kairos_log_error "${tag} failed (rc=${rc})"
        kairos_log_error "log: ${log_file}"
        if [[ "${KAIROS_QUIET:-0}" == "1" ]]; then
            echo "--- ${tag} log (tail) ---" >&2
            tail -n 120 "$log_file" >&2 || true
            echo "-------------------------" >&2
        fi
    fi
    return "$rc"
}

kairos_exec_script() {
    local tag="$1"
    local script="$2"
    shift 2
    kairos_run_tagged "$tag" env \
        ARCH="${KAIROS_ARCH}" \
        QUIET="${KAIROS_QUIET}" \
        JOBS="${KAIROS_JOBS}" \
        "$script" "$@"
}

kairos_exec_script_env() {
    local tag="$1"
    shift
    kairos_run_tagged "$tag" env "$@"
}

#!/usr/bin/env bash
#
# lock.sh - Shared lock helpers for Kairos orchestration.
#

KAIROS_LOCK_BUSY_RC="${KAIROS_LOCK_BUSY_RC:-75}"

kairos_lock_busy_rc() {
    echo "${KAIROS_LOCK_BUSY_RC:-75}"
}

kairos_lock_is_busy_rc() {
    local rc="${1:-0}"
    [[ "$rc" -eq "$(kairos_lock_busy_rc)" ]]
}

kairos_lock_repo_root() {
    if [[ -n "${KAIROS_ROOT_DIR:-}" ]]; then
        echo "${KAIROS_ROOT_DIR}"
        return 0
    fi
    local this_dir
    this_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    (cd "${this_dir}/../.." && pwd)
}

kairos_lock_meta_file() {
    local lock_file="$1"
    echo "${lock_file}.meta"
}

kairos_lock_write_meta() {
    local lock_file="$1"
    shift

    local meta_file tmp_file start_utc start_epoch cmd_quoted
    meta_file="$(kairos_lock_meta_file "${lock_file}")"
    tmp_file="${meta_file}.tmp.$$"
    start_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    start_epoch="$(date +%s)"
    cmd_quoted=""
    if [[ $# -gt 0 ]]; then
        printf -v cmd_quoted '%q ' "$@"
        cmd_quoted="${cmd_quoted% }"
    fi

    {
        echo "pid=$$"
        echo "start_utc=${start_utc}"
        echo "start_epoch=${start_epoch}"
        echo "cwd=$(pwd)"
        echo "cmd=${cmd_quoted}"
    } > "${tmp_file}"
    mv -f "${tmp_file}" "${meta_file}"
}

kairos_lock_clear_meta() {
    local lock_file="$1"
    rm -f "$(kairos_lock_meta_file "${lock_file}")"
}

kairos_lock_read_meta_pid() {
    local lock_file="$1"
    local meta_file
    meta_file="$(kairos_lock_meta_file "${lock_file}")"
    [[ -f "${meta_file}" ]] || return 1
    awk -F= '$1 == "pid" { print $2; found=1; exit } END { if (!found) exit 1 }' "${meta_file}"
}

kairos_lock_reclaim_stale() {
    local lock_file="$1"
    local stale_pid lock_fd
    stale_pid="$(kairos_lock_read_meta_pid "${lock_file}" 2>/dev/null || true)"
    if [[ -n "${stale_pid}" && "${stale_pid}" =~ ^[0-9]+$ ]]; then
        if kill -0 "${stale_pid}" >/dev/null 2>&1; then
            return 1
        fi
    fi

    exec {lock_fd}> "${lock_file}"
    if ! flock -n "${lock_fd}"; then
        exec {lock_fd}>&-
        return 1
    fi
    : > "${lock_file}" || true
    kairos_lock_clear_meta "${lock_file}" || true
    flock -u "${lock_fd}" || true
    exec {lock_fd}>&-
    return 0
}

kairos_lock_with_file() {
    local lock_file="$1"
    shift

    local lock_wait="${KAIROS_LOCK_WAIT:-0}"
    local lock_fd rc had_errexit stale_retry

    if ! [[ "${lock_wait}" =~ ^[0-9]+$ ]]; then
        return 2
    fi
    mkdir -p "$(dirname "${lock_file}")"

    stale_retry=1
    while true; do
        exec {lock_fd}> "${lock_file}"
        if flock -w "${lock_wait}" "${lock_fd}"; then
            kairos_lock_write_meta "${lock_file}" "$@" || true
            had_errexit=0
            if [[ $- == *e* ]]; then
                had_errexit=1
                set +e
            fi
            "$@"
            rc=$?
            if [[ "${had_errexit}" -eq 1 ]]; then
                set -e
            fi
            kairos_lock_clear_meta "${lock_file}" || true
            flock -u "${lock_fd}" || true
            exec {lock_fd}>&-
            return "${rc}"
        fi
        exec {lock_fd}>&-

        if [[ "${stale_retry}" -eq 1 ]] && kairos_lock_reclaim_stale "${lock_file}"; then
            stale_retry=0
            continue
        fi
        return "$(kairos_lock_busy_rc)"
    done
}

kairos_lock_global() {
    local name="$1"
    shift
    local repo_root lock_root
    repo_root="$(kairos_lock_repo_root)"
    lock_root="${KAIROS_GLOBAL_LOCK_ROOT:-${repo_root}/build/.locks}"
    kairos_lock_with_file "${lock_root}/global-${name}.lock" "$@"
}

kairos_lock_buildroot() {
    local build_root="$1"
    local name="$2"
    shift 2
    kairos_lock_with_file "${build_root}/.locks/${name}.lock" "$@"
}

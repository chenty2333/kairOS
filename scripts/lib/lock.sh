#!/usr/bin/env bash
#
# lock.sh - Shared lock helpers for Kairos orchestration.
#

kairos_lock_with_file() {
    local lock_file="$1"
    shift

    local lock_wait="${KAIROS_LOCK_WAIT:-0}"
    mkdir -p "$(dirname "$lock_file")"
    exec {lock_fd}> "$lock_file"
    if ! flock -w "$lock_wait" "$lock_fd"; then
        exec {lock_fd}>&-
        return 75
    fi

    "$@"
    local rc=$?
    flock -u "$lock_fd" || true
    exec {lock_fd}>&-
    return "$rc"
}

kairos_lock_global() {
    local name="$1"
    shift
    local lock_root="${KAIROS_ROOT_DIR}/.locks"
    kairos_lock_with_file "${lock_root}/global-${name}.lock" "$@"
}

kairos_lock_buildroot() {
    local build_root="$1"
    local name="$2"
    shift 2
    kairos_lock_with_file "${build_root}/.locks/${name}.lock" "$@"
}

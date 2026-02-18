#!/usr/bin/env bash
#
# log.sh - Shared logging helpers for Kairos scripts.
#

kairos_log_info() {
    if [[ "${KAIROS_QUIET:-0}" != "1" ]]; then
        echo "$*"
    fi
}

kairos_log_warn() {
    echo "WARN: $*" >&2
}

kairos_log_error() {
    echo "Error: $*" >&2
}

kairos_die() {
    kairos_log_error "$*"
    exit 2
}

#!/usr/bin/env bash
#
# deps.sh - Third-party dependency orchestration.
#

kairos_deps_usage() {
    cat <<'EOF'
Usage: scripts/kairos.sh [global options] deps <action> [component]

Actions:
  fetch [component]  Run fetch-deps.sh (default: all)
  freedoom           Download freedoom assets
  all                Fetch all deps + freedoom
EOF
}

kairos_deps_dispatch() {
    local action="${1:-}"
    shift || true

    if [[ -z "$action" ]]; then
        kairos_deps_usage
        return 2
    fi

    case "$action" in
        fetch)
            local component="${1:-all}"
            kairos_lock_global "deps-fetch" \
                kairos_exec_script "deps" "${KAIROS_ROOT_DIR}/scripts/impl/fetch-deps.sh" "${component}" || \
                kairos_die "deps fetch is busy (global lock: deps-fetch)"
            ;;
        freedoom)
            kairos_lock_global "deps-fetch" \
                kairos_exec_script "deps" "${KAIROS_ROOT_DIR}/scripts/impl/fetch-freedoom.sh" || \
                kairos_die "deps fetch is busy (global lock: deps-fetch)"
            ;;
        all)
            kairos_lock_global "deps-fetch" \
                kairos_exec_script "deps" "${KAIROS_ROOT_DIR}/scripts/impl/fetch-deps.sh" "all" || \
                kairos_die "deps fetch is busy (global lock: deps-fetch)"
            kairos_lock_global "deps-fetch" \
                kairos_exec_script "deps" "${KAIROS_ROOT_DIR}/scripts/impl/fetch-freedoom.sh" || \
                kairos_die "deps fetch is busy (global lock: deps-fetch)"
            ;;
        *)
            kairos_die "unknown deps action: ${action}"
            ;;
    esac
}

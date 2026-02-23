#!/usr/bin/env bash
#
# toolchain.sh - Toolchain and userland build orchestration.
#

kairos_toolchain_usage() {
    cat <<'EOF'
Usage: scripts/kairos.sh [global options] toolchain <action>

Actions:
  compiler-rt   Build compiler-rt builtins
  musl          Build musl sysroot
  busybox       Build busybox
  tcc           Build tinycc
  musl-cross    Build musl-cross toolchain (optional)
  all           Build compiler-rt + musl + busybox + tcc
EOF
}

kairos_toolchain_with_global_lock() {
    local action="$1"
    shift

    local wait_s="${TOOLCHAIN_LOCK_WAIT:-900}"
    local lock_name="toolchain-${KAIROS_ARCH}"
    local rc=0

    if ! [[ "${wait_s}" =~ ^[0-9]+$ ]]; then
        kairos_die "invalid TOOLCHAIN_LOCK_WAIT=${wait_s} (expected non-negative integer)"
    fi

    set +e
    KAIROS_LOCK_WAIT="${wait_s}" kairos_lock_global "${lock_name}" "$@"
    rc=$?
    set -e
    if ((rc != 0)); then
        if kairos_lock_is_busy_rc "${rc}"; then
            kairos_die "toolchain ${action} is busy for ARCH=${KAIROS_ARCH} (global lock: ${lock_name}, wait=${wait_s}s)"
        fi
        return "${rc}"
    fi
    return 0
}

kairos_toolchain_dispatch() {
    local action="${1:-}"
    if [[ -z "$action" ]]; then
        kairos_toolchain_usage
        return 2
    fi

    case "$action" in
        compiler-rt)
            kairos_toolchain_with_global_lock "compiler-rt" \
                kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-compiler-rt.sh" "${KAIROS_ARCH}"
            ;;
        musl)
            kairos_toolchain_with_global_lock "musl" \
                kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-musl.sh" "${KAIROS_ARCH}"
            ;;
        busybox)
            kairos_toolchain_with_global_lock "busybox" \
                kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-busybox.sh" "${KAIROS_ARCH}"
            ;;
        tcc)
            kairos_toolchain_with_global_lock "tcc" \
                kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-tcc.sh" "${KAIROS_ARCH}"
            ;;
        musl-cross)
            kairos_toolchain_with_global_lock "musl-cross" \
                kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-musl-cross.sh" "${KAIROS_ARCH}"
            ;;
        all)
            case "${TOOLCHAIN_MODE:-auto}" in
                clang)
                    kairos_toolchain_dispatch compiler-rt
                    ;;
                auto|gcc)
                    ;;
                *)
                    kairos_die "invalid TOOLCHAIN_MODE=${TOOLCHAIN_MODE:-auto} (expected auto|clang|gcc)"
                    ;;
            esac
            kairos_toolchain_dispatch musl
            kairos_toolchain_dispatch busybox
            kairos_toolchain_dispatch tcc
            ;;
        *)
            kairos_die "unknown toolchain action: ${action}"
            ;;
    esac
}

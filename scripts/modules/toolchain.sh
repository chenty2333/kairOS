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

kairos_toolchain_dispatch() {
    local action="${1:-}"
    if [[ -z "$action" ]]; then
        kairos_toolchain_usage
        return 2
    fi

    case "$action" in
        compiler-rt)
            kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-compiler-rt.sh" "${KAIROS_ARCH}"
            ;;
        musl)
            kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-musl.sh" "${KAIROS_ARCH}"
            ;;
        busybox)
            kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-busybox.sh" "${KAIROS_ARCH}"
            ;;
        tcc)
            kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-tcc.sh" "${KAIROS_ARCH}"
            ;;
        musl-cross)
            kairos_exec_script "toolchain" "${KAIROS_ROOT_DIR}/scripts/impl/build-musl-cross.sh" "${KAIROS_ARCH}"
            ;;
        all)
            if [[ "${USE_GCC:-0}" != "1" ]]; then
                kairos_toolchain_dispatch compiler-rt
            fi
            kairos_toolchain_dispatch musl
            kairos_toolchain_dispatch busybox
            kairos_toolchain_dispatch tcc
            ;;
        *)
            kairos_die "unknown toolchain action: ${action}"
            ;;
    esac
}

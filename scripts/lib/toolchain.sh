#!/usr/bin/env bash
#
# toolchain.sh - Shared toolchain probing and selection helpers.
#

kairos_tc_mode() {
    if [[ -n "${TOOLCHAIN_MODE:-}" ]]; then
        echo "${TOOLCHAIN_MODE}"
        return 0
    fi
    if [[ "${USE_GCC:-0}" == "1" ]]; then
        echo "gcc"
    else
        echo "auto"
    fi
}

kairos_tc_find_gcc_prefix() {
    local target="$1"
    local gnu_target="${target/-musl/-gnu}"
    local prefix
    for prefix in "${target}-" "${gnu_target}-"; do
        if command -v "${prefix}gcc" >/dev/null 2>&1 &&
           command -v "${prefix}ar" >/dev/null 2>&1 &&
           command -v "${prefix}ranlib" >/dev/null 2>&1 &&
           command -v "${prefix}strip" >/dev/null 2>&1; then
            echo "${prefix}"
            return 0
        fi
    done
    return 1
}

kairos_tc_have_clang_suite() {
    command -v clang >/dev/null 2>&1 &&
    command -v llvm-ar >/dev/null 2>&1 &&
    command -v llvm-ranlib >/dev/null 2>&1 &&
    command -v llvm-strip >/dev/null 2>&1
}

kairos_tc_probe_clang_static() {
    local target="$1"
    local sysroot="$2"
    local arch_cflags="$3"

    local src out err
    KAIROS_TC_PROBE_ERROR=""
    src="$(mktemp /tmp/kairos-tc-probe-XXXXXX.c)"
    out="${src%.c}.bin"
    err="${src%.c}.err"
    cat > "$src" <<'EOF'
int main(void) { return 0; }
EOF

    local cmd=(clang "--target=${target}" -fuse-ld=lld)
    if [[ -n "$sysroot" ]]; then
        cmd+=("--sysroot=${sysroot}" "-isystem" "${sysroot}/include" "-L${sysroot}/lib")
    fi
    if [[ -n "$arch_cflags" ]]; then
        # shellcheck disable=SC2206
        local extra=($arch_cflags)
        cmd+=("${extra[@]}")
    fi
    cmd+=(-static "$src" -o "$out")

    if "${cmd[@]}" >/dev/null 2>"$err"; then
        rm -f "$src" "$out" "$err"
        return 0
    fi
    if [[ -s "$err" ]]; then
        KAIROS_TC_PROBE_ERROR="$(tail -n 1 "$err" | tr -d '\r')"
    fi
    rm -f "$src" "$out" "$err"
    return 1
}

kairos_tc_prepare_libgcc_compat() {
    local arch="$1"
    local sysroot="$2"
    local lib_dir="${sysroot}/lib"

    [[ -d "$lib_dir" ]] || return 0
    if [[ -f "${lib_dir}/libgcc.a" && -f "${lib_dir}/libgcc_eh.a" ]]; then
        return 0
    fi

    local rt_resource_dir="${COMPILER_RT_RESOURCE_DIR:-${KAIROS_ROOT_DIR}/build/${arch}/compiler-rt/resource}"
    local builtins=""
    if [[ -d "$rt_resource_dir" ]]; then
        builtins="$(find "$rt_resource_dir" -name 'libclang_rt.builtins*.a' | head -n1 || true)"
    fi

    [[ -n "$builtins" ]] || return 0
    ln -sf "$builtins" "${lib_dir}/libgcc.a"

    if [[ ! -f "${lib_dir}/libgcc_eh.a" ]]; then
        if command -v llvm-ar >/dev/null 2>&1; then
            llvm-ar cr "${lib_dir}/libgcc_eh.a" >/dev/null 2>&1 || true
        elif command -v ar >/dev/null 2>&1; then
            ar cr "${lib_dir}/libgcc_eh.a" >/dev/null 2>&1 || true
        fi
        if [[ ! -f "${lib_dir}/libgcc_eh.a" ]]; then
            printf '!<arch>\n' > "${lib_dir}/libgcc_eh.a"
        fi
    fi
}

kairos_tc_select() {
    local target="$1"
    local sysroot="$2"
    local arch_cflags="${3:-}"
    local require_static="${4:-0}"

    KAIROS_TC_KIND=""
    KAIROS_TC_CC=""
    KAIROS_TC_AR=""
    KAIROS_TC_RANLIB=""
    KAIROS_TC_STRIP=""
    KAIROS_TC_CFLAGS=""
    KAIROS_TC_LDFLAGS=""
    KAIROS_TC_CROSS_PREFIX=""
    KAIROS_TC_NOTE=""

    local mode
    mode="$(kairos_tc_mode)"
    case "$mode" in
        auto|clang|gcc) ;;
        *) kairos_die "invalid TOOLCHAIN_MODE=${mode} (expected auto|clang|gcc)" ;;
    esac

    local gcc_prefix=""
    if [[ "$mode" == "gcc" || "$mode" == "auto" ]]; then
        gcc_prefix="$(kairos_tc_find_gcc_prefix "$target" || true)"
    fi

    if [[ "$mode" == "clang" || "$mode" == "auto" ]]; then
        if kairos_tc_have_clang_suite; then
            if [[ "$require_static" != "1" ]] ||
               kairos_tc_probe_clang_static "$target" "$sysroot" "$arch_cflags"; then
                KAIROS_TC_KIND="clang"
                KAIROS_TC_CC="clang --target=${target}"
                KAIROS_TC_AR="llvm-ar"
                KAIROS_TC_RANLIB="llvm-ranlib"
                KAIROS_TC_STRIP="llvm-strip"
                if [[ -n "$sysroot" ]]; then
                    KAIROS_TC_CC="${KAIROS_TC_CC} --sysroot=${sysroot}"
                    KAIROS_TC_CFLAGS="--target=${target} --sysroot=${sysroot} -isystem ${sysroot}/include ${arch_cflags}"
                    KAIROS_TC_LDFLAGS="--target=${target} --sysroot=${sysroot} -fuse-ld=lld -L${sysroot}/lib ${arch_cflags}"
                else
                    KAIROS_TC_CFLAGS="--target=${target} ${arch_cflags}"
                    KAIROS_TC_LDFLAGS="--target=${target} -fuse-ld=lld ${arch_cflags}"
                fi
                return 0
            fi
            if [[ -n "${KAIROS_TC_PROBE_ERROR:-}" ]]; then
                KAIROS_TC_NOTE="clang static link probe failed: ${KAIROS_TC_PROBE_ERROR}"
            else
                KAIROS_TC_NOTE="clang static link probe failed"
            fi
        else
            KAIROS_TC_NOTE="clang/llvm tool suite not found"
        fi
        if [[ "$mode" == "clang" ]]; then
            kairos_die "TOOLCHAIN_MODE=clang requested, but clang target toolchain is not usable (${KAIROS_TC_NOTE})"
        fi
    fi

    if [[ -n "$gcc_prefix" ]]; then
        KAIROS_TC_KIND="gcc"
        KAIROS_TC_CC="${gcc_prefix}gcc"
        KAIROS_TC_AR="${gcc_prefix}ar"
        KAIROS_TC_RANLIB="${gcc_prefix}ranlib"
        KAIROS_TC_STRIP="${gcc_prefix}strip"
        KAIROS_TC_CROSS_PREFIX="${gcc_prefix}"
        if [[ -n "$sysroot" ]]; then
            KAIROS_TC_CFLAGS="--sysroot=${sysroot} -isystem ${sysroot}/include ${arch_cflags}"
            KAIROS_TC_LDFLAGS="--sysroot=${sysroot} -L${sysroot}/lib ${arch_cflags}"
        else
            KAIROS_TC_CFLAGS="${arch_cflags}"
            KAIROS_TC_LDFLAGS="${arch_cflags}"
        fi
        if [[ "$mode" == "auto" && -n "$KAIROS_TC_NOTE" ]]; then
            KAIROS_TC_NOTE="${KAIROS_TC_NOTE}; falling back to ${gcc_prefix}gcc"
        fi
        return 0
    fi

    kairos_die "no usable toolchain found for ${target} (mode=${mode})"
}

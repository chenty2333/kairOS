#!/usr/bin/env bash
#
# run.sh - Run/test/doctor orchestration.
#

kairos_run_usage() {
    cat <<'EOF'
Usage: scripts/kairos.sh [global options] run <action> [options]

Actions:
  test        Run kernel tests (marker-based)
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-soak   Run soak test (expects timeout)
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-debug  Run tests with CONFIG_DEBUG
              Options: --extra-cflags <flags> --timeout <sec> --log <path>
  test-matrix Run SMP x DEBUG test matrix
EOF
}

kairos_doctor_usage() {
    cat <<'EOF'
Usage: scripts/kairos.sh [global options] doctor
EOF
}

kairos_doctor() {
    local qemu
    qemu="$(kairos_arch_to_qemu "${KAIROS_ARCH}")" || kairos_die "unsupported architecture: ${KAIROS_ARCH}"

    local code_src vars_src
    code_src="${UEFI_CODE_SRC:-$(kairos_default_uefi_code_src "${KAIROS_ARCH}")}"
    vars_src="${UEFI_VARS_SRC:-$(kairos_default_uefi_vars_src "${KAIROS_ARCH}")}"

    local failed=0
    for cmd in "$qemu" mke2fs python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            kairos_log_error "missing host tool: $cmd"
            failed=1
        fi
    done
    if ! command -v mkfs.fat >/dev/null 2>&1 && ! command -v mkfs.vfat >/dev/null 2>&1; then
        kairos_log_error "missing host tool: mkfs.fat (dosfstools)"
        failed=1
    fi
    if [[ ! -f "$code_src" || ! -f "$vars_src" ]]; then
        kairos_log_error "UEFI firmware not found for ${KAIROS_ARCH}:"
        kairos_log_error "  ${code_src}"
        kairos_log_error "  ${vars_src}"
        failed=1
    fi
    if ((failed)); then
        return 3
    fi

    kairos_log_info "doctor: OK (${KAIROS_ARCH})"
}

kairos_run_clean_kernel_artifacts() {
    local build_dir="${KAIROS_ROOT_DIR}/build/${KAIROS_ARCH}"
    rm -rf "${build_dir}/kernel" "${build_dir}/third_party" \
        "${build_dir}/kairos.elf" "${build_dir}/kairos.bin" \
        "${build_dir}/.cflags."*
}

kairos_run_test_once() {
    local extra_cflags="$1"
    local timeout_s="$2"
    local log_path="$3"
    local require_markers="$4"
    local expect_timeout="$5"

    local qemu_cmd
    printf -v qemu_cmd 'make --no-print-directory ARCH=%q EXTRA_CFLAGS=%q run' \
        "${KAIROS_ARCH}" "${extra_cflags}"
    kairos_run_clean_kernel_artifacts

    local rc=0
    set +e
    (
        cd "${KAIROS_ROOT_DIR}"
        kairos_exec_script_env "test" \
            QEMU_CMD="${qemu_cmd}" \
            TEST_TIMEOUT="${timeout_s}" \
            TEST_LOG="${log_path}" \
            TEST_REQUIRE_MARKERS="${require_markers}" \
            TEST_EXPECT_TIMEOUT="${expect_timeout}" \
            "${KAIROS_ROOT_DIR}/scripts/run-qemu-test.sh"
    )
    rc=$?
    set -e

    kairos_run_clean_kernel_artifacts
    return "$rc"
}

kairos_run_parse_common_opts() {
    local -n _extra_ref="$1"
    local -n _timeout_ref="$2"
    local -n _log_ref="$3"
    shift 3

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --extra-cflags)
                [[ $# -ge 2 ]] || kairos_die "--extra-cflags requires a value"
                _extra_ref="$2"
                shift 2
                ;;
            --timeout)
                [[ $# -ge 2 ]] || kairos_die "--timeout requires a value"
                _timeout_ref="$2"
                shift 2
                ;;
            --log)
                [[ $# -ge 2 ]] || kairos_die "--log requires a value"
                _log_ref="$2"
                shift 2
                ;;
            *)
                kairos_die "unknown run option: $1"
                ;;
        esac
    done
}

kairos_run_dispatch() {
    local action="${1:-}"
    shift || true

    if [[ -z "$action" ]]; then
        kairos_run_usage
        return 2
    fi

    local default_extra="${TEST_EXTRA_CFLAGS:--DCONFIG_KERNEL_TESTS=1}"
    local extra timeout_s log_path

    case "$action" in
        test)
            extra="$default_extra"
            timeout_s="${TEST_TIMEOUT:-180}"
            log_path="${TEST_LOG:-${KAIROS_ROOT_DIR}/build/${KAIROS_ARCH}/test.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_once "$extra" "$timeout_s" "$log_path" 1 0
            ;;
        test-soak)
            extra="$default_extra"
            timeout_s="${SOAK_TIMEOUT:-600}"
            log_path="${SOAK_LOG:-${KAIROS_ROOT_DIR}/build/${KAIROS_ARCH}/soak.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_once "$extra" "$timeout_s" "$log_path" 0 1
            ;;
        test-debug)
            extra="${default_extra} -DCONFIG_DEBUG=1"
            timeout_s="${TEST_TIMEOUT:-180}"
            log_path="${TEST_LOG:-${KAIROS_ROOT_DIR}/build/${KAIROS_ARCH}/test.log}"
            kairos_run_parse_common_opts extra timeout_s log_path "$@"
            kairos_run_test_once "$extra" "$timeout_s" "$log_path" 1 0
            ;;
        test-matrix)
            (
                cd "${KAIROS_ROOT_DIR}"
                kairos_exec_script_env "test-matrix" \
                    ARCH="${KAIROS_ARCH}" \
                    CPUS="${CPUS:-1 2 4}" \
                    DEBUG_LEVELS="${DEBUG_LEVELS:-0 1}" \
                    bash "${KAIROS_ROOT_DIR}/scripts/test-matrix.sh"
            )
            ;;
        *)
            kairos_die "unknown run action: ${action}"
            ;;
    esac
}

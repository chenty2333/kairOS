#!/usr/bin/env bash
# Shared bootstrap helpers for GitHub Actions CI jobs.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

usage() {
    cat <<'USAGE'
Usage:
  scripts/impl/ci-bootstrap.sh install-host-deps <arch>
  scripts/impl/ci-bootstrap.sh fetch-required-third-party
  scripts/impl/ci-bootstrap.sh locate-uefi <arch>

Supported arch values: riscv64, x86_64, aarch64
USAGE
}

require_arch() {
    local arch="${1:-}"
    case "${arch}" in
        riscv64|x86_64|aarch64)
            ;;
        *)
            echo "ci-bootstrap: unsupported arch '${arch}'" >&2
            usage >&2
            exit 2
            ;;
    esac
}

append_optional_pkg() {
    local -n out_ref="$1"
    local pkg="$2"
    if apt-cache show "${pkg}" >/dev/null 2>&1; then
        out_ref+=("${pkg}")
    fi
}

install_host_deps() {
    local arch="$1"
    require_arch "${arch}"

    sudo apt-get update

    local pkgs=(
        clang
        lld
        llvm
        make
        python3
        git
        cmake
        ninja-build
        rsync
        curl
        unzip
        ca-certificates
        e2fsprogs
        dosfstools
        mtools
        qemu-utils
        ovmf
    )

    case "${arch}" in
        riscv64)
            pkgs+=(qemu-system-misc)
            append_optional_pkg pkgs qemu-efi-riscv64
            append_optional_pkg pkgs edk2-ovmf
            ;;
        x86_64)
            pkgs+=(qemu-system-x86)
            append_optional_pkg pkgs edk2-ovmf
            ;;
        aarch64)
            pkgs+=(qemu-system-arm qemu-system-misc)
            append_optional_pkg pkgs qemu-efi-aarch64
            append_optional_pkg pkgs qemu-efi-arm
            append_optional_pkg pkgs edk2-ovmf
            ;;
    esac

    sudo apt-get install -y "${pkgs[@]}"
}

fetch_required_third_party() {
    cd "${ROOT_DIR}"

    local deps=(lwip limine musl busybox tcc doomgeneric)
    local dep
    local ok
    local attempt
    for dep in "${deps[@]}"; do
        ok=0
        for attempt in 1 2 3; do
            echo "Fetching ${dep} (attempt ${attempt}/3)"
            if scripts/kairos.sh deps fetch "${dep}"; then
                ok=1
                break
            fi
            sleep $((attempt * 5))
        done
        if [[ "${ok}" -ne 1 ]]; then
            echo "Failed to fetch dependency: ${dep}" >&2
            exit 2
        fi
    done

    local required=(
        third_party/lwip/src/include/lwip/tcp.h
        third_party/limine/Makefile
        third_party/musl/include/stdio.h
        third_party/busybox/Makefile
        third_party/tinycc/tcc.c
        third_party/doomgeneric/doomgeneric/doomgeneric.h
    )

    local path
    for path in "${required[@]}"; do
        if [[ ! -e "${path}" ]]; then
            echo "Dependency verification failed: missing ${path}" >&2
            exit 2
        fi
    done
}

set_uefi_env() {
    local code_src="$1"
    local vars_src="$2"

    if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "UEFI_CODE_SRC=${code_src}" >> "${GITHUB_ENV}"
        echo "UEFI_VARS_SRC=${vars_src}" >> "${GITHUB_ENV}"
    fi

    echo "Using UEFI_CODE_SRC=${code_src}"
    echo "Using UEFI_VARS_SRC=${vars_src}"
}

locate_uefi() {
    local arch="$1"
    require_arch "${arch}"

    local code_candidates=()
    local vars_candidates=()
    local pairs=()

    case "${arch}" in
        riscv64)
            code_candidates=(
                /usr/share/edk2/riscv/RISCV_VIRT_CODE.fd
                /usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd
                /usr/share/qemu/RISCV_VIRT_CODE.fd
            )
            vars_candidates=(
                /usr/share/edk2/riscv/RISCV_VIRT_VARS.fd
                /usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd
                /usr/share/qemu/RISCV_VIRT_VARS.fd
            )
            ;;
        x86_64)
            pairs=(
                "/usr/share/edk2/ovmf/OVMF_CODE.fd|/usr/share/edk2/ovmf/OVMF_VARS.fd"
                "/usr/share/edk2/ovmf/OVMF_CODE_4M.fd|/usr/share/edk2/ovmf/OVMF_VARS_4M.fd"
                "/usr/share/OVMF/OVMF_CODE.fd|/usr/share/OVMF/OVMF_VARS.fd"
                "/usr/share/OVMF/OVMF_CODE_4M.fd|/usr/share/OVMF/OVMF_VARS_4M.fd"
                "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd|/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"
                "/usr/share/edk2-ovmf/x64/OVMF_CODE_4M.fd|/usr/share/edk2-ovmf/x64/OVMF_VARS_4M.fd"
            )
            ;;
        aarch64)
            code_candidates=(
                /usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw
                /usr/share/edk2/aarch64/QEMU_EFI-pflash.raw
                /usr/share/AAVMF/AAVMF_CODE.fd
                /usr/share/AAVMF/AAVMF_CODE.ms.fd
                /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
            )
            vars_candidates=(
                /usr/share/edk2/aarch64/vars-template-pflash.raw
                /usr/share/AAVMF/AAVMF_VARS.fd
                /usr/share/AAVMF/AAVMF_VARS.ms.fd
                /usr/share/qemu-efi-aarch64/QEMU_VARS.fd
            )
            ;;
    esac

    local code_src=""
    local vars_src=""
    local p

    if [[ "${arch}" == "x86_64" ]]; then
        local pair
        local code
        local vars
        for pair in "${pairs[@]}"; do
            IFS='|' read -r code vars <<< "${pair}"
            if [[ -f "${code}" && -f "${vars}" ]]; then
                code_src="${code}"
                vars_src="${vars}"
                break
            fi
        done
    else
        for p in "${code_candidates[@]}"; do
            if [[ -f "${p}" ]]; then
                code_src="${p}"
                break
            fi
        done

        for p in "${vars_candidates[@]}"; do
            if [[ -f "${p}" ]]; then
                vars_src="${p}"
                break
            fi
        done
    fi

    if [[ -z "${code_src}" || -z "${vars_src}" ]]; then
        echo "Unable to locate ${arch} UEFI firmware on runner" >&2
        exit 2
    fi

    set_uefi_env "${code_src}" "${vars_src}"
}

main() {
    local cmd="${1:-}"
    case "${cmd}" in
        install-host-deps)
            [[ $# -eq 2 ]] || { usage >&2; exit 2; }
            install_host_deps "$2"
            ;;
        fetch-required-third-party)
            [[ $# -eq 1 ]] || { usage >&2; exit 2; }
            fetch_required_third_party
            ;;
        locate-uefi)
            [[ $# -eq 2 ]] || { usage >&2; exit 2; }
            locate_uefi "$2"
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            echo "ci-bootstrap: unknown command '${cmd}'" >&2
            usage >&2
            exit 2
            ;;
    esac
}

main "$@"

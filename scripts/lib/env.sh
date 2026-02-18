#!/usr/bin/env bash
#
# env.sh - Architecture/environment helpers for Kairos orchestration.
#

kairos_require_arch() {
    case "$1" in
        riscv64 | x86_64 | aarch64) ;;
        *) kairos_die "unsupported architecture: $1" ;;
    esac
}

kairos_arch_to_qemu() {
    case "$1" in
        riscv64) echo "qemu-system-riscv64" ;;
        x86_64) echo "qemu-system-x86_64" ;;
        aarch64) echo "qemu-system-aarch64" ;;
        *) return 1 ;;
    esac
}

kairos_default_uefi_code_src() {
    case "$1" in
        riscv64)
            echo "/usr/share/edk2/riscv/RISCV_VIRT_CODE.fd"
            ;;
        x86_64)
            echo "/usr/share/edk2/ovmf/OVMF_CODE.fd"
            ;;
        aarch64)
            if [[ -f "/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw" ]]; then
                echo "/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw"
            else
                echo "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

kairos_default_uefi_vars_src() {
    case "$1" in
        riscv64)
            echo "/usr/share/edk2/riscv/RISCV_VIRT_VARS.fd"
            ;;
        x86_64)
            echo "/usr/share/edk2/ovmf/OVMF_VARS.fd"
            ;;
        aarch64)
            echo "/usr/share/edk2/aarch64/vars-template-pflash.raw"
            ;;
        *)
            return 1
            ;;
    esac
}

#!/usr/bin/env bash
#
# common.sh - Shared helpers for Kairos build scripts.
#

KAIROS_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

kairos_die() {
    echo "Error: $*" >&2
    exit 1
}

kairos_warn() {
    echo "WARN: $*" >&2
}

kairos_info() {
    if [[ "${QUIET:-0}" != "1" ]]; then
        echo "$*"
    fi
}

kairos_require_cmd() {
    local cmd="$1"
    local hint="${2:-}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        if [[ -n "$hint" ]]; then
            kairos_die "$cmd not found ($hint)"
        fi
        kairos_die "$cmd not found"
    fi
}

kairos_arch_to_musl_target() {
    case "$1" in
        riscv64) echo "riscv64-linux-musl" ;;
        x86_64) echo "x86_64-linux-musl" ;;
        aarch64) echo "aarch64-linux-musl" ;;
        *) return 1 ;;
    esac
}

kairos_arch_cflags() {
    case "$1" in
        riscv64) echo "-march=rv64gc -mabi=lp64" ;;
        x86_64 | aarch64) echo "" ;;
        *) return 1 ;;
    esac
}

kairos_arch_to_boot_efi() {
    case "$1" in
        x86_64) echo "BOOTX64.EFI" ;;
        aarch64) echo "BOOTAA64.EFI" ;;
        riscv64) echo "BOOTRISCV64.EFI" ;;
        *) return 1 ;;
    esac
}

kairos_busybox_applets_file() {
    echo "$KAIROS_ROOT_DIR/scripts/busybox-applets.txt"
}

kairos_read_busybox_applets() {
    local applets_file="${1:-$(kairos_busybox_applets_file)}"
    [[ -f "$applets_file" ]] || kairos_die "BusyBox applet list not found: $applets_file"
    grep -o '[a-zA-Z_][a-zA-Z0-9_]*' "$applets_file"
}

kairos_install_busybox_applet_links() {
    local bin_dir="$1"
    local link_target="${2:-/bin/busybox}"
    local applets_file="${3:-$(kairos_busybox_applets_file)}"

    mkdir -p "$bin_dir"
    while IFS= read -r app; do
        [[ -n "$app" ]] || continue
        ln -sf "$link_target" "$bin_dir/$app"
    done < <(kairos_read_busybox_applets "$applets_file")
}

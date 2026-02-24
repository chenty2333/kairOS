#!/bin/bash
#
# Fetch third-party dependencies for Kairos
#
# Usage: scripts/kairos.sh deps fetch [component]
#   scripts/kairos.sh deps fetch all      - Fetch all dependencies
#   scripts/kairos.sh deps fetch limine   - Fetch Limine bootloader
#   scripts/kairos.sh deps fetch lwip     - Fetch lwIP network stack
#   scripts/kairos.sh deps fetch tinyusb  - Fetch TinyUSB
#   scripts/kairos.sh deps fetch fatfs    - Fetch FatFs
#   scripts/kairos.sh deps fetch tcc      - Fetch TCC (Tiny C Compiler)
#   scripts/kairos.sh deps fetch doomgeneric - Fetch DoomGeneric source

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DEPS_DIR="$ROOT_DIR/third_party"
mkdir -p "$DEPS_DIR"

dep_ready() {
    local dep_name="$1"
    local dep_sentinel="$2"
    local dep_dir="$DEPS_DIR/$dep_name"

    if [ -e "$dep_dir" ] && [ ! -d "$dep_dir" ]; then
        echo "$dep_name path exists but is not a directory, removing: $dep_dir"
        rm -f "$dep_dir"
    fi

    if [ ! -d "$dep_dir" ]; then
        return 1
    fi

    if [ -n "$dep_sentinel" ] && [ ! -e "$dep_dir/$dep_sentinel" ]; then
        echo "$dep_name exists but is incomplete (missing $dep_sentinel), refetching"
        rm -rf "$dep_dir"
        return 1
    fi

    echo "$dep_name already exists, skipping"
    return 0
}

verify_dep_ready() {
    local dep_name="$1"
    local dep_sentinel="$2"
    local dep_dir="$DEPS_DIR/$dep_name"
    if [ ! -e "$dep_dir/$dep_sentinel" ]; then
        echo "Failed to verify dependency: $dep_name (missing $dep_sentinel)" >&2
        exit 1
    fi
}

fetch_limine() {
    local limine_git_url="${LIMINE_GIT_URL:-https://github.com/limine-bootloader/limine.git}"
    local limine_git_ref="${LIMINE_GIT_REF:-v10.8.0-binary}"
    local limine_git_commit="${LIMINE_GIT_COMMIT:-1e99a4a6d593507719a8fbb567a8c34b58a8299b}"

    echo "=== Fetching Limine bootloader ==="
    if dep_ready "limine" "Makefile"; then
        if [[ -n "$limine_git_commit" ]]; then
            local limine_head
            limine_head="$(git -C "$DEPS_DIR/limine" rev-parse HEAD 2>/dev/null || true)"
            if [[ -n "$limine_head" && "$limine_head" != "$limine_git_commit" ]]; then
                echo "limine exists but at $limine_head (expected $limine_git_commit), refetching"
                rm -rf "$DEPS_DIR/limine"
            else
                echo "Source: $limine_git_url ($limine_git_ref${limine_git_commit:+ @ $limine_git_commit})"
                return
            fi
        else
            echo "Source: $limine_git_url ($limine_git_ref)"
            return
        fi
    fi
    git clone "$limine_git_url" \
        --branch="$limine_git_ref" --depth=1 "$DEPS_DIR/limine"
    if [[ -n "$limine_git_commit" ]]; then
        git -C "$DEPS_DIR/limine" fetch --depth=1 origin "$limine_git_commit"
        git -C "$DEPS_DIR/limine" checkout --detach "$limine_git_commit"
    fi
    verify_dep_ready "limine" "Makefile"
    echo "Limine downloaded to $DEPS_DIR/limine"
    echo "Source: $limine_git_url ($limine_git_ref${limine_git_commit:+ @ $limine_git_commit})"
}

fetch_lwip() {
    local lwip_git_url="${LWIP_GIT_URL:-https://github.com/lwip-tcpip/lwip.git}"
    local lwip_git_ref="${LWIP_GIT_REF:-STABLE-2_2_1_RELEASE}"
    local lwip_git_commit="${LWIP_GIT_COMMIT:-}"

    echo "=== Fetching lwIP network stack ==="
    if dep_ready "lwip" "src/include/lwip/tcp.h"; then
        return
    fi
    git clone "$lwip_git_url" \
        --branch="$lwip_git_ref" --depth=1 "$DEPS_DIR/lwip"
    if [[ -n "$lwip_git_commit" ]]; then
        git -C "$DEPS_DIR/lwip" fetch --depth=1 origin "$lwip_git_commit"
        git -C "$DEPS_DIR/lwip" checkout --detach "$lwip_git_commit"
    fi
    verify_dep_ready "lwip" "src/include/lwip/tcp.h"
    echo "lwIP downloaded to $DEPS_DIR/lwip"
    echo "Source: $lwip_git_url ($lwip_git_ref${lwip_git_commit:+ @ $lwip_git_commit})"
    echo "License: BSD-3-Clause"
}

fetch_tinyusb() {
    echo "=== Fetching TinyUSB ==="
    if dep_ready "tinyusb" "src/tusb.h"; then
        return
    fi
    git clone https://github.com/hathach/tinyusb.git \
        --branch=0.20.0 --depth=1 "$DEPS_DIR/tinyusb"
    verify_dep_ready "tinyusb" "src/tusb.h"
    echo "TinyUSB downloaded to $DEPS_DIR/tinyusb"
    echo "License: MIT"
}

fetch_fatfs() {
    local fatfs_zip_url="${FATFS_ZIP_URL:-http://elm-chan.org/fsw/ff/arc/ff16.zip}"
    local fatfs_zip_sha256="${FATFS_ZIP_SHA256:-}"
    local fatfs_zip_tmp

    echo "=== Fetching FatFs ==="
    if dep_ready "fatfs" "source/ff.c"; then
        return
    fi
    mkdir -p "$DEPS_DIR/fatfs"
    # FatFs is distributed as a zip, so we fetch and unpack the archive.
    fatfs_zip_tmp="$(mktemp /tmp/fatfs.XXXXXX.zip)"
    curl -fL "$fatfs_zip_url" -o "$fatfs_zip_tmp"
    if [[ -n "$fatfs_zip_sha256" ]]; then
        echo "${fatfs_zip_sha256}  ${fatfs_zip_tmp}" | sha256sum -c -
    fi
    unzip -q "$fatfs_zip_tmp" -d "$DEPS_DIR/fatfs"
    rm -f "$fatfs_zip_tmp"
    verify_dep_ready "fatfs" "source/ff.c"
    echo "FatFs downloaded to $DEPS_DIR/fatfs"
    echo "Source: $fatfs_zip_url"
    if [[ -n "$fatfs_zip_sha256" ]]; then
        echo "SHA256: verified ($fatfs_zip_sha256)"
    fi
    echo "License: BSD-1-Clause (FatFs license)"
}

fetch_busybox() {
    local busybox_git_url="${BUSYBOX_GIT_URL:-https://github.com/mirror/busybox.git}"
    local busybox_git_ref="${BUSYBOX_GIT_REF:-1_36_1}"
    local busybox_git_commit="${BUSYBOX_GIT_COMMIT:-}"

    echo "=== Fetching BusyBox ==="
    if dep_ready "busybox" "Makefile"; then
        return
    fi
    git clone "$busybox_git_url" \
        --branch="$busybox_git_ref" --depth=1 "$DEPS_DIR/busybox"
    if [[ -n "$busybox_git_commit" ]]; then
        git -C "$DEPS_DIR/busybox" fetch --depth=1 origin "$busybox_git_commit"
        git -C "$DEPS_DIR/busybox" checkout --detach "$busybox_git_commit"
    fi
    verify_dep_ready "busybox" "Makefile"
    echo "BusyBox downloaded to $DEPS_DIR/busybox"
    echo "Source: $busybox_git_url ($busybox_git_ref${busybox_git_commit:+ @ $busybox_git_commit})"
    echo "License: GPL-2.0"
}

fetch_musl() {
    local musl_git_url="${MUSL_GIT_URL:-https://git.musl-libc.org/git/musl}"
    local musl_git_ref="${MUSL_GIT_REF:-v1.2.5}"
    local musl_git_commit="${MUSL_GIT_COMMIT:-}"

    echo "=== Fetching musl libc ==="
    if dep_ready "musl" "include/stdio.h"; then
        return
    fi
    git clone "$musl_git_url" \
        --branch="$musl_git_ref" --depth=1 "$DEPS_DIR/musl"
    if [[ -n "$musl_git_commit" ]]; then
        git -C "$DEPS_DIR/musl" fetch --depth=1 origin "$musl_git_commit"
        git -C "$DEPS_DIR/musl" checkout --detach "$musl_git_commit"
    fi
    verify_dep_ready "musl" "include/stdio.h"
    echo "musl downloaded to $DEPS_DIR/musl"
    echo "Source: $musl_git_url ($musl_git_ref${musl_git_commit:+ @ $musl_git_commit})"
    echo "License: MIT"
}

fetch_limine_header() {
    local dst="$ROOT_DIR/kernel/include/boot/limine.h"
    local limine_header_ref="${LIMINE_HEADER_REF:-aa0fe82730f9a6ea09794503cdf6361be15d66a6}"
    local limine_header_url="${LIMINE_HEADER_URL:-https://raw.githubusercontent.com/limine-bootloader/limine-protocol/${limine_header_ref}/include/limine.h}"
    local force_fetch="${FORCE_LIMINE_HEADER_FETCH:-0}"
    echo "=== Fetching Limine protocol header ==="
    mkdir -p "$(dirname "$dst")"
    if [[ -f "$dst" && "$force_fetch" != "1" ]]; then
        echo "Limine header already exists ($dst), skipping"
        echo "Set FORCE_LIMINE_HEADER_FETCH=1 to refresh from upstream"
        return
    fi
    curl -fL "$limine_header_url" -o "$dst"
    echo "Limine header downloaded to $dst"
    echo "Source: $limine_header_url"
}

fetch_tcc() {
    local tcc_git_url="${TCC_GIT_URL:-https://github.com/chenty2333/tinycc.git}"
    local tcc_git_ref="${TCC_GIT_REF:-mob}"
    local tcc_git_commit="${TCC_GIT_COMMIT:-}"

    echo "=== Fetching TCC (Tiny C Compiler) ==="
    if dep_ready "tinycc" "tcc.c"; then
        return
    fi
    git clone "$tcc_git_url" \
        --branch="$tcc_git_ref" --depth=1 "$DEPS_DIR/tinycc"
    if [[ -n "$tcc_git_commit" ]]; then
        git -C "$DEPS_DIR/tinycc" fetch --depth=1 origin "$tcc_git_commit"
        git -C "$DEPS_DIR/tinycc" checkout --detach "$tcc_git_commit"
    fi
    verify_dep_ready "tinycc" "tcc.c"
    echo "TCC downloaded to $DEPS_DIR/tinycc"
    echo "Source: $tcc_git_url ($tcc_git_ref${tcc_git_commit:+ @ $tcc_git_commit})"
    echo "License: LGPL-2.1"
}

fetch_doomgeneric() {
    local doom_git_url="${DOOMGENERIC_GIT_URL:-https://github.com/ozkl/doomgeneric.git}"
    local doom_git_ref="${DOOMGENERIC_GIT_REF:-master}"
    local doom_git_commit="${DOOMGENERIC_GIT_COMMIT:-}"

    echo "=== Fetching DoomGeneric source ==="
    if dep_ready "doomgeneric" "doomgeneric/doomgeneric.h"; then
        return
    fi
    git clone "$doom_git_url" \
        --branch="$doom_git_ref" --depth=1 "$DEPS_DIR/doomgeneric"
    if [[ -n "$doom_git_commit" ]]; then
        git -C "$DEPS_DIR/doomgeneric" fetch --depth=1 origin "$doom_git_commit"
        git -C "$DEPS_DIR/doomgeneric" checkout --detach "$doom_git_commit"
    fi
    verify_dep_ready "doomgeneric" "doomgeneric/doomgeneric.h"
    echo "DoomGeneric downloaded to $DEPS_DIR/doomgeneric"
    echo "Source: $doom_git_url ($doom_git_ref${doom_git_commit:+ @ $doom_git_commit})"
    echo "License: GPL-2.0"
}

show_help() {
    echo "Usage: $0 [component]"
    echo ""
    echo "Components:"
    echo "  all      - Fetch all dependencies"
    echo "  limine   - Limine bootloader (for creating bootable images)"
    echo "  lwip     - lwIP TCP/IP stack (BSD license)"
    echo "  tinyusb  - TinyUSB stack (MIT license)"
    echo "  fatfs    - FatFs FAT32 library (BSD license)"
    echo "  musl     - musl C library (MIT license)"
    echo "  busybox  - BusyBox userland (GPL-2.0)"
    echo "  tcc      - TCC Tiny C Compiler (LGPL-2.1)"
    echo "  doomgeneric - DoomGeneric source (GPL-2.0)"
    echo "  header   - Just the Limine protocol header"
    echo ""
    echo "All dependencies will be placed in ./third_party/"
}

case "${1:-help}" in
    all)
        fetch_limine
        fetch_limine_header
        fetch_lwip
        fetch_tinyusb
        fetch_fatfs
        fetch_musl
        fetch_busybox
        fetch_tcc
        fetch_doomgeneric
        echo ""
        echo "=== All dependencies fetched ==="
        ;;
    limine)
        fetch_limine
        fetch_limine_header
        ;;
    lwip)
        fetch_lwip
        ;;
    tinyusb)
        fetch_tinyusb
        ;;
    fatfs)
        fetch_fatfs
        ;;
    musl)
        fetch_musl
        ;;
    busybox)
        fetch_busybox
        ;;
    tcc)
        fetch_tcc
        ;;
    doomgeneric)
        fetch_doomgeneric
        ;;
    header)
        fetch_limine_header
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown component: $1"
        show_help
        exit 1
        ;;
esac

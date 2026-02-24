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

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DEPS_DIR="$ROOT_DIR/third_party"
mkdir -p "$DEPS_DIR"

fetch_limine() {
    echo "=== Fetching Limine bootloader ==="
    if [ -d "$DEPS_DIR/limine" ]; then
        echo "Limine already exists, skipping"
        return
    fi
    git clone https://github.com/limine-bootloader/limine.git \
        --branch=v10.x-binary --depth=1 "$DEPS_DIR/limine"
    echo "Limine downloaded to $DEPS_DIR/limine"
}

fetch_lwip() {
    echo "=== Fetching lwIP network stack ==="
    if [ -d "$DEPS_DIR/lwip" ]; then
        echo "lwIP already exists, skipping"
        return
    fi
    git clone https://git.savannah.nongnu.org/git/lwip.git \
        --branch=STABLE-2_2_1_RELEASE --depth=1 "$DEPS_DIR/lwip"
    echo "lwIP downloaded to $DEPS_DIR/lwip"
    echo "License: BSD-3-Clause"
}

fetch_tinyusb() {
    echo "=== Fetching TinyUSB ==="
    if [ -d "$DEPS_DIR/tinyusb" ]; then
        echo "TinyUSB already exists, skipping"
        return
    fi
    git clone https://github.com/hathach/tinyusb.git \
        --branch=0.20.0 --depth=1 "$DEPS_DIR/tinyusb"
    echo "TinyUSB downloaded to $DEPS_DIR/tinyusb"
    echo "License: MIT"
}

fetch_fatfs() {
    echo "=== Fetching FatFs ==="
    if [ -d "$DEPS_DIR/fatfs" ]; then
        echo "FatFs already exists, skipping"
        return
    fi
    mkdir -p "$DEPS_DIR/fatfs"
    # FatFs is distributed as a zip, we'll use curl
    curl -L "http://elm-chan.org/fsw/ff/arc/ff16.zip" -o "/tmp/fatfs.zip"
    unzip -q "/tmp/fatfs.zip" -d "$DEPS_DIR/fatfs"
    rm "/tmp/fatfs.zip"
    echo "FatFs downloaded to $DEPS_DIR/fatfs"
    echo "License: BSD-1-Clause (FatFs license)"
}

fetch_busybox() {
    echo "=== Fetching BusyBox ==="
    if [ -d "$DEPS_DIR/busybox" ]; then
        echo "BusyBox already exists, skipping"
        return
    fi
    git clone https://git.busybox.net/busybox \
        --branch=1_36_1 --depth=1 "$DEPS_DIR/busybox"
    echo "BusyBox downloaded to $DEPS_DIR/busybox"
    echo "License: GPL-2.0"
}

fetch_musl() {
    echo "=== Fetching musl libc ==="
    if [ -d "$DEPS_DIR/musl" ]; then
        echo "musl already exists, skipping"
        return
    fi
    git clone https://git.musl-libc.org/git/musl \
        --branch=v1.2.5 --depth=1 "$DEPS_DIR/musl"
    echo "musl downloaded to $DEPS_DIR/musl"
    echo "License: MIT"
}

fetch_limine_header() {
    local dst="$ROOT_DIR/kernel/include/boot/limine.h"
    local force_fetch="${FORCE_LIMINE_HEADER_FETCH:-0}"
    echo "=== Fetching Limine protocol header ==="
    mkdir -p "$(dirname "$dst")"
    if [[ -f "$dst" && "$force_fetch" != "1" ]]; then
        echo "Limine header already exists ($dst), skipping"
        echo "Set FORCE_LIMINE_HEADER_FETCH=1 to refresh from upstream"
        return
    fi
    curl -L "https://codeberg.org/Limine/limine-protocol/raw/branch/trunk/include/limine.h" \
        -o "$dst"
    echo "Limine header downloaded to $dst"
}

fetch_tcc() {
    local tcc_git_url="${TCC_GIT_URL:-https://github.com/chenty2333/tinycc.git}"
    local tcc_git_ref="${TCC_GIT_REF:-mob}"
    local tcc_git_commit="${TCC_GIT_COMMIT:-}"

    echo "=== Fetching TCC (Tiny C Compiler) ==="
    if [ -d "$DEPS_DIR/tinycc" ]; then
        echo "TCC already exists, skipping"
        return
    fi
    git clone "$tcc_git_url" \
        --branch="$tcc_git_ref" --depth=1 "$DEPS_DIR/tinycc"
    if [[ -n "$tcc_git_commit" ]]; then
        git -C "$DEPS_DIR/tinycc" fetch --depth=1 origin "$tcc_git_commit"
        git -C "$DEPS_DIR/tinycc" checkout --detach "$tcc_git_commit"
    fi
    echo "TCC downloaded to $DEPS_DIR/tinycc"
    echo "Source: $tcc_git_url ($tcc_git_ref${tcc_git_commit:+ @ $tcc_git_commit})"
    echo "License: LGPL-2.1"
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

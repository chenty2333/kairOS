#!/bin/bash
#
# Fetch third-party dependencies for Kairos
#
# Usage: ./scripts/fetch-deps.sh [component]
#   ./scripts/fetch-deps.sh all      - Fetch all dependencies
#   ./scripts/fetch-deps.sh limine   - Fetch Limine bootloader
#   ./scripts/fetch-deps.sh lwip     - Fetch lwIP network stack
#   ./scripts/fetch-deps.sh tinyusb  - Fetch TinyUSB
#   ./scripts/fetch-deps.sh fatfs    - Fetch FatFs

set -e

DEPS_DIR="third_party"
mkdir -p "$DEPS_DIR"

fetch_limine() {
    echo "=== Fetching Limine bootloader ==="
    if [ -d "$DEPS_DIR/limine" ]; then
        echo "Limine already exists, skipping"
        return
    fi
    git clone https://github.com/limine-bootloader/limine.git \
        --branch=v8.x-binary --depth=1 "$DEPS_DIR/limine"
    echo "Limine downloaded to $DEPS_DIR/limine"
}

fetch_lwip() {
    echo "=== Fetching lwIP network stack ==="
    if [ -d "$DEPS_DIR/lwip" ]; then
        echo "lwIP already exists, skipping"
        return
    fi
    git clone https://git.savannah.nongnu.org/git/lwip.git \
        --branch=STABLE-2_2_0_RELEASE --depth=1 "$DEPS_DIR/lwip"
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
        --branch=0.16.0 --depth=1 "$DEPS_DIR/tinyusb"
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
    curl -L "http://elm-chan.org/fsw/ff/arc/ff15.zip" -o "/tmp/fatfs.zip"
    unzip -q "/tmp/fatfs.zip" -d "$DEPS_DIR/fatfs"
    rm "/tmp/fatfs.zip"
    echo "FatFs downloaded to $DEPS_DIR/fatfs"
    echo "License: BSD-1-Clause (FatFs license)"
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
    echo "=== Fetching Limine protocol header ==="
    mkdir -p "kernel/include/boot"
    curl -L "https://raw.githubusercontent.com/limine-bootloader/limine/v8.x-binary/limine.h" \
        -o "kernel/include/boot/limine.h"
    echo "Limine header downloaded to kernel/include/boot/limine.h"
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

#!/usr/bin/env bash
#
# image.sh - Image assembly orchestration.
#

kairos_image_usage() {
    cat <<'EOF'
Usage: scripts/kairos.sh [global options] image <action>

Actions:
  initramfs      Build initramfs image
  rootfs-base    Stage rootfs base
  rootfs-init    Stage rootfs init
  rootfs-busybox Stage rootfs busybox
  rootfs-tcc     Stage rootfs tcc payload
  rootfs         Stage rootfs (base + init + busybox + optional tcc)
  disk           Build ext2 disk image
  prepare-uefi   Prepare UEFI firmware pflash files
  uefi-disk      Build UEFI FAT boot image
  uefi           Prepare UEFI firmware and boot image
  iso            Build bootable ISO
  all            Build initramfs + uefi + disk
EOF
}

kairos_image_stage_rootfs() {
    local stage="$1"
            kairos_exec_script_env "image" \
                ARCH="${KAIROS_ARCH}" \
                BUILD_ROOT="${KAIROS_BUILD_ROOT}" \
                QUIET="${KAIROS_QUIET}" \
                JOBS="${KAIROS_JOBS}" \
                ROOTFS_ONLY=1 \
                ROOTFS_STAGE="${stage}" \
                "${KAIROS_ROOT_DIR}/scripts/impl/make-disk.sh" \
                "${KAIROS_ARCH}"
}

kairos_image_dispatch() {
    local action="${1:-}"
    if [[ -z "$action" ]]; then
        kairos_image_usage
        return 2
    fi

    case "$action" in
        initramfs)
            kairos_exec_script "image" "${KAIROS_ROOT_DIR}/scripts/impl/make-initramfs.sh" "${KAIROS_ARCH}"
            ;;
        rootfs-base)
            kairos_image_stage_rootfs "base"
            ;;
        rootfs-init)
            kairos_image_stage_rootfs "init"
            ;;
        rootfs-busybox)
            kairos_image_stage_rootfs "busybox"
            ;;
        rootfs-tcc)
            kairos_image_stage_rootfs "tcc"
            ;;
        rootfs)
            kairos_image_stage_rootfs "base"
            kairos_image_stage_rootfs "init"
            kairos_image_stage_rootfs "busybox"
            if [[ -x "${KAIROS_BUILD_ROOT}/${KAIROS_ARCH}/tcc/bin/tcc" ]]; then
                kairos_image_stage_rootfs "tcc"
            fi
            ;;
        disk)
            kairos_exec_script "image" "${KAIROS_ROOT_DIR}/scripts/impl/make-disk.sh" "${KAIROS_ARCH}"
            ;;
        prepare-uefi)
            kairos_exec_script "image" "${KAIROS_ROOT_DIR}/scripts/impl/prepare-uefi.sh" "${KAIROS_ARCH}"
            ;;
        uefi-disk)
            kairos_exec_script "image" "${KAIROS_ROOT_DIR}/scripts/impl/make-uefi-disk.sh" "${KAIROS_ARCH}"
            ;;
        uefi)
            kairos_image_dispatch prepare-uefi
            kairos_image_dispatch uefi-disk
            ;;
        iso)
            kairos_exec_script "image" "${KAIROS_ROOT_DIR}/scripts/impl/make-iso.sh" "${KAIROS_ARCH}"
            ;;
        all)
            kairos_image_dispatch initramfs
            kairos_image_dispatch uefi
            kairos_image_dispatch disk
            ;;
        *)
            kairos_die "unknown image action: ${action}"
            ;;
    esac
}

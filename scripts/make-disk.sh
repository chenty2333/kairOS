#!/bin/bash
#
# make-disk.sh - Create an ext2 disk image for testing
#
# This script creates a 64MB ext2 filesystem with some test files.

set -e

DISK_IMG="${1:-disk.img}"
DISK_SIZE=64  # MB
MOUNT_POINT="/tmp/kairos-disk-$$"

echo "Creating ext2 disk image: $DISK_IMG"

# Create empty disk image
dd if=/dev/zero of="$DISK_IMG" bs=1M count=$DISK_SIZE 2>/dev/null

# Create ext2 filesystem
mkfs.ext2 -F "$DISK_IMG" >/dev/null 2>&1

echo "Created $DISK_SIZE MB ext2 filesystem"

# Mount the filesystem
mkdir -p "$MOUNT_POINT"
sudo mount -o loop "$DISK_IMG" "$MOUNT_POINT"

# Create test files
echo "Hello from Kairos filesystem!" | sudo tee "$MOUNT_POINT/test.txt" >/dev/null
echo "This is another test file" | sudo tee "$MOUNT_POINT/test2.txt" >/dev/null

# Create test directories
sudo mkdir -p "$MOUNT_POINT/home"
sudo mkdir -p "$MOUNT_POINT/etc"
sudo mkdir -p "$MOUNT_POINT/bin"

# Create some files in subdirectories
echo "root:x:0:0:root:/root:/bin/sh" | sudo tee "$MOUNT_POINT/etc/passwd" >/dev/null
echo "127.0.0.1 localhost" | sudo tee "$MOUNT_POINT/etc/hosts" >/dev/null

# Show contents
echo ""
echo "Disk contents:"
sudo ls -lR "$MOUNT_POINT"

# Unmount
sudo umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

echo ""
echo "Disk image created successfully: $DISK_IMG"
echo ""
echo "To use with QEMU:"
echo "  make run"
echo ""
echo "The disk will be automatically attached as virtio block device (vda)"

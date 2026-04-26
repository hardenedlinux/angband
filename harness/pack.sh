#!/bin/bash

# Simple script to pack an initramfs
# Assumes a 'rootfs' directory exists

if [ ! -d "rootfs" ]; then
    mkdir rootfs
    echo "[*] Created rootfs directory. Add your files there."
    exit 0
fi

cd rootfs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
cd ..

echo "[*] initramfs.cpio.gz created."

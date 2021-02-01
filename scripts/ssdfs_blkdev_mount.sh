#!/bin/bash

## Script to mount SSDFS filesystem using block device.
## Initial script: http://wiki.emacinc.com/wiki/Mounting_JFFS2_Images_on_a_Linux_PC

if [[ $# -lt 2 ]]
then
    echo "Usage: $0 BLOCK_DEVICE MOUNTPOINT"
    exit 1
fi

if [ "$(whoami)" != "root" ]
then
    echo "$0 must be run as root!"
    exit 1
fi

if [[ ! -d $2 ]]
then
    echo "$2 is not a valid mount point"
    exit 1
fi

# cleanup if necessary
umount "$2" &>/dev/null
modprobe -r ssdfs &>/dev/null
sleep 0.25

modprobe ssdfs || exit 1

mount -t ssdfs "$1" "$2" || exit 1

echo "Successfully mounted $1 on $2"
exit 0

#!/bin/bash

## Script to mount SSDFS filesystem using block device.
## Initial script: http://wiki.emacinc.com/wiki/Mounting_JFFS2_Images_on_a_Linux_PC

if [[ $# -lt 2 ]]
then
    echo "Usage: $0 FSNAME.SSDFS LOOP_DEVICE MOUNTPOINT"
    exit 1
fi

if [ "$(whoami)" != "root" ]
then
    echo "$0 must be run as root!"
    exit 1
fi

if [[ ! -e $1 ]]
then
    echo "$1 does not exist"
    exit 1
fi

if [[ ! -b $2 ]]
then
    echo "$2 is not a loop device"
    exit 1
fi

if [[ ! -d $3 ]]
then
    echo "$3 is not a valid mount point"
    exit 1
fi

# cleanup if necessary
umount "$3" &>/dev/null
modprobe -r ssdfs &>/dev/null
sleep 0.25
losetup -d "$2" &>/dev/null
sleep 0.25

modprobe loop || exit 1
losetup "$2" "$1" || exit 1
modprobe ssdfs || exit 1

mount -t ssdfs "$2" "$3" || exit 1

echo "Successfully mounted $1 on $3"
exit 0

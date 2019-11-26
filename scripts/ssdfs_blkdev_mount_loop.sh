#!/bin/bash

## Script to mount SSDFS filesystem using block device.
## Initial script: http://wiki.emacinc.com/wiki/Mounting_JFFS2_Images_on_a_Linux_PC

if [[ $# -lt 2 ]]
then
    echo "Usage: $0 FSNAME.SSDFS MOUNTPOINT"
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

if [[ ! -d $2 ]]
then
    echo "$2 is not a valid mount point"
    exit 1
fi

# cleanup if necessary
umount $2 &>/dev/null
modprobe -r ssdfs &>/dev/null
sleep 0.25
losetup -d /dev/loop0 &>/dev/null
sleep 0.25

modprobe loop || exit 1
losetup /dev/loop0 "$1" || exit 1
modprobe ssdfs || exit 1

mount -t ssdfs /dev/loop0 "$2" || exit 1

echo "Successfully mounted $1 on $2"
exit 0

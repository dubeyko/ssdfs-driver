#!/bin/bash

if [[ $# -lt 3 ]]
then
    echo "Usage: $0 BLOCK_DEVICE MOUNTPOINT START-NUMBER STEP-INSIDE-MOUNT FILES-NUMBER"
    exit 1
fi

if [ "$(whoami)" != "root" ]
then
    echo "$0 must be run as root!"
    exit 1
fi

sudo ./ssdfs_blkdev_mount.sh $1 $2

ls -lah $2

echo "remove all files $2/*"

rm -rf $2/*

sudo umount $2

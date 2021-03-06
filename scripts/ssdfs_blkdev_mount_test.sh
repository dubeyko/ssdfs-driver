#!/bin/bash

if [[ $# -lt 2 ]]
then
    echo "Usage: $0 BLOCK_DEVICE MOUNTPOINT MOUNT_NUMBER"
    exit 1
fi

if [ "$(whoami)" != "root" ]
then
    echo "$0 must be run as root!"
    exit 1
fi

i="0"

while [ $i -lt $3 ]
do
i=$[$i+1]

echo $i

sudo ./ssdfs_blkdev_mount.sh $1 $2
sudo umount $2

#mkdir $i"-MOUNT-DUMP"

#cd $i"-MOUNT-DUMP"

#dump.ssdfs -p parse_all,raw_dump -o ./ $1

#cd ../

done

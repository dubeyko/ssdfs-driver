#!/bin/bash

if [[ $# -lt 2 ]]
then
    echo "Usage: $0 SSDFS-IMAGE MOUNT_NUMBER"
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

i="0"

while [ $i -lt $2 ]
do
i=$[$i+1]

echo $i

sudo ./ssdfs_blkdev_mount_loop.sh $1 /mnt/ssdfs/
sudo umount /mnt/ssdfs

mkdir $i"-MOUNT-DUMP"

cd $i"-MOUNT-DUMP"

../dump.ssdfs -p parse_all,raw_dump -o ./ ../$1

cd ../

done

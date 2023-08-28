#!/bin/bash

if [[ $# -lt 3 ]]
then
    echo "Usage: $0 BLOCK_DEVICE MOUNTPOINT START-NUMBER STEP-INSIDE-MOUNT FILES-NUMBER BYTES-COUNT"
    exit 1
fi

if [ "$(whoami)" != "root" ]
then
    echo "$0 must be run as root!"
    exit 1
fi

i=$3

while [ $i -lt $[$3+$5] ]
do

sudo ./ssdfs_blkdev_mount.sh $1 $2

j="0"

while [ $j -lt $4 ]
do
j=$[$j+1]

i=$[$i+1]

echo $i

touch $2/$i".txt"
dd if=/dev/urandom of=$2/$i".txt" conv=notrunc oflag=append bs=1 count=$6

done

#ls -lah $2
#ls /mnt/ssdfs

sudo umount $2

#mkdir $i"-MOUNT-DUMP"
#chown -hR slavad $i"-MOUNT-DUMP"

#cd $i"-MOUNT-DUMP"

#dump.ssdfs -p parse_all,raw_dump -o ./ ../$1

#cd ../

done

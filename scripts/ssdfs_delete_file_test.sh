#!/bin/bash

if [[ $# -lt 3 ]]
then
    echo "Usage: $0 SSDFS-IMAGE START-NUMBER STEP-INSIDE-MOUNT FILES-NUMBER"
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

i=$2

while [ $i -lt $[$2+$4] ]
do

sudo ./ssdfs_blkdev_mount_loop.sh $1 /mnt/ssdfs/

j="0"

while [ $j -lt $3 ]
do
j=$[$j+1]

i=$[$i+1]

echo $i

rm /mnt/ssdfs/$i".txt"

done

#ls -lah /mnt/ssdfs
ls /mnt/ssdfs

sudo umount /mnt/ssdfs

#mkdir $i"-MOUNT-DUMP"
#chown -hR slavad $i"-MOUNT-DUMP"

#cd $i"-MOUNT-DUMP"

#dump.ssdfs -p parse_all,raw_dump -o ./ ../$1

#cd ../

done

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

done

#ls -lah /mnt/ssdfs
#ls /mnt/ssdfs

file_count=`ls -1A /mnt/ssdfs | wc -l`
echo "Files count: $file_count"

k=$[$i-1]

if [[ $file_count -lt $k ]]
then
    echo "Files count $file_count must be equal to $k!"
    ls -lah /mnt/ssdfs
    sudo umount $2
    exit 1
fi

#j="0"

#while [ $j -lt 10 ]
#do
#j=$[$j+1]

#echo $j

#sleep 1

#done

sudo umount $2

#mkdir $i"-MOUNT-DUMP"
#chown -hR slavad $i"-MOUNT-DUMP"

#cd $i"-MOUNT-DUMP"

#dump.ssdfs -p parse_all,raw_dump -o ./ ../$1

#cd ../

done

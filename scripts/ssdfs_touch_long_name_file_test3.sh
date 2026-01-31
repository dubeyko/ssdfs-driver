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

MIN_LEN=14
MAX_LEN=255
RANGE_LEN=$(($MAX_LEN - $MIN_LEN + 1)) # Calculate the range size

while [ $i -lt $[$3+$5] ]
do

sudo ./ssdfs_blkdev_mount.sh $1 $2

j="0"

while [ $j -lt $4 ]
do
j=$[$j+1]

i=$[$i+1]

RAND_LEN=$(($MIN_LEN + $RANDOM % $RANGE_LEN))
RAND_STRING=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$RAND_LEN")

echo $RAND_STRING

touch $2/$RAND_STRING".txt"

done

#ls -lah $2
#ls $2

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

#dump.ssdfs -p parse_all,raw_dump -o ./ $1

#cd ../

done

#!/bin/bash

if [[ $# -lt 3 ]]
then
    echo "Usage: $0 BLOCK_DEVICE MOUNTPOINT TOTAL-FILES-NUMBER"
    exit 1
fi

if [ "$(whoami)" != "root" ]
then
    echo "$0 must be run as root!"
    exit 1
fi

i=0

while [ $i -lt $3 ]
do

i=$[$i+1]

# create empty file
./ssdfs_touch_file_test2.sh $1 $2 0 $i $i

# update empty file
./ssdfs_touch_file_test2.sh $1 $2 0 $i $i

# delete empty file
./ssdfs_delete_file_test2.sh $1 $2 0 $i $i

done

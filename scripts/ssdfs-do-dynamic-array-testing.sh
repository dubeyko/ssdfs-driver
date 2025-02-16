#!/bin/bash

#if [[ $# -lt 3 ]]
#then
#    echo "Usage: $0 LOOP-DEVICE MOUNT-POINT"
#    exit 1
#fi

if [ "$(whoami)" != "root" ]
then
    echo "$0 must be run as root!"
    exit 1
fi

image="./ssdfs-test-dynamic-array-image.bin"
loop_device=$1
mount_point=$2
test_file="test"

echo "Create $image ..."

sudo dd if=/dev/zero of=$image bs=1024 count=1048576 || exit 1

echo "Format $image ..."

sudo mkfs.ssdfs -p 4096 -e 131072 -s 131072 -L ssdfs-test $image || exit 1

#sudo mkdir $mount_point

# cleanup if necessary
umount $mount_point &>/dev/null
modprobe -r ssdfs &>/dev/null
sleep 0.25
losetup -d $loop_device &>/dev/null
sleep 0.25

modprobe loop || exit 1
losetup $loop_device $image || exit 1
modprobe ssdfs || exit 1

# DYNAMIC ARRAY TESTING

iterations=2
capacity=10
item_size=1
upper_bound=4096

while [ $item_size -lt $upper_bound ]
do

i=1

while [ $i -lt $iterations ]
do

count=1

while [ $count -lt $capacity ]
do

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "DYNAMIC_ARRAY: ITEM_SIZE $item_size COUNT $count ITERATIONS $i"

sudo test.ssdfs -s memory_primitives -M iterations=$iterations,capacity=$capacity,count=$count,item_size=$item_size,test_dynamic_array $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

#cat /proc/meminfo

count=$[$count+1]

done

i=$[$i+1]

done

item_size=$[$item_size*2]

done

sudo rm $image

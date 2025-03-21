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

image="./ssdfs-test-block-bitmap-image.bin"
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

# BLOCK BITMAP TESTING

capacity=32
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=100
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=500
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=1000
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=10000
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=50000
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=100000
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=250000
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=500000
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=750000
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

capacity=1000000
pre_alloc=1
alloc=1
invalidate=1
reserve=1

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $capacity"

sudo test.ssdfs -s block_bitmap -b capacity=$capacity,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

i=1
iterations=10
capacity=1000
count=32
pre_alloc=1
alloc=1
invalidate=1
reserve=1

while [ $count -lt $capacity ]
do

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

echo "BLOCK BITMAP: PRE_ALLOC $pre_alloc ALLOC $alloc INVALIDATE $invalidate RESERVE $reserve CAPACITY $count"

sudo test.ssdfs -s block_bitmap -b capacity=$count,pre-alloc=$pre_alloc,alloc=$alloc,invalidate=$invalidate,reserve=$reserve  $mount_point/$test_file || exit 1

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

count=$[$count+1]

done

sudo rm $image

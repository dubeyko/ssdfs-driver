#!/bin/bash

#if [[ $# -lt 3 ]]
#then
#    echo "Usage: $0 SSDFS-IMAGE FILE-NAME ITERATION-COUNT BYTES-COUNT"
#    exit 1
#fi

if [ "$(whoami)" != "root" ]
then
    echo "$0 must be run as root!"
    exit 1
fi

image="./ssdfs-test-image.bin"
mount_point="/mnt/ssdfs"
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
losetup -d /dev/loop0 &>/dev/null
sleep 0.25

modprobe loop || exit 1
losetup /dev/loop0 $image || exit 1
modprobe ssdfs || exit 1

mount -t ssdfs /dev/loop0 $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

sudo test.ssdfs --all --extent max_len=16 --file max_count=100,max_size=1073741824 $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

sudo rm $image

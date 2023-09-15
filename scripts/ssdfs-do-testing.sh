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

image="./ssdfs-test-image.bin"
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

# FOLIO VECTOR TESTING

i=1
iterations=10
capacity=100
count=100

while [ $i -lt $iterations ]
do

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

#sudo test.ssdfs --all --extent max_len=16 --file max_count=100,max_size=1073741824 $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=100,capacity=100,count=100,item_size=8192,test_folio_vector $mount_point/$test_file

item_size=4096
echo "FOLIO VECTOR: ITEM_SIZE $item_size COUNT $count ITERATIONS $i"

sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$count,item_size=$item_size,test_folio_vector $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$i,item_size=4096,test_folio_vector $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

#sudo test.ssdfs --all --extent max_len=16 --file max_count=100,max_size=1073741824 $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=100,capacity=100,count=100,item_size=8192,test_folio_vector $mount_point/$test_file

item_size=8192
echo "FOLIO VECTOR: ITEM_SIZE $item_size COUNT $count ITERATIONS $i"

sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$count,item_size=$item_size,test_folio_vector $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$i,item_size=8192,test_folio_vector $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

#sudo test.ssdfs --all --extent max_len=16 --file max_count=100,max_size=1073741824 $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=100,capacity=100,count=100,item_size=8192,test_folio_vector $mount_point/$test_file

item_size=16384
echo "FOLIO VECTOR: ITEM_SIZE $item_size COUNT $count ITERATIONS $i"

sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$count,item_size=$item_size,test_folio_vector $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$i,item_size=16384,test_folio_vector $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

#sudo test.ssdfs --all --extent max_len=16 --file max_count=100,max_size=1073741824 $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=100,capacity=100,count=100,item_size=8192,test_folio_vector $mount_point/$test_file

item_size=32768
echo "FOLIO VECTOR: ITEM_SIZE $item_size COUNT $count ITERATIONS $i"

sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$count,item_size=$item_size,test_folio_vector $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$i,item_size=32768,test_folio_vector $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

#sudo test.ssdfs --all --extent max_len=16 --file max_count=100,max_size=1073741824 $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=100,capacity=100,count=100,item_size=8192,test_folio_vector $mount_point/$test_file

item_size=65536
echo "FOLIO VECTOR: ITEM_SIZE $item_size COUNT $count ITERATIONS $i"

sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$count,item_size=$item_size,test_folio_vector $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$i,item_size=65536,test_folio_vector $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

#sudo test.ssdfs --all --extent max_len=16 --file max_count=100,max_size=1073741824 $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=100,capacity=100,count=100,item_size=8192,test_folio_vector $mount_point/$test_file

item_size=131072
echo "FOLIO VECTOR: ITEM_SIZE $item_size COUNT $count ITERATIONS $i"

sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$count,item_size=$item_size,test_folio_vector $mount_point/$test_file
#sudo test.ssdfs -s memory_primitives -M iterations=$i,capacity=$capacity,count=$i,item_size=131072,test_folio_vector $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

i=$[$i+1]

done

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

# FOLIO ARRAY TESTING

i=1
iterations=10
capacity=1000
count=100

while [ $count -lt $capacity ]
do

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

item_size=4096
echo "FOLIO ARRAY: ITEM_SIZE $item_size COUNT $count ITERATIONS $iterations"

sudo test.ssdfs -s memory_primitives -M iterations=$iterations,capacity=$capacity,count=$count,item_size=$item_size,test_folio_array $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

item_size=8192
echo "FOLIO ARRAY: ITEM_SIZE $item_size COUNT $count ITERATIONS $iterations"

sudo test.ssdfs -s memory_primitives -M iterations=$iterations,capacity=$capacity,count=$count,item_size=$item_size,test_folio_array $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

item_size=16384
echo "FOLIO ARRAY: ITEM_SIZE $item_size COUNT $count ITERATIONS $iterations"

sudo test.ssdfs -s memory_primitives -M iterations=$iterations,capacity=$capacity,count=$count,item_size=$item_size,test_folio_array $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

item_size=32768
echo "FOLIO ARRAY: ITEM_SIZE $item_size COUNT $count ITERATIONS $iterations"

sudo test.ssdfs -s memory_primitives -M iterations=$iterations,capacity=$capacity,count=$count,item_size=$item_size,test_folio_array $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

item_size=65536
echo "FOLIO ARRAY: ITEM_SIZE $item_size COUNT $count ITERATIONS $iterations"

sudo test.ssdfs -s memory_primitives -M iterations=$iterations,capacity=$capacity,count=$count,item_size=$item_size,test_folio_array $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

mount -t ssdfs $loop_device $mount_point || exit 1

echo "Successfully mounted $image on $mount_point"

sudo touch $mount_point/$test_file || exit 1

item_size=131072
echo "FOLIO ARRAY: ITEM_SIZE $item_size COUNT $count ITERATIONS $iterations"

sudo test.ssdfs -s memory_primitives -M iterations=$iterations,capacity=$capacity,count=$count,item_size=$item_size,test_folio_array $mount_point/$test_file

sudo rm $mount_point/$test_file

sudo umount $mount_point

echo "Unmounted $mount_point"

count=$[$count+1]

done

# NEXT TEST HERE

sudo rm $image

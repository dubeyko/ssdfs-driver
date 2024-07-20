#!/bin/bash

## Script to mount SSDFS filesystem using block device.
## Initial script: http://wiki.emacinc.com/wiki/Mounting_JFFS2_Images_on_a_Linux_PC

if [[ $# -lt 2 ]]
then
    echo "Usage: $0 BLOCK_DEVICE MOUNTPOINT"
    exit 1
fi

if [ "$(whoami)" != "root" ]
then
    echo "$0 must be run as root!"
    exit 1
fi

if [[ ! -d $2 ]]
then
    echo "$2 is not a valid mount point"
    exit 1
fi

declare -a block_size=("4KB" "8KB" "16KB" "32KB")
declare -a erase_block_size=("128KB" "256KB" "512KB" "2MB" "8MB")
declare -a segment_size=("128KB" "256KB" "512KB" "2MB" "8MB")

block_size_array_length=${#block_size[@]}
erase_block_size_array_length=${#erase_block_size[@]}

for (( i=0; i<${erase_block_size_array_length}; i++ ));
do
  for (( j=0; j<${block_size_array_length}; j++ ));
  do
    mkfs.ssdfs -p ${block_size[$j]} -e ${erase_block_size[$i]} -s ${segment_size[$i]} -L testing $1
    ./ssdfs_add_user_data_test4.sh $1 $2 0 10 1000 16384
    ./ssdfs_update_user_data_test5.sh $1 $2 0 10 1000 16384
    ./ssdfs_delete_file_test2.sh $1 $2 0 10 1000

    mkfs.ssdfs -p ${block_size[$j]} -e ${erase_block_size[$i]} -s ${segment_size[$i]} -L testing $1
    ./ssdfs_add_user_data_test4.sh $1 $2 0 100 1000 16384
    ./ssdfs_update_user_data_test5.sh $1 $2 0 100 1000 16384
    ./ssdfs_delete_file_test2.sh $1 $2 0 100 1000

    mkfs.ssdfs -p ${block_size[$j]} -e ${erase_block_size[$i]} -s ${segment_size[$i]} -L testing $1
    ./ssdfs_add_user_data_test4.sh $1 $2 0 1000 1000 16384
    ./ssdfs_update_user_data_test5.sh $1 $2 0 1000 1000 16384
    ./ssdfs_delete_file_test2.sh $1 $2 0 1000 1000

    mkfs.ssdfs -p ${block_size[$j]} -e ${erase_block_size[$i]} -s ${segment_size[$i]} -L testing $1
    ./ssdfs_add_user_data_test4.sh $1 $2 0 10 1000 102400
    ./ssdfs_update_user_data_test5.sh $1 $2 0 10 1000 102400
    ./ssdfs_delete_file_test2.sh $1 $2 0 10 1000

    mkfs.ssdfs -p ${block_size[$j]} -e ${erase_block_size[$i]} -s ${segment_size[$i]} -L testing $1
    ./ssdfs_add_user_data_test4.sh $1 $2 0 100 1000 102400
    ./ssdfs_update_user_data_test5.sh $1 $2 0 100 1000 102400
    ./ssdfs_delete_file_test2.sh $1 $2 0 100 1000

    mkfs.ssdfs -p ${block_size[$j]} -e ${erase_block_size[$i]} -s ${segment_size[$i]} -L testing $1
    ./ssdfs_add_user_data_test4.sh $1 $2 0 1000 1000 102400
    ./ssdfs_update_user_data_test5.sh $1 $2 0 1000 1000 102400
    ./ssdfs_delete_file_test2.sh $1 $2 0 1000 1000
  done
done

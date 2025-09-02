#!/bin/bash

## Script to mount SSDFS filesystem using block device.
## Initial script: http://wiki.emacinc.com/wiki/Mounting_JFFS2_Images_on_a_Linux_PC

if [[ $# -lt 2 ]]
then
    echo "Usage: $0 LOOP-DEVICE MOUNTPOINT"
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

loop_device=$1
mount_point=$2

declare -a block_size=("4KB" "8KB" "16KB" "32KB")
declare -a block_size_number=(4096 8192 16384 32768)
block_size_array_length=${#block_size[@]}

peb_size_min=131072
peb_size_max=$[4*1024*1024*1024]
#pebs_per_segment_max=64
pebs_per_segment_max=2
seg_size_max=$[64*1024*1024*1024]
volume_size_min=$[1024*1024*1024]
volume_size_max=$[16*1024*1024*1024*1024]
nsegs_max=150000000
min_segs=40
min_logical_blks_per_peb=8
max_logical_blks_per_peb=$[65536-1]
volume_1gb_factor=$[1024*1024*1024]
volume_10gb_factor=$[10*1024*1024*1024]
volume_100gb_factor=$[100*1024*1024*1024]
volume_size_1gb_threshold=$[100*1024*1024*1024]
volume_size_10gb_threshold=$[1024*1024*1024*1024]

for (( volume_size=$volume_size_min; volume_size<$volume_size_max; ));
do
  for (( pebs_per_seg=1; pebs_per_seg<$pebs_per_segment_max; pebs_per_seg=$[$pebs_per_seg*2] ));
  do
    for (( peb_size=peb_size_min; peb_size<$peb_size_max; peb_size=$[$peb_size*2] ));
    do

      seg_size=$[$peb_size*$pebs_per_seg]
      if [[ $seg_size -gt $seg_size_max ]]
      then
        echo "Skip segment_size: $seg_size (peb_size: $peb_size, pebs_per_seg: $pebs_per_seg)"
        continue
      fi

      nsegs=$[$volume_size/$seg_size]
      if [[ $nsegs -lt $min_segs ]]
      then
        echo "Skip segments_number: $nsegs (peb_size: $peb_size, pebs_per_seg: $pebs_per_seg)"
        continue
      fi

      echo "volume_size: $volume_size (peb_size: $peb_size, pebs_per_seg: $pebs_per_seg)"

      for (( i=0; i<${block_size_array_length}; i++ ));
      do

        logical_blks_per_peb=$[$peb_size/${block_size_number[$i]}]
        if [[ $logical_blks_per_peb -lt $min_logical_blks_per_peb ]]
        then
          echo "Skip logical_blks_per_peb: $logical_blks_per_peb (peb_size: $peb_size, page_size: ${block_size[$i]})"
          continue
        fi
        if [[ $logical_blks_per_peb -gt $max_logical_blks_per_peb ]]
        then
          echo "Skip logical_blks_per_peb: $logical_blks_per_peb (peb_size: $peb_size, page_size: ${block_size[$i]})"
          continue
        fi

        echo "CREATE: volume_size: $volume_size (page_size: ${block_size[$i]}, peb_size: $peb_size, pebs_per_seg: $pebs_per_seg)"

        image="./ssdfs-test-volume-"${block_size[$i]}"-"$peb_size"-"$pebs_per_seg".bin"

        echo "Create $image ..."
        dd if=/dev/zero of=$image bs=$seg_size count=1 || exit 1
        dd if=/dev/zero of=$image seek=$[$nsegs-2] bs=$seg_size count=1 || exit 1

        # cleanup if necessary
        umount $mount_point &>/dev/null
        modprobe -r ssdfs &>/dev/null
        sleep 0.25
        losetup -d $loop_device &>/dev/null
        sleep 0.25

        modprobe loop || exit 1
        losetup $loop_device $image || exit 1
        modprobe ssdfs || exit 1

        echo "Format $image ..."
        mkfs.ssdfs -p ${block_size[$i]} -e $peb_size -s $seg_size -L ssdfs-test $image || exit 1

        echo "Start testing ..."
        ./ssdfs_add_user_data_test4.sh $loop_device $mount_point 0 10 1000 16384
        ./ssdfs_read_md5_user_data.sh $loop_device $mount_point 0 10 1000
        ./ssdfs_update_user_data_test5.sh $loop_device $mount_point 0 10 1000 16384
        ./ssdfs_delete_file_test2.sh $loop_device $mount_point 0 10 1000

#        folder_name=${block_size[$i]}"-"$peb_size"-"$seg_size"-MOUNT-DUMP-0001"
#        mkdir $folder_name
#        chown -hR slavad $folder_name
#        cd $folder_name
#        dump.ssdfs -p parse_all,raw_dump -o ./ $1
#        cd ../

        echo "Format $image ..."
        mkfs.ssdfs -p ${block_size[$i]} -e $peb_size -s $seg_size -L ssdfs-test $image || exit 1

        echo "Start testing ..."
        ./ssdfs_add_user_data_test4.sh $loop_device $mount_point 0 100 1000 16384
        ./ssdfs_read_md5_user_data.sh $loop_device $mount_point 0 100 1000
        ./ssdfs_update_user_data_test5.sh $loop_device $mount_point 0 100 1000 16384
        ./ssdfs_delete_file_test2.sh $loop_device $mount_point 0 100 1000

#        folder_name=${block_size[$i]}"-"$peb_size"-"$seg_size"-MOUNT-DUMP-0002"
#        mkdir $folder_name
#        chown -hR slavad $folder_name
#        cd $folder_name
#        dump.ssdfs -p parse_all,raw_dump -o ./ $1
#        cd ../

        echo "Format $image ..."
        mkfs.ssdfs -p ${block_size[$i]} -e $peb_size -s $seg_size -L ssdfs-test $image || exit 1

        echo "Start testing ..."
        ./ssdfs_add_user_data_test4.sh $loop_device $mount_point 0 1000 1000 16384
        ./ssdfs_read_md5_user_data.sh $loop_device $mount_point 0 1000 1000
        ./ssdfs_update_user_data_test5.sh $loop_device $mount_point 0 1000 1000 16384
        ./ssdfs_delete_file_test2.sh $loop_device $mount_point 0 1000 1000

#        folder_name=${block_size[$i]}"-"$peb_size"-"$seg_size"-MOUNT-DUMP-0003"
#        mkdir $folder_name
#        chown -hR slavad $folder_name
#        cd $folder_name
#        dump.ssdfs -p parse_all,raw_dump -o ./ $1
#        cd ../

        echo "Format $image ..."
        mkfs.ssdfs -p ${block_size[$i]} -e $peb_size -s $seg_size -L ssdfs-test $image || exit 1

        echo "Start testing ..."
        ./ssdfs_add_user_data_test4.sh $loop_device $mount_point 0 10 1000 102400
        ./ssdfs_read_md5_user_data.sh $loop_device $mount_point 0 10 1000
        ./ssdfs_update_user_data_test5.sh $loop_device $mount_point 0 10 1000 102400
        ./ssdfs_delete_file_test2.sh $loop_device $mount_point 0 10 1000

#        folder_name=${block_size[$i]}"-"$peb_size"-"$seg_size"-MOUNT-DUMP-0004"
#        mkdir $folder_name
#        chown -hR slavad $folder_name
#        cd $folder_name
#        dump.ssdfs -p parse_all,raw_dump -o ./ $1
#        cd ../

        echo "Format $image ..."
        mkfs.ssdfs -p ${block_size[$i]} -e $peb_size -s $seg_size -L ssdfs-test $image || exit 1

        echo "Start testing ..."
        ./ssdfs_add_user_data_test4.sh $loop_device $mount_point 0 100 1000 102400
        ./ssdfs_read_md5_user_data.sh $loop_device $mount_point 0 100 1000
        ./ssdfs_update_user_data_test5.sh $loop_device $mount_point 0 100 1000 102400
        ./ssdfs_delete_file_test2.sh $loop_device $mount_point 0 100 1000

#        folder_name=${block_size[$i]}"-"$peb_size"-"$seg_size"-MOUNT-DUMP-0005"
#        mkdir $folder_name
#        chown -hR slavad $folder_name
#        cd $folder_name
#        dump.ssdfs -p parse_all,raw_dump -o ./ $1
#        cd ../

        echo "Format $image ..."
        mkfs.ssdfs -p ${block_size[$i]} -e $peb_size -s $seg_size -L ssdfs-test $image || exit 1

        echo "Start testing ..."
        ./ssdfs_add_user_data_test4.sh $loop_device $mount_point 0 1000 1000 102400
        ./ssdfs_read_md5_user_data.sh $loop_device $mount_point 0 1000 1000
        ./ssdfs_update_user_data_test5.sh $loop_device $mount_point 0 1000 1000 102400
        ./ssdfs_delete_file_test2.sh $loop_device $mount_point 0 1000 1000

#        folder_name=${block_size[$i]}"-"$peb_size"-"$seg_size"-MOUNT-DUMP-0006"
#        mkdir $folder_name
#        chown -hR slavad $folder_name
#        cd $folder_name
#        dump.ssdfs -p parse_all,raw_dump -o ./ $1
#        cd ../

        losetup -d $loop_device &>/dev/null
        sleep 0.25

        sudo rm $image
      done
    done
  done

  if [[ $volume_size -lt $volume_size_1gb_threshold ]]
  then
    volume_size=$[$volume_size+$volume_1gb_factor]
  elif [[ $volume_size -lt $volume_size_10gb_threshold ]]
  then
    volume_size=$[$volume_size+$volume_10gb_factor]
  else
    volume_size=$[$volume_size+$volume_100gb_factor]
  fi

done

exit 0

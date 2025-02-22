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
block_size_array_length=${#block_size[@]}

peb_size_min=131072
peb_size_max=$[4*1024*1024*1024]
pebs_per_segment_max=256
volume_size_max=$[18*1024*1024*1024*1024]
nsegs_max=150000000

for (( nsegs=16; nsegs<$nsegs_max; nsegs++ ));
do
  for (( pebs_per_seg=1; pebs_per_seg<$pebs_per_segment_max; pebs_per_seg++ ));
  do
    for (( peb_size=peb_size_min; peb_size<$peb_size_max; peb_size*2 ));
    do

      volume_size=$[$peb_size*$pebs_per_seg*$nsegs]
      if [[ $volume_size -gt $volume_size_max ]]
      then
        echo "Skip volume_size: $volume_size (peb_size: $peb_size, pebs_per_seg: $pebs_per_seg, nsegs: $nsegs)"
        continue
      fi

      for (( i=0; i<${block_size_array_length}; i++  ));
      do
        echo "CREATE: volume_size: $volume_size (peb_size: $peb_size, pebs_per_seg: $pebs_per_seg, nsegs: $nsegs)"

        image="./ssdfs-test-volume-"${block_size[$i]}"-"$peb_size"-"$nsegs".bin"

        echo "Create $image ..."
        sudo dd if=/dev/zero of=$image bs=$peb_size count=$[$pebs_per_seg*$nsegs] || exit 1

        echo "Format $image ..."
        seg_size=$[$peb_size*$pebs_per_seg]
        sudo mkfs.ssdfs -p ${block_size[$i]} -e $peb_size -s $seg_size -L ssdfs-test $image || exit 1

        folder_name=${block_size[$i]}"-"$peb_size"-"$seg_size"-"$nsegs"-MOUNT-DUMP"
        mkdir $folder_name
        chown -hR slavad $folder_name
        cd $folder_name
        dump.ssdfs -p parse_all,raw_dump -o ./ $image
        cd ../

        # cleanup if necessary
        umount $mount_point &>/dev/null
        modprobe -r ssdfs &>/dev/null
        sleep 0.25
        losetup -d $loop_device &>/dev/null
        sleep 0.25

        modprobe loop || exit 1
        losetup $loop_device $image || exit 1
        modprobe ssdfs || exit 1

        mount -t ssdfs $loop_device $mount_point || exit 1
        echo "Successfully mounted $image on $mount_point"

        # Add logic

        sudo umount $mount_point
        echo "Unmounted $mount_point"

        sudo rm $image
      done
    done
  done
done

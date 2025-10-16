#!/usr/bin/env bash

cwd=$(pwd)

# Defaults
VG=""
SCRIPTS=../scripts
RAW_MOUNT_OPTS="-t famfs -o noatime -o dax=always "
BIN=../debug
VALGRIND_ARG="valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes"
RMMOD=0
FAMFS_MOD="famfs.ko"

# Allow these variables to be set from the environment
if [ -z "$DEV" ]; then
    DEV="/dev/dax0.0"
fi
if [ -z "$MPT" ]; then
    MPT=/mnt/famfs
fi
if [ -z "$UMOUNT" ]; then
    UMOUNT="umount"
fi
if [ -z "${FAMFS_MODE}" ]; then
    FAMFS_MODE="v1"
fi

# Override defaults as needed
while (( $# > 0)); do
    flag="$1"
    shift
    case "$flag" in
	(-M|--module)
	    FAMFS_MOD=$1
	    shift
	    ;;
	(-d|--device)
	    DEV=$1
	    shift;
	    ;;
	(-b|--bin)
	    BIN=$1
	    shift
	    ;;
	(-s|--scripts)
	    SCRIPTS=$1
	    source_root=$1;
	    shift;
	    ;;
	(-m|--mode)
	    FAMFS_MODE="$1"
	    shift
	    ;;
	(-v|--valgrind)
	    # no argument to -v; just setup for Valgrind
	    VG=${VALGRIND_ARG}
	    ;;
	*)
	    echo "Unrecognized command line arg: $flag"
	    ;;

    esac
done

if [[ "$FAMFS_MODE" == "v1" || "$FAMFS_MODE" == "fuse" ]]; then
    echo "FAMFS_MODE: $FAMFS_MODE"
    if [[ "$FAMFS_MODE" == "fuse" ]]; then
        MOUNT_OPTS="--fuse" # Can drop this b/c fuse is the default
    else
        MOUNT_OPTS="--nofuse" # Can drop this b/c fuse is the default
    fi
else
    echo "FAMFS_MODE: invalid"
    exit 1;
fi

MOUNT="sudo $VG $BIN/famfs mount $MOUNT_OPTS"
MKFS="sudo $VG $BIN/mkfs.famfs"
CLI="sudo $VG $BIN/famfs"
CLI_NOSUDO="$VG $BIN/famfs"
TEST="test3"

source $SCRIPTS/test_funcs.sh
# Above this line should be the same for all smoke tests

set -x

# Start with a clean, empty file systeem
famfs_recreate "test3"

verify_mounted $DEV $MPT "test2.sh"

${CLI} creat -r -s 4096 -S 1 $MPT/ddtest    || fail "creat ddfile"
${CLI} verify -S 1 -f $MPT/ddtest           || fail "verify ddfile creat"
${CLI} cp $MPT/ddtest $MPT/ddtest_copy      || fail "copy ddfile should succeed"
sudo dd if=/dev/zero of=$MPT/ddtest bs=4096 count=1 conv=notrunc  || fail "dd into ddfile"
${CLI} verify -S 1 -f $MPT/ddtest           && fail "verify should fail after dd overwrite"
sudo dd of=/dev/null if=$MPT/ddtest bs=4096 || fail "dd out of ddfile"

#
# Test some cases where the kmod should throw errors because the famfs file is
# not in a valid state
#
sudo truncate $MPT/ddtest -s 2048
if (( $? == 0 )); then
    # This should be reconsidered when we no longer support kmods that
    # allow truncate XXX
    echo "--------------------------------------------"
    echo "This kernel allows truncate"
    echo "--------------------------------------------"
    assert_file_size "$MPT/ddtest" 2048 "bad size after rogue truncate"
    sudo dd of=/dev/null if=$MPT/ddtest bs=2048 \
	&& fail "Any read from a truncated file should fail"
    sudo truncate $MPT/ddtest -s 4096           \
	|| fail "truncate extra-hinky - back to original size"
    assert_file_size "$MPT/ddtest"  4096 "bad size after second rogue truncate"
    sudo dd of=/dev/null if=$MPT/ddtest bs=2048 \
	&& fail "Read from previously horked file should fail"
fi

# Test behavior of standard "cp" into famfs
# The create should succeed, but the write should fail, leaving an empty, invalid file
sudo cp /etc/passwd $MPT/pwd && fail "cp to famfs should fail due to invalid famfs metadata"
if [[ "${FAMFS_MODE}" == "v1" ]]; then
    test -f $MPT/pwd || fail "v1 cp should leave an invalid destination file"
    test -s $MPT/pwd && fail "file from cp should be empty"
    # Create an invalid file via "touch" and test behavior
    sudo touch $MPT/touchfile || fail "touch should succeed at creating an invalid file"
    sudo dd if=$MPT/touchfile && fail "dd from invalid file should fail"

    sudo truncate $MPT/touchfile -s 8192
    if (( $? == 0 )); then
	# This should be reconsidered when we no longer support kmods that
	# allow truncate XXX
	sudo dd if=$MPT/touchfile of=/dev/null bs=8192 count=1  \
	    && fail "dd from touchfile should fail"
	sudo dd if=/dev/zero of=$MPT/touchfile bs=8192 count=1  \
	    && fail "dd to touchfile should fail"
    fi
else
    test -f $MPT/pwd && fail "non-cli cp to famfs/fuse should fail outright"
    # Create an invalid file via "touch" and test behavior
    sudo touch $MPT/touchfile && fail "non-cli touch should fail in famfs/fuse"
    sudo dd if=$MPT/touchfile && fail "dd from missing file should fail"
fi

stat $MPT/ddtest

# Dump icache stats before umount
if [[ "$FAMFS_MODE" == "fuse" ]]; then
    # turn up log debug
    sudo curl  --unix-socket $(scripts/famfs_shadow.sh /mnt/famfs)/sock \
	 http://localhost/icache_stats
fi

# unmount and remount
sudo $UMOUNT $MPT || fail "umount"
findmnt -t famfs
verify_not_mounted $DEV $MPT "test3"
sleep 1
${MOUNT} $DEV $MPT
verify_mounted $DEV $MPT "test3 x"
findmnt -t famfs

sudo stat $MPT/ddtest

# Test that our invalid files from above are going after umount/mount
sudo test -f $MPT/touchfile           && fail "touchfile should have disappeared"
sudo test -f $MPT/pwd                 && fail "pwd file should have disappeared"
sudo test -f $MPT/ddtest              || fail "ddtest file should have reappeared and become valid again"

# Unmounting and remounting the file system should have restored the ddtest file's
# size after the rogue truncate above. Double check this

assert_file_size "$MPT/ddtest" 4096 "bad file size after remount"

${CLI} verify -S 1 -f $MPT/ddtest && fail "verify ddfile should fail since it was overwritten"
sudo dd conv=notrunc if=$MPT/ddtest_copy of=$MPT/ddtest bs=2048 || fail "dd contents back into ddfile"
${CLI} verify -S 1 -f $MPT/ddtest || fail "verify ddfile should succeed since contents put back"

${CLI} fsck $MPT || fail "fsck should succeed - no cross links yet"

mkdir -p ~/smoke.shadow
${CLI} logplay --shadow ~/smoke.shadow/test3.shadow $MPT

set +x
echo ":==*************************************************************************"
echo ":==test3 completed successfully"
echo ":==*************************************************************************"
exit 0

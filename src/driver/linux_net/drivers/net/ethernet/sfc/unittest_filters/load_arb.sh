#!/bin/sh

if [ -z "$1" ]
then
    echo "Usage: load_arb.sh <ethX>"
    exit 1
fi

insmod arb_filter_test_mod.ko "dev=$1"

MAJOR=`awk '/sfc_aftm$/{print $1;}' /proc/devices`
mknod /dev/sfc_aftm c ${MAJOR:-254} 0

#!/bin/bash
###############################################################################
# <L5_PRIVATE L5_SCRIPT>
#   Copyright: (c) Level 5 Networks Limited.
#      Author: slp
#     Started: 07/08/2002
# Description: Script to unload linux drivers and remove device nodes.
# </L5_PRIVATE>
###############################################################################

p=$(basename "$0")
bin=$(dirname "$0")

err  () { echo 1>&2 "$*";   }
log  () { err "$p: $*";     }
fail () { log "$*"; exit 1; }
try  () { "$@" || fail "ERROR: '$*' failed"; }

DIR=$(dirname "$0")
N_MODS="sfc sfc_ef100 sfc_driverlink"

usage () {
  err
  err "usage:  $p [options] [net]"
  err
  err "options:"
  err "  --hotplug     - Simulate hotplug event to reset MSI(X) vectors"
  err "  --debug       - verbose logging of commands"
  err
  exit 1
}

down () {
  ethif=$1

  if /sbin/ip link show dev "$ethif" >/dev/null 2>&1; then
    /sbin/ip link set dev "$ethif" down
  else
    log "$ethif is not configured."
  fi
}

do_fake_hotplug () {
  # This is so that MSI <-> MSI-X vectors can be swapped for ease of testing
  modprobe fakephp
  err "Faking hot-plug removal and insertion of SFC NIC"
  for DEV in $(grep -l 0x1924 /sys/bus/pci/devices/*.0/vendor | cut -d/ -f6) ; do
    if [ -f  /sys/bus/pci/slots/$DEV/power ]; then
      echo 0 > /sys/bus/pci/slots/$DEV/power
    else
      err "Couldn't fake hot plug for $DEV"
    fi
  done

  # Enable the root device. This has been overriden to re-enumerate all devices
  echo 1 > /sys/bus/pci/slots/0000:00:00.0/power 2> /dev/null
  modprobe -r fakephp
}

list_net_dev () {
  for dir in /sys/class/net/*; do
    if [ -L "$dir/device/driver" ]; then
      driver="$(basename "$(readlink "$dir/device/driver")")"
    elif [ -L "$dir/driver" ]; then
      driver="$(basename "$(readlink "$dir/driver")")"
    else
      continue
    fi
    if echo "$driver" | grep -q -x "${N_MODS/ /\|}"; then
      basename "$dir"
    fi
  done
}

donet () {
  for ethif in $(list_net_dev); do
    down $ethif
    [ ! -f /sys/class/net/$ethif/device/driver/unbind ] ||
      echo -n "$pci_dev" > /sys/class/net/$ethif/device/driver/unbind
  done

  for m in onload sfc_char sfc_resource sfc_affinity sfc_mtd sfc_control sfc_mdio_trace $N_MODS; do
    grep -q "^$m " /proc/modules && {
     echo "Removing $m driver"
      /sbin/rmmod "$m" || { log "rmmod $m failed (rc $?)"; bad=true; }
    }
  done

  rm -f /dev/sfc_tweak
}

###############################################################################
# main

[ `whoami` == "root" ] || fail "Please run as root"

bad=false
do_fake_hotplug=false

while [ $# -gt 0 ]; do
  case "$1" in
    --debug)	set -x;;
    --hotplug)  do_fake_hotplug=true;;
    -*)		usage;;
    *)		break;;
  esac
  shift
done

do_net=true

[ $# -gt 0 ] && {
  do_net=false;
  while [ $# -gt 0 ]; do
    case "$1" in
      net)	do_net=true;;
      *)	usage;;
    esac
    shift
  done
}

grep sfc_suspend /proc/modules >/dev/null
if [ $? == 0 ] ; then
   fail "Do not use unload.sh when sfc_suspend is loaded"
fi

# Doit!
$do_net && donet
$do_fake_hotplug && do_fake_hotplug

$bad && fail "Not all modules unloaded"
exit 0


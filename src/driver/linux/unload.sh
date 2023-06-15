#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.
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
. "$bin/shared.sh" || { echo >&2 "shared.sh missing"; exit 1; }

usage () {
  err
  err "usage:  $p [options] [char] [net]"
  err
  err "options:"
  err "  --hotplug     - Simulate hotplug event to reset MSI(X) vectors"
  err "  --debug       - verbose logging of commands"
  err
  exit 1
}

FUSER=/sbin/fuser
if [ ! -x $FUSER ]; then
  FUSER=/bin/fuser
fi

modusedby() {
  local mod="$1"
  local usedby="$2"
  /sbin/lsmod | grep -q "^$mod\>.*\<$usedby\>"
}

tryunload () {
  mod="$1"
  if isloaded "$mod"; then
    log "/sbin/rmmod $mod"
    [ -c "/dev/$mod" ] && $FUSER -k "/dev/$mod"
    # Find and kill users of onloadfs
    [ "$mod" = "onload" -a -x "$(which onload_fuser 2>/dev/null)" ] && onload_fuser -k
    # For extra reliability retry  once. Seen "ERROR: Module sfc is in use"
    /sbin/rmmod "$mod" || (sleep 5 && /sbin/rmmod "$mod") || { log "rmmod $mod failed ($?)"; bad=true; return 1; }
  fi
  if ! isdev "$mod"; then
    rm -f "/dev/$mod"
  fi
  return 0
}

dochar () {
  # kill onload_cp_server instance if any
  # note onload_fuser would only be able to do that
  # if /dev/onload still exists
  cat /proc/driver/onload/cp_server_pids 2>/dev/null | xargs -r kill

  # onload_helper is spawned from UL, so kernel does not have a list of
  # them.  Let's kill them by name!
  pkill -x onload_helper

  modusedby sfc_resource sfc_affinity &&
    tryunload sfc_affinity
  tryunload onload
  if ! isdev onload; then
    rm -f "/dev/onload_epoll"
  fi
  tryunload onload_cplane
  tryunload sfc_char
  tryunload sfc_resource
  tryunload sfc_affinity
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
    if echo $LINUX_NET | grep -wq "$driver"; then
      basename "$dir"
    fi
  done
}

donet () {
  LINUX_NET="sfc sfc_ef100"
  # Inform phychk (if listening)
  if anyloaded $LINUX_NET && pidof phychk >/dev/null 2>&1; then
    echo "DN" | nc localhost 11811 >/dev/null 2>&1
  fi

  for ethif in $(list_net_dev); do
    [ ! -f /sys/class/net/$ethif/device/driver/unbind ] ||
      echo -n "$pci_dev" > /sys/class/net/$ethif/device/driver/unbind
  done

  for m in sfc_mtd sfc_control sfc_mdio_trace $LINUX_NET virtual_bus sfc_driverlink; do
    tryunload "$m"
  done
  [ -f /dev/sfc_control ] || rm -f /dev/sfc_tweak
}


###############################################################################
# main

[ `whoami` = "root" ] || fail "Please run as root"

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

do_char=true
do_net=true

[ $# -gt 0 ] && {
  do_char=false; do_net=false;
  while [ $# -gt 0 ]; do
    case "$1" in
      char)	do_char=true;;
      net)	do_net=true;;
      *)	usage;;
    esac
    shift
  done
}

if isloaded sfc_suspend; then
  fail "ERROR: Do not use unload.sh when sfc_suspend is loaded"
fi

$do_char && dochar
$do_net && donet
$do_fake_hotplug && do_fake_hotplug
$bad && fail "Not all modules unloaded"
exit 0

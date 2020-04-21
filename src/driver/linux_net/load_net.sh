#!/bin/bash
###############################################################################
# <L5_PRIVATE L5_SCRIPT>
#   Copyright: (c) Level 5 Networks Limited.
#      Author: slp
#     Started: 07/08/2002
# Description: Script to load linux drivers and make device nodes.
# </L5_PRIVATE>
###############################################################################

shopt -s nullglob

allargs="$@"
p=$(basename "$0")
bin=$(dirname "$0")

err  () { echo 1>&2 "$*";   }
log  () { err "$p: $*";     }
fail () { log "$*"; exit 1; }
try  () { "$@" || fail "ERROR: '$*' failed"; }

DIR=$(dirname "$0")

NET_SUFFIX=("l" "m" "p" "q")  # textual suffixes for test networks

N_MODS="sfc_driverlink sfc sfc_ef100"

INTERRUPT_MODE=""
EEPROM_ARG=""
FLASH_ARG=""

NET_OPT=

if [ "$DATABASE_LOG" = "" ] ; then
   DATABASE_LOG=1
fi

usage () {
  err
  err "bad command line for linux_net/load.sh '$allargs'"
  err
  err "usage:  $p [options] [net|test]"
  err
  err "targets:          - If none are specified net drivers are loaded"
  err " net              - Load net driver"
  err " test             - Load net driver brainless"
  err
  err "configuration options"
  err "  -largeeeprom    - Force net driver to large-eeprom mode"
  err "  -smalleeprom    - Force net driver to small-eeprom mode"
  err "  -flash TYPE     - Force net driver to use given flash device type"
  err "  -noip           - don't assign IP addresses to interfaces"
  err "  -onlyip         - only assign IP addresses to interfaces"
  err "  -noifup         - don't bring the interfaces up"
  err "  -jumbo          - Set interface mtu to 9000"
  err "  -mtu <mtu>      - Set interface mtu to <mtu>"
  err "  -[no]dblog      - Post a record of the driver load to central database"
  err "  -noperrintr     - Disable fatal interrupts on mem parity errors"

  err
  err "net driver specific options:"
  err "  -netdebug       - Specify the NET driver debug level"
  err "  -allowload      - Ignore test failures during load"
  err "  -noselftest     - Don't do an offline self-test during load"
  err "  -nolro          - turn off Large Recieve Offload"
  err "  -noipp          - turn off ICMP/IGMP net->char passing"
  err "  -legacy         - (Falcon) Only allow legacy interrupts"
  err "  -msi            - (Falcon) Enable MSI interrupts"
  err "  -msix           - (Falcon) Enable MSI-X on all available CPU's"
  err "  -netparm        - Add a module parameter setting for net driver"
  err "  -suspend        - Load all devices suspended"
  err "  -writeallnv     - Allow write access to the flash/EEPROM"
  err "  -initnvconfig   - Prepare to write nvconfig and ignore current values"
  err "  -initphyflash   - Prepare to write PHY firmware and do not start PHY"

  err
  err "debug options"
  err "  --debug         - verbose logging of commands in this script"
  err
  exit 1
}

trylog() {
  tmpf=$(mktemp /tmp/tmp.XXXXXX)
  "$@" &>$tmpf
  rc=$?
  [ $rc = 0 ] || {
    cat $tmpf
    rm -f $tmpf
    fail "FAILED: $* (rc $rc)"
  }
  rm -f $tmpf
  return $rc
}

###############################################################################
# insert module for net device driver

hname () { hostname -s 2>/dev/null | sed 's/-\(.\|20\)$//'; }
hostip () { host -- "$1" | awk '/has address/{print $4}'; }
hostip6 () { host -t AAAA -- "$1" | awk '/has (AAAA|IPv6) address/{print $5}'; }

# A mount point has a different block device from its parent.
# (Unless it's the root directory, but we can ignore that here.)
is_mount_point () {
  test -d "$1" -a "$(stat -c %D "$1" 2>/dev/null)" != "$(stat -c %D "$1/.." 2>/dev/null)"
}


# NetworkManager runs DHCP on link-up and removes IP addrs on failure
# Match runbench prepare_machine.py::verify_dhcp_disabled()
disable_dhcp () {
  local intf="$1"
  local cfg_file="/etc/sysconfig/network-scripts/ifcfg-$intf"
  local using_nm=false

  [ $NO_IP_ADDR -eq 1 ] && return # don't interfer with runbench's use of load.sh

  (service NetworkManager status 2>&1 | egrep -qi '(started|running|active)') && using_nm=true

  if [ ! -f "$cfg_file" ]; then
     $using_nm || return # without NetworkManager, no cfgfile => unmanaged
     touch $cfg_file
  fi

  cp $cfg_file $cfg_file.new
  sed -nie '/DEVICE=/ n; /BOOTPROTO=/ n; /HWADDR=/ n; /ONBOOT/ n; /NM_CONTROLLED/ n; p' $cfg_file.new
  local hwaddr=$(cat /sys/class/net/$intf/address)

  cat >> $cfg_file.new <<EOF
DEVICE=$intf
BOOTPROTO=static
HWADDR=$hwaddr
ONBOOT=no
NM_CONTROLLED=no
EOF

  if ! cmp -s $cfg_file $cfg_file.new; then
    echo "Writing ifcfg-$intf then sleep 5 to allow NetworkManager to detect it  ..."
    mv $cfg_file.new $cfg_file
    sleep 5

    # bug 22617 - DHCP may have already started. NB dhclient is for RHEL
    if pkill -f "dhclient-$intf"; then
      echo "killing dhclient-$intf ..."
      sleep 2
      # Killing dhclient has been seen to leave the interface down
      ifconfig $intf up
    fi
  fi
}


donet () {
  PATH=/sbin:$PATH
  if $ONLY_IP; then
    true
  elif /sbin/lsmod | grep -q "^\(${N_MODS/ /\|}\)\>"; then
    echo "Module already loaded."
  else

    # Load NET driver
    # Don't use trylog here, and set -q: if these modules don't load then
    # they are built in to the kernel and we don't care that modprobe failed.
    /sbin/modprobe -q crc32
    /sbin/modprobe -q i2c-algo-bit
    /sbin/modprobe -q hwmon
    /sbin/modprobe -q hwmon-vid
    /sbin/modprobe -q mdio
    /sbin/modprobe -q 8021q
    # Kernel versions up to 2.6.22 inclusive have an 'mtdpart' module
    # needed for partition support.  From 2.6.23 this is combined
    # with other code into an 'mtd' module.  Or it might be built-in.
    /sbin/modprobe -q mtdpart || /sbin/modprobe -q mtd
    # We also want either mtdchar or mtdblock, but don't mind which.
    # Only try to load the mtdblock module if we know it is
    # hotplug-safe.  In kernel versions before 2.6.17 it will trigger
    # an oops in sysfs_remove_dir() when an MTD is removed.  In kernel
    # versions 2.6.26 and 2.6.27 (before 2.6.27.53) the bdi sysfs code
    # will trigger an oops if an mtdblock device is removed and
    # re-added.
    if ! /sbin/modprobe -q mtdchar; then
      if uname -r | egrep -q '^(2\.6\.(1[7-9]|2([0-58-9]|7\.(5[3-9]|[6789][0-9]))|[3-4][0-9])|[3-9]|[1-9][0-9])([^0-9]|$)'; then
	if ! /sbin/modprobe -q mtdblock; then
	  log "W: failed to load either mtdchar or mtdblock"
	fi
      else
	log "W: did not load mtdblock as it is not hotplug-safe on this kernel version"
      fi
    fi
    /sbin/modprobe -q ptp

    for m in $N_MODS; do
	test -f $DIR/$m.ko || continue
	# Only pass known options to the modules
	modinfo -F parm $DIR/$m.ko > /tmp/parm.$$
	echo "dyndbg: Dynamic module debugging" >> /tmp/parm.$$
	MOD_OPT=
	for option in $NET_OPT;
	do
	  grep -q "^${option%%=*}:" /tmp/parm.$$
	  if [ $? -eq 0 ];
	  then
	      MOD_OPT="$MOD_OPT $option";
	  else
	      echo "Module $m has no option ${option%%=*}, ignoring it";
	  fi
	done

        trylog /sbin/insmod $DIR/$m.ko $MOD_OPT
    done
    rm -f /tmp/parm.$$

    major=90
    # wait for any device nodes to be created
    sleep 0.5
    # udev may or may not create the device nodes for us
    # so use /proc/mtd to check what nodes should be created 
    # and make sure they are created
    i=0
    for F in _ `cat /proc/mtd | awk -F : '/mtd/ {print $1}'`; do
        [ $F = '_' ] && continue
        [ -c /dev/$F ] || try mknod /dev/$F c 90 $i
        i=`expr $i + 2`
    done
  fi

  # Find all interfaces created by driver
  declare -a interfaces
  for d in /sys/class/net/*; do
    driver="$(readlink "$d"/device/driver 2>/dev/null || readlink "$d"/driver)"
    if echo "$driver" | grep -qE "/${N_MODS/ /$|/}$"; then
      interfaces[${#interfaces[*]}]="$(basename "$d")"
    fi
  done
  if [ ${#interfaces[*]} -eq 0 ]; then
    if [ -z "`lspci -d 1924:`" ] && [ -z "`lspci -d 10ee:0100`" ]; then
      fail "no Solarflare NICs detected in this machine"
    else
      fail "driver failed to create any interfaces"
    fi
  fi

  # Sort by MAC address to give stable IPs (and match runbench behaviour)
  intf_by_mac="$(for i in "${interfaces[@]}"; do echo "$(cat /sys/class/net/$i/address) $i"; done | sort)"
  interfaces=($(echo "$intf_by_mac" | cut -d ' ' -f 2))

  # Sanity check that all interfaces have unique globally-assigned MAC addresses
  mac_dup="$(echo "$intf_by_mac" | cut -d ' ' -f 1 | uniq -d)"
  [ -z "${mac_dup}" ] || fail "Repeated MAC address(es) ${mac_dup}"
  mac_local=("$(echo "$intf_by_mac" | sed -n 's/^\(0[26ae].*\) \(.*\)/\1(\2)/p')")
  if [ -n "${mac_local[0]}" ]; then
      log "Locally-assigned MAC address(es)" ${mac_local[*]}
      log "Use ef10config to set a global MAC address pool for each board, e.g."
      log "    ef10config --mac_pool 00:0f:53:23:ef:10/4 ioctl=eth42"
      exit 1
  fi

  # Find driver debug dir
  if grep -q debugfs /proc/filesystems; then
    if is_mount_point /debug; then
      driver_debug_dir=/debug/sfc
    else
      driver_debug_dir=/sys/kernel/debug/sfc
      if ! is_mount_point /sys/kernel/debug; then
        mount -t debugfs debugfs /sys/kernel/debug
      fi
    fi
  fi
  if ! [ -d "$driver_debug_dir" ]; then
    echo "Warning: sfc driver debug dir not found"
  fi

  if [ $NO_IFUP -eq 0 ] ; then
      # bring up interfaces
      suffixindex=0

      houseeth=`route | grep "UG" | head -1 | awk 'NF>1{print $NF}'`
      houseip=`ifconfig $houseeth | grep -o "inet addr:[0-9.]\+"`
      houseip=${houseip##*:}
      housenetpf=$(/sbin/ip address show dev "$houseeth"  | grep inet | head -1)
      housenetpf=$(echo "$housenetpf" | egrep -o "/[0-9]+ " | sed 's+[/ ]++g')
      os=`uname -a`
      os=${os// /%20}
      for ethif in "${interfaces[@]}"; do
        disable_dhcp $ethif

        # Set an IP address using DNS for <host>-l/-m
        echo Bring up interface $ethif
        suffix="-"${NET_SUFFIX[$suffixindex]}
        suffix6="-6"${NET_SUFFIX[$suffixindex]}
        suffixindex=$(($suffixindex + 1))

	# Warn if there is a config file in place (might use DHCP and change routing on failure)
	ifcfg="/etc/sysconfig/network-scripts/ifcfg-$ethif"
	if [ -f "$ifcfg" ]; then
	    err "WARNING network interface configuration exists. Perhaps remove '$ifcfg'"
	fi

        if [ $NO_IP_ADDR -eq 0 ]; then
                myip=$(hostip $(hname)$suffix 2>/dev/null)
                myip6=$(hostip6 $(hname)$suffix6 2>/dev/null)
                if [ -z "$myip" ] ; then
                        err "DNS lookup for $(hname)$suffix failed"
                        err "Please run /sbin/ip addr add <IP>/$netpf brd + dev $ethif"
                else
			# Cambridge test networks are /21 blocks
			# within 172.16.128.0/19 and 172.16.160.0/21.
			# For any other address, assume the prefix
			# length matches the house interface.
			if [ "${myip#172.16.12[89].}" != "$myip" ] || \
			   [ "${myip#172.16.1[345][0-9].}" != "$myip" ] || \
			   [ "${myip#172.16.16[0-7].}" != "$myip" ]; then
				netpf=21
			else
				netpf=$housenetpf
			fi
                        /sbin/ip addr add "$myip/$netpf" brd + dev "$ethif"
                fi
                if [ -z "$myip6" ] ; then
                        err "DNS lookup for IPv6 addr failed for $(hname)$suffix6"
                else
                        modprobe ipv6
                        /sbin/ip addr add "$myip6/117" dev $ethif
                fi
        fi

        # Send to the database
        if [ "$DATABASE_LOG" = "1" ] ; then
		for host in boards-db.uk.solarflarecom.com 10.17.129.30; do
		    ping -c1 -w1 $host >/dev/null 2>&1 && break
		done
		if ! ping -c1 -w1 $host >/dev/null 2>&1; then
		    echo "Could not contact board database"
		    break 2
		fi
		
		# Gather data
		url="http://${host}/update/?host=$(hostname)"
	        mac=$(cat /sys/class/net/$ethif/address)
		url="${url}&mac=${mac}"
		slot=$(basename $(readlink -f /sys/class/net/$ethif/device))
		url="${url}&slot=${slot}"
		device=$(cat /sys/class/net/$ethif/device/device)
		url="${url}&device_id=${device}"
		vendor=$(cat /sys/class/net/$ethif/device/vendor)
		url="${url}&vendor_id=${vendor}"
		subsystem_device=$(cat \
		    /sys/class/net/$ethif/device/subsystem_device)
		url="${url}&ss_device_id=${subsystem_device}"
		subsystem_vendor=$(cat \
		    /sys/class/net/$ethif/device/subsystem_vendor)
		url="${url}&ss_vendor_id=${subsystem_vendor}"

		# Add VPD data if present
		vpddata=$(lspci -s ${slot} -vv | awk '
BEGIN		{ FS=":"; OFS="="; ORS="&" }
/Product Name/	{ gsub("+", "%2B", $2); print "product_name", substr($2, 2); }
/Part number/	{ print "part_number", substr($2, 2); }
/Serial number/	{ print "serial_number", substr($2, 2); }
/Engineering changes/	{ printf "engineering_changes=%s:%s", substr($2, 2), $3; }
')
		url="${url}&${vpddata}"

		# Upload to the database
                wget -q --timeout=10 -t 1 -O /dev/null "${url}" && \
		   echo "BoardDB update done for ${ethif}" || \
                   echo "WARN: BoardDB update failed. Please paste this into a browser to see the error '${url}'"
        fi
        /sbin/ip link set $ethif up mtu $mtu

        # The link-local address is probably harmless, but the user did say NOip...
        if [ $NO_IP_ADDR -eq 1 ]; then
          /sbin/ip addr flush $ethif
        fi

      done
  fi

  # Warn if the PCI-X chipset does not support MSI
  (lspci | grep "8131" > /dev/null) && {
    lspci -d 1924: -vvv 2>/dev/null | grep -qi express ||
      err "WARNING: AMD 8131 PCI-X tunnel present. MSI for PCI-X cards will" \
          "be broken!"
  }

  # Check that the kernel is configured for MSI
  kver=`uname -r`
  if [ -f "/boot/*/config-$kver" ]; then
    grep -qs 'CONFIG_PCI_MSI=y' /boot/*/config-${kver} || \
      err "MSI support might not be compiled in this kernel"
  fi
  if [ -f "/boot/config-$kver" ]; then
    grep -qs 'CONFIG_PCI_MSI=y' /boot/config-${kver} || \
      err "MSI support might not be compiled in this kernel"
  fi
  if [ -f "/proc/kallsyms" ]; then
    grep -qs pci_enable_msi /proc/kallsyms || \
      err "Running kernel does not appear to support MSI"
  fi

  # Print out any config info that we can
  # Don't assume the nic_* or if_* symlinks exist (debugfs doesn't support
  # them before 2.6.21)
  if [ -d "$driver_debug_dir" ]; then
      for n in "$driver_debug_dir"/cards/*; do
	  echo -n $(cat "$n"/name)
	  echo -n " is: "
	  cat "$n"/hardware_desc
	  echo
	  echo -n "Interrupt mode is:  "
	  cat "$n"/interrupt_mode
      done
  fi
}


###############################################################################
# main()

[ `whoami` == "root" ] || fail "Please run as root"

DOMAIN=`domainname`
if [ "$DOMAIN" = "uk.solarflarecom.com" ]; then
    NO_IP_ADDR=0
elif [ "$DOMAIN" = "uk.level5networks.com" ]; then
    NO_IP_ADDR=0
elif [ "$DOMAIN" = "sfnd" ]; then
    NO_IP_ADDR=0
else
    NO_IP_ADDR=1
fi
NO_IFUP=0
ONLY_IP=false
mtu=1500
unload=true

while [ $# -gt 0 ]; do
  case "$1" in
    -nounload)  unload=false;;
    -noip)      NO_IP_ADDR=1;;
    -onlyip)    unload=false; DATABASE_LOG=0; ONLY_IP=true;;
    -noifup)    NO_IFUP=1;;
    -jumbo)	mtu=8982;;
    -mtu)	mtu="$2"; shift;;
    -dblog)     DATABASE_LOG=1 ;;
    -nodblog)   DATABASE_LOG=0 ;;
    -largeeeprom) EEPROM_ARG="eeprom_type=1" ;;
    -smalleeprom) EEPROM_ARG="eeprom_type=0" ;;
    -flash)     FLASH_ARG="flash_type=$2"; shift;;
    -writeallnv) NET_OPT="$NET_OPT efx_allow_nvconfig_writes=1" ;;
    -initnvconfig)
	NET_OPT="$NET_OPT efx_allow_nvconfig_writes=1"
	test -n "$EEPROM_ARG" || EEPROM_ARG="eeprom_type=0"
	test -n "$FLASH_ARG" || FLASH_ARG="flash_type=0x080f52d1"
	NO_IFUP=1 ;;
    -initphyflash)
	NET_OPT="$NET_OPT phy_flash_cfg=1"
	NO_IFUP=1 ;;
    -allowload | -allowload2 | -noselftest | -notune | -tuneparm)
		err "WARNING: $1 no longer has any effect" ;;
    -nolro)	NET_OPT="$NET_OPT lro=0";;
    -legacy)    INTERRUPT_MODE="interrupt_mode=2";;
    -msi)	INTERRUPT_MODE="interrupt_mode=1";;
    -msix)      INTERRUPT_MODE="interrupt_mode=0";;
    -netparm)	NET_OPT="$NET_OPT $2"; shift;;
    --debug)	set -x;;
    -*)		usage;;
    *)		break;;
  esac
  shift
done

[ $# -gt 1 ] && usage

# By default we unload before loading, to ensure that the user gets the
# driver they're expecting.  (This is important because some kernels
# include a version of our sfc driver, so we need to remove it by default).
$unload && { "$bin/unload.sh" || exit; }

#
# Add NIC / driver specific options
NET_OPT="$NET_OPT $INTERRUPT_MODE $EEPROM_ARG $FLASH_ARG"

if [ $# = 0 ]; then
  donet
elif [ "$1" = net ]; then
  shift
  donet
elif [ "$1" = test ]; then
  shift
  NO_IP_ADDR=1
  donet
else
  usage
fi

exit 0

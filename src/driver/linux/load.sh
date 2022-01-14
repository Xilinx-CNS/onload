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
. "$bin/shared.sh" || { echo >&2 "shared.sh missing"; exit 1; }

NET_SUFFIX=("l" "m" "p" "q")  # textual suffixes for test networks

NET_INTERRUPT_MODE=
EEPROM_ARG=
FLASH_ARG=
NET_OPT=
CHAR_OPT=
LOAD_CONFIG=false
PROBE_CP_SERVER_PATH=true
LINUX_NET="sfc"


usage () {
  err 
  err "bad command line for linux/load.sh '$allargs'"
  err
  err "usage:  $p [options] [targets]"
  err
  err "targets:          - If none are specified net driver is loaded"
  err "  net             - Load net driver"
  err "  res             - Load net and resource drivers"
  err "  onload          - Load drivers needed for onload"
  err "  [net]char       - Load drivers needed for char access"
  err "  mknod           - Create /dev/* nodes for char and onload"
  err "  onload_xdp      - Load onload and register SFC interfaces as af_xdp ones"
  err
  err "configuration options"
  err "  -char           - Load sfc_char module (where available)"
  err "  -noconfig       - Don't attempt to configure driver after load"
  err "  -noconfigspec   - Use no configuration file - accelerates all apps"
  err "  -safeconfig     - Use safe configuration - should disable acceleration"
  err "  -largeeeprom    - Force net driver to large-eeprom mode"
  err "  -smalleeprom    - Force net driver to small-eeprom mode"
  err "  -flash TYPE     - Force net driver to use given flash device type"
  err "  -nomtd          - If mtd driver is built DO NOT load mtd driver"
  err "  -myconfig <cfg> - Use owner's configuration file <cfg>"
  err "  -onloadcfg <cmd> - Use <cmd> instead of onloadcfg"
  err "  -a              - Use arp module (default state)"
  err "  -noip           - don't assign IP addresses to interfaces"
  err "  -noifup         - don't bring the interface(s) up"
  err "  -jumbo          - Set interface mtu to 9000"
  err "  -mtu <mtu>      - Set interface mtu to <mtu>"
  err
  err "resource driver specific options:"
  err "  -irqmodc <val>  - char driver int moderation (in usec)"
  err "  -noirq          - request no irq (resource only)"
  err "  -pause <pause>  - Pause frame duration"
  err
  err "onload driver specific options:"
  err "  -oo_bits <val>  - Set debug_bits module option (val in hex - start with 0x)"
  err "  -oo_cbits <val> - Set code_bits module option (val in hex - start with 0x)"
  err "  -noct           - don't support close trampolines"
  err "  -nosspanic      - don't crash if shared state is corrupted"
  err "  -noipp          - turn off ICMP/IGMP net->onload passing"
  err
  err "net driver specific options:"
  err "  -netdebug       - Specify the NET driver debug level"
  err "  -noresets       - Net driver will not reset the HW"
  err "  -allowload      - Ignore test failures during load"
  err "  -noselftest     - Don't do an offline self-test during load"
  err "  -nolro          - turn off Large Recieve Offload"
  err "  -netparm        - Add a module parameter setting for net driver"
  err "  -charparm       - Add a module parameter setting for char driver"
  err "  -suspend        - Suspend all interfaces by default"
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
    fail "FAILED: $*"
  }
  rm -f $tmpf
  return $rc
}

startcmd() {
  echo "$DONE" | grep -qw "$1" && return 0
  DONE="$DONE $1"
  return 1
}

loadmod() {
  local m="$1"
  shift 1
  if isloaded "$m"; then
    echo "$m is already loaded"
  elif ! [ -f "$DIR/$m.ko" ]; then
    echo "ERROR: $m.ko not built"
    exit 1
  elif ! /sbin/insmod "$DIR/$m.ko" "$@"; then
    exit
  fi
  return 0
}

getmajor() {
  grep -w "$1" /proc/devices | awk '{ print $1 }'
}

domknod () {
  local path="$1"
  local major="$2"
  local minor="$3"
  local perm="$4"

  try rm -f "$path"
  try mknod -m "$perm" "$path" c "$major" "$minor"
  [ -x /sbin/restorecon ] && /sbin/restorecon "$path"
}

mknod_for_drv() {
  local name="$1"
  local dev="$1"
  local perm="$2"
  local major=$(getmajor "$name")
  if ! [ -n "$major" ]; then
    err "ERROR: Did not find $name in /proc/devices"
  else
    domknod "/dev/$dev" "$major" 0 "$perm"
  fi
}

get_cp_server_path() {
  # The path defaults to /sbin/onload_cp_server, so we need to fix this up when
  # loading from a developer build.
  echo "${EF_BUILDTREE_UL}/tools/cplane/onload_cp_server"
}


######################################################################

dores () {
  donet
  startcmd res && return 0

  # linux may load alien sfc_resource for PCI VFs
  # if sfc_resource is installed in standard /lib/modules
  if $unload; then
    if /sbin/lsmod | grep -q "^sfc_resource\>"; then
      log "/sbin/rmmod sfc_resource"
      /sbin/rmmod sfc_resource
    fi
  fi

  echo "RESOURCE_OPT is $R_MOD_ARGS"
  loadmod sfc_resource $R_MOD_ARGS
}


dochar () {
  dores
  startcmd char && return 0

  echo "CHAR_OPT is $CHAR_OPT"
  loadmod sfc_char $C_MOD_ARGS
}


doonload () {
  dochar
  startcmd onload && return 0

  # Add default cplane parameters.  If user provides the same parameters
  # via ONLOAD_OPT, then user's values win, because the deafult parameters
  # are added to the beginning of the command line.
  echo "ONLOAD_OPT is $ONLOAD_OPT"
  $PROBE_CP_SERVER_PATH && \
    O_MOD_ARGS="cplane_server_path=$(get_cp_server_path) cplane_server_params=-K ${O_MOD_ARGS}"

  # For developers we'd like to set cplane_track_xdp on all the kernels
  # which support it.  Unfortunately RHEL7 (linux-3.10) is unable to ignore
  # an unknown parameter.
  if nm $DIR/onload.ko |grep -q -w cplane_track_xdp; then
    O_MOD_ARGS="cplane_track_xdp=yes ${O_MOD_ARGS}"
  fi
  loadmod onload $O_MOD_ARGS
  $LOAD_CONFIG && doonloadconfig
}

doxdp () {
  O_MOD_ARGS="${O_MOD_ARGS} oof_shared_keep_thresh=0"
  R_MOD_ARGS="${R_MOD_ARGS} enable_driverlink=0"
  doonload

  (
    # BPF requires this for linux<5.11
    # We are increasing the ulimit in subshell, so it does not affect the
    # caller
    ulimit -l unlimited

    for ethif in $(get_interfaces); do
      echo $ethif >/sys/module/sfc_resource/afxdp/register
      echo "Register $ethif in sfc_resource/afxdp"
    done
  )
}

###############################################################################
# insert module for net device driver

hname () { hostname -s 2>/dev/null | sed 's/-.$//'; }
hostip () { host -- "$1" | awk '/has address/{print $4}'; }
hostip6 () { host -t AAAA -- "$1" | awk '/has (AAAA|IPv6) address/{print $5}'; }

# A mount point has a different block device from its parent.
# (Unless it's the root directory, but we can ignore that here.)
is_mount_point () {
  test -d "$1" -a "$(stat -c %D "$1" 2>/dev/null)" != "$(stat -c %D "$1/.." 2>/dev/null)"
}

# Find all interfaces created by driver
get_interfaces() {
  declare -a interfaces
  for d in /sys/class/net/*; do
    driver="$(readlink "$d"/device/driver/module)"
    for m in $LINUX_NET; do
        if [ "${driver%/"$m"}" != "$driver" ]; then
          interfaces[${#interfaces[*]}]="$(basename "$d")"
        fi
    done
  done

  echo "${interfaces[@]}"
}

donet () {
  startcmd net && return 0

  echo "NET_OPT is $NET_OPT"
  echo "CHAR_OPT is $CHAR_OPT"

  PATH=/sbin:$PATH
  if anyloaded $LINUX_NET; then
    echo "Net driver already loaded."
  else
    # Don't use trylog here, and set -q: if these modules don't load then
    # they are built in to the kernel and we don't care that modprobe failed.
    /sbin/modprobe -q mii
    /sbin/modprobe -q crc32
    # Load inet_lro for generic LRO support, if possible.
    /sbin/modprobe -q inet_lro
    /sbin/modprobe -q i2c-algo-bit
    /sbin/modprobe -q hwmon
    /sbin/modprobe -q hwmon-vid
    /sbin/modprobe -q mdio
    /sbin/modprobe -q 8021q
    /sbin/modprobe -q ptp
    /sbin/modprobe -q mtd
    # We also want either mtdchar or mtdblock, but don't mind which.
    /sbin/modprobe -q mtdchar || /sbin/modprobe -q mtdblock
    modprobe -q vdpa
    # ef100 support requires nf_flow_table if it is configured in
    modprobe nf_flow_table

    # Coverage
    for m in $LINUX_NET; do
        dogcov $DIR/$m.ko
    done

    # Tell phychk (if it is listening)
    pidof phychk > /dev/null 2>&1
    if [ $? == 0 ]; then
	echo "UP" | nc localhost 11811 > /dev/null 2>&1
    fi

    # Net driver
    loadmod sfc_driverlink
    loadmod virtual_bus
    for m in $LINUX_NET; do
      loadmod $m $N_MOD_ARGS
    done

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
    echo "Warning: sfc driver debug dir not found in procfs or debugfs"
  fi

  if $IFUP; then
      # bring up interfaces
      suffixindex=0

      houseeth=$(route -n | grep "UG" | head -1 | awk 'NF>1{print $NF}')
      houseip=$(ifconfig $houseeth | grep -o "inet addr:[0-9.]\+")
      houseip=${houseip##*:}
      netpf=$(/sbin/ip address show dev "$houseeth"  | grep inet | head -1)
      netpf=$(echo "$netpf" | egrep -o "/[0-9]+ " | sed 's+[/ ]++g')
      os=`uname -a`
      os=${os// /%20}
      for ethif in $(get_interfaces); do
        # Set an IP address using DNS for <host>-l/-m
        echo Bring up interface $ethif
        suffix="-"${NET_SUFFIX[$suffixindex]}
        suffix6="-6"${NET_SUFFIX[$suffixindex]}
        suffixindex=$(($suffixindex + 1))
        myip=$(hostip $(hname)$suffix)
        myip6=$(hostip6 $(hname)$suffix6)

	# Warn if interface is configured to use DHCP at boot time.
	ifcfg="/etc/sysconfig/network-scripts/ifcfg-$ethif"
	if grep -q BOOTPROTO=dhcp "$ifcfg" &>/dev/null && \
           ! grep -q ONBOOT=no "$ifcfg" &>/dev/null; then
	    err "WARNING: '$ifcfg' is setup to use DHCP at boot time."
	fi

        if [ $NO_IP_ADDR -eq 0 ]; then
                if [ -z "$myip" ] ; then
                        err "DNS lookup for $(hname)$suffix failed"
                        err "Please run /sbin/ip addr add <IP>/$netpf brd + dev $ethif"
                else
                        /sbin/ip addr add "$myip/$netpf" brd + dev "$ethif"
                fi
                if [ -z "$myip6" ] ; then
                        err "DNS lookup for IPv6 addr failed for $(hname)$suffix6"
                else
                        modprobe ipv6
                        /sbin/ip addr add "$myip6/117" dev $ethif
                fi
        fi

        /sbin/ip link set $ethif up mtu $mtu

        # The link-local address is probably harmless, but the user did say NOip...
        if [ $NO_IP_ADDR -eq 1 ]; then
          /sbin/ip addr flush $ethif
        fi

        if which cmdclient &> /dev/null
        then
          if cmdclient --sync -q -c "straps;q" ioctl=$ethif 2> /dev/null | grep -q "Alternative.*MADE"
          then
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo "Alternate DBI settings are active.  Is that really what you want?"
          fi
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

  for m in $LINUX_NET; do
      if nm $DIR/$m.ko | grep -q __efx_enable_debug; then
          echo "$m is a DEBUG driver"
      else
          echo "$m is a RELEASE driver"
      fi
  done

  # Make sure alternate DBI is not set
        
  # Add to database
  [ "$SETUP_UL_APPLOG" = "yes" ] && dologsetup
}

_get_interrupt_count() {
    local output="`cat /proc/interrupts`"
    # how many cpu's are there?
    local cpu_count=`echo "$output" | head -1 | wc -w`
    for key in $1; do
	local i=0
	local sum=0
	for field in `echo "$output" | grep $key`; do
	    i=`expr $i + 1`
	    [ $i = 1 ] && continue
	    [ $i -gt $cpu_count ] && break
	    sum=`expr $sum + $field`
	done
	echo $key $sum
    done
}

dogcov() {
    # is the gcov module needed? If not, don't load it
    GCOV_NEEDED=false
    for m in $LINUX_NET; do
	if /usr/bin/nm $DIR/$m.ko | grep -q gcov; then
	    GCOV_NEEDED=true
	fi
    done
    if $GCOV_NEEDED; then
	# if it's already loaded the leave it loaded
	if ! isloaded sfc_gcov; then
	    # load it. It it fails then the net driver won't load
	    # anyway
            # Do not trylog -- it beaks OKTET Labs TCE!
	    (loadmod sfc_gcov gcov_persist=1)
	fi
    fi
}

###############################################################################
# load configuration database

LOAD_NOCONFIG=false
SUBDIR_CONFIG="distfiles/efabcfg"

# Try to find the top of the tree, and put the scripts directory on the
# path.  This is where it should be if load.sh is in a build tree.
ef_scripts="$bin/../../../../scripts"
# And here is where is should be if load.sh is in the source tree.
[ -d "$ef_scripts" ] || ef_scripts="$bin/../../../scripts"
[ -d "$ef_scripts" ] && {
  EF_TREE=$(cd "$ef_scripts/.." >/dev/null && pwd)
  export PATH="$EF_TREE/scripts:$PATH"
}

# If user uses a non-standard UL build directory, then he probably sets
# $ONLOAD_PRELOAD to point to the correct location.  Let's try to find out
# the name of the UL build directory from the $ONLOAD_PRELOAD.
[ -z "$EF_BUILDTREE_UL" -a -n "$ONLOAD_PRELOAD" ] && {
  EF_BUILDTREE_UL=${ONLOAD_PRELOAD%/lib/transport/unix/libcitransport0.so}
  [ $EF_BUILDTREE_UL = $ONLOAD_PRELOAD ] && EF_BUILDTREE_UL=
}
[ -z "$EF_BUILDTREE_UL" ] && {
  if which mmaketool &>/dev/null; then
    # move into our directory first so mmaketool is in the tree
    EF_BUILDTREE_UL="$EF_TREE/build/$(cd $bin>/dev/null && mmaketool --userbuild)"
  else
    err "WARNING: mmaketool is not on the path.  This is strange."
    err "EF_TREE=$EF_TREE"
    err "PATH=$PATH"
  fi
}


CMD_EFABCFG=

# by default we use the configuration files we'll distribute to users
CONFIG_OWNER=       # the file the user can tweak
CONFIG_DRIVER=      # the file Level 5 distributes with the driver
CONFIG_DISABLE=     # a driver configuration file that disables all apps
if [ ! -z "$EF_TREE" ]; then
    if [ -r "$EF_TREE/$SUBDIR_CONFIG/owner_empty.cfg" ]; then
        CONFIG_OWNER="$EF_TREE/$SUBDIR_CONFIG/owner_empty.cfg"
    fi
    if [ -r "$EF_TREE/$SUBDIR_CONFIG/unix/driver.cfg" ]; then
        CONFIG_DRIVER="$EF_TREE/$SUBDIR_CONFIG/unix/driver.cfg"
    fi
    if [ -r "$EF_TREE/$SUBDIR_CONFIG/owner_empty.cfg" ]; then
        CONFIG_DISABLE="$EF_TREE/$SUBDIR_CONFIG/driver_disable.cfg"
    fi
fi

doonloadconfig()
{   local rc=
    if [ -z "$CMD_EFABCFG" -a ! -z "$EF_BUILDTREE_UL" ]; then
       CMD_EFABCFG="$EF_BUILDTREE_UL/tools/efabcfg/onloadcfg"
    fi
    if [ -z "$CMD_EFABCFG" ]; then
        fail "'onloadcfg' location unknown - set EF_BUILDTREE_UL? or use option -onloadcfg?"
	rc=1
    elif $LOAD_NOCONFIG; then
	if $CMD_EFABCFG --noconfig; then
	   rc=
	else
	   rc=$?
	fi
    else
	if [ -z "$CONFIG_OWNER" ]; then
	   fail "can't find an owner's configuration file (normally in $SUBDIR_CONFIG)"
	elif [ -z "$CONFIG_DRIVER" ]; then
	   fail "can't find a driver configuration file (normally in $SUBDIR_CONFIG/unix)"
	else
	    if $CMD_EFABCFG -g "$CONFIG_DRIVER" "$CONFIG_OWNER"; then
	       rc=
	    else
	       rc=$?
	    fi
	fi
    fi
    if [ -z "$rc" ]; then
       echo "Driver configured"
    else
	# NB: these error codes need to be kept in sync with their definition
	#     in src/tools/efabcfg/efabcfg.c
	case "$rc" in
	    10)  # didn't find onloadcfg
	         err="where is 'onloadcfg'?";;
	    141) # EFABCFG_EXIT_ARGS
		 err="failed to parse command line arguments";;
	    142) # EFABCFG_EXIT_NOCMDS
		 err="internal error - didn't start up";;
	    143) # EFABCFG_EXIT_DRIVER
		 err="EtherFabric driver didn't open";;
	    144) # EFABCFG_EXIT_PROLOG_BUILTIN
		 err="error in internal prolog script";;
	    145) # EFABCFG_EXIT_PROLOG_FILE
		 err="error in external prolog script";;
	    146) # EFABCFG_EXIT_FILE_OPEN
		 err="couldn't open configuration file";;
	    147) # EFABCFG_EXIT_FILE_EXEC
		 err="failed to execute configuration file";;
	    148) # EFABCFG_EXIT_EPILOG_BUILTIN
		 err="error in internal epilog script";;
	    149) # EFABCFG_EXIT_CMD_ERRORS
		 err="error in configuration specification";;
	    *)
		 err="not built? (-noconfig omits config step)";;
	esac
	fail "onloadcfg failed (rc $rc) - $err"
    fi
}



###############################################################################
# set up logging files

SETUP_UL_APPLOG="yes"
APPLOG_FILE="/var/log/etherfabric_users"

dologsetup()
{   touch "$APPLOG_FILE"
    chmod a+w "$APPLOG_FILE"
}


###############################################################################
# main()

if [ "`dnsdomainname`" = "uk.solarflarecom.com" ] ||
   [ "`dnsdomainname`" = "uk.level5networks.com" ] ||
   [ "`dnsdomainname`" = "xcblab.xilinx.com" ]; then
    NO_IP_ADDR=0
else
    NO_IP_ADDR=1
fi
IFUP=true
mtu=1500
unload=true

while [ $# -gt 0 ]; do
  case "$1" in
    -nounload)
		unload=false;;
    -onloadconfig)
		LOAD_CONFIG=true;;
    -noonloadconfig)
		LOAD_CONFIG=false;;
    -onloadnoconfigspec)
		LOAD_CONFIG=true; LOAD_NOCONFIG=true;;  
    -probecpserverpath)
		PROBE_CP_SERVER_PATH=true;;
    -noprobecpserverpath)
		PROBE_CP_SERVER_PATH=false;;
    -onloadsafeconfig)
		CONFIG_OWNER="/dev/null"; CONFIG_DRIVER="$CONFIG_DISABLE";;
    -myconfig)	CONFIG_OWNER="$2"; shift;;  
    -onloadcfg)	CMD_EFABCFG="$2"; shift;;
    -oo_bits)   ONLOAD_OPT="$ONLOAD_OPT oo_debug_bits=$2"; shift;;
    -noct)      ONLOAD_OPT="$ONLOAD_OPT no_ct=1";;
    -nosspanic) ONLOAD_OPT="$ONLOAD_OPT no_shared_state_panic=1" ;;
    -noipp)	ONLOAD_OPT="$ONLOAD_OPT use_ipp_redirect=0" ;;

    -noip)      NO_IP_ADDR=1;;
    -noifup)    IFUP=false;;
    -jumbo)	mtu=8982;;
    -mtu)	mtu="$2"; shift;;
    -largeeeprom) EEPROM_ARG="eeprom_type=1" ;;
    -smalleeprom) EEPROM_ARG="eeprom_type=0" ;;
    -flash)     FLASH_ARG="flash_type=$2"; shift ;;
    -ignorebadnv) NET_OPT="$NET_OPT efx_ignore_nvconfig=1" ;;
    -writeallnv) NET_OPT="$NET_OPT efx_allow_nvconfig_writes=1" ;;
    -initnvconfig)
	NET_OPT="$NET_OPT efx_ignore_nvconfig=1"
	NET_OPT="$NET_OPT efx_allow_nvconfig_writes=1"
 	test -n "$EEPROM_ARG" || EEPROM_ARG="eeprom_type=0"
 	test -n "$FLASH_ARG" || FLASH_ARG="flash_type=0x080f52d1"
	IFUP=false;;
    -initphyflash)
	NET_OPT="$NET_OPT phy_flash_cfg=1"
	IFUP=false;;
    -allowload | -allowload2 | -noselftest)
		err "WARNING: $1 no longer has any effect" ;;
    -nolro)	NET_OPT="$NET_OPT lro=0";;
    -netparm)	NET_OPT="$NET_OPT $2"; shift;;
    -charparm)	CHAR_OPT="$CHAR_OPT $2"; shift;;
    --debug)	set -x;;
    -*)		usage;;
    *)		break;;
  esac
  shift
done


# Add NIC / driver specific options
ONLOAD_OPT="$ONLOAD_OPT"
NET_OPT="$NET_OPT $NET_INTERRUPT_MODE $EEPROM_ARG $FLASH_ARG"

# Set up default module arguments, for most cases below
N_MOD_ARGS="$NET_OPT"
C_MOD_ARGS="$CHAR_OPT"
R_MOD_ARGS="$RESOURCE_OPT"
CP_MOD_ARGS="$CPLANE_OPT"
O_MOD_ARGS="$ONLOAD_OPT"
DONE=

# By default we unload before loading, to ensure that the user gets the
# driver they're expecting.  (This is important because some kernels
# include a version of our sfc driver, so we need to remove it by default).
$unload && { "$bin/unload.sh" || exit; }

if [ $# = 0 ]; then
  donet
else
  while [ $# -gt 0 ]; do
    case "$1" in
    net)	
      donet
      ;;
    char|netchar)
      dochar
      ;;
    res|netres)
      dores
      ;;
    onload)
      doonload
      ;;
    mknod)
      mknod_for_drv sfc_char 0666
      mknod_for_drv onload 0666
      mknod_for_drv onload_epoll 0666
      ;;
    onload_xdp)
      doxdp
      ;;
    *)
      err "arg = $1"
      usage
      exit 0;;
    esac
    shift
  done
fi

exit 0

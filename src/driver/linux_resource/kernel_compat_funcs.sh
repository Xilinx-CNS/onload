#!/bin/bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2019 Xilinx, Inc.

######################################################################
#
# Driver for Solarflare network controllers and boards
# Copyright 2019 Solarflare Communications Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, incorporated herein by reference.
#
######################################################################

err  () { echo >&2 "$*";    }
log  () { err "$me: $*";    }
vlog () { $efx_verbose && err "$me: $*"; }
fail () { log "$*"; exit 1; }
try  () { "$@" || fail "'$*' failed"; }
vmsg () { $efx_quiet || log "$@"; }

function usage()
{
    err
    err "usage:"
    err "  $me [options] <symbol1> <symbol2>"
    err
    err "description:"
    err "  Produce a list of kernel compatability macros to match the "
    err "  kernel_compat.c and kernel_compat.h files"
    err
    err "options:"
    err "  -k KPATH        -- Specify the path to the kernel build source tree"
    err "                     defaults to /lib/modules/VERSION/build"
    err "  -o PATH         -- Specify the output directory, if any"
    err "                     defaults to KPATH"
    err "  -r VERSION      -- Specify the kernel version instead to test"
    err '                     defaults to `uname -r`'
    err "  -a ARCH         -- Set the architecture to ARCH"
    err "                     defaults to `uname -m`"
    err "  -m MAP          -- Specify a System map for the build kernel."
    err "                     By default will look in KPATH and /boot"
    err "  -q              -- Quieten the checks"
    err "  -v              -- Verbose output"
    err "  -s              -- Symbol list to use"
    err "  <symbol>        -- Symbol to evaluate."
    err "                     By default every symbol is evaluated"

}

######################################################################
# Generic methods for standard symbol types

# Look for up to 3 numeric components separated by dots and stop when
# we find anything that doesn't match this.  Convert to a number like
# the LINUX_VERSION_CODE macro does.
function string_to_version_code
{
    local ver="$1"
    local code=0
    local place=65536
    local num

    while [ -n "$ver" ]; do
	# Look for numeric component; if none found then we're done;
	# otherwise add to the code
	num=${ver%%[^0-9]*}
	test -n "$num" || break
	code=$((code + $num * $place))

	# If this was the last component (place value = 1) then we're done;
	# otherwise update place value
	test $place -gt 1 || break
	place=$((place / 256))

	# Move past numeric component and following dot (if present)
	ver=${ver#$num}
	ver=${ver#.}
    done

    echo $code
}

# Test cases for string_to_version_code:
# test $(string_to_version_code 1.2.3) = $((1 * 65536 + 2 * 256 + 3))
# test $(string_to_version_code 12.34.56) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56.78) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56.foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56-foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34.0) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34foo) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34-56) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34.foo) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34-foo) = $((12 * 65536 + 34 * 256))

function do_kver()
{
    shift 2;
    local op="$1"
    local right_ver="$2"

    local left=$(string_to_version_code "$KVER")
    local right=$(string_to_version_code "$right_ver")

    local result=$((1 - ($left $op $right)))
    local msg="$KVER $op $right_ver == $left $op $right == "
    if [ $result = 0 ]; then
	msg="$msg true"
    else
	msg="$msg false"
    fi
    vmsg "$msg"
    return $result
}

function do_symbol()  { shift 2; test_symbol "$@"; }
function do_nsymbol() { shift 2; ! test_symbol "$@"; }
function do_symtype() { shift 2; defer_test_symtype pos "$@"; }
function do_nsymtype() { shift 2; defer_test_symtype neg "$@"; }
function do_member() { shift 2; defer_test_memtype pos "$@" void; }
function do_nmember() { shift 2; defer_test_memtype neg "$@" void; }
function do_memtype() { shift 2; defer_test_memtype pos "$@"; }
function do_nmemtype() { shift 2; defer_test_memtype neg "$@"; }
function do_bitfield() { shift 2; defer_test_bitfield pos "$@"; }
function do_nbitfield() { shift 2; defer_test_bitfield neg "$@"; }
function do_export()
{
    local sym=$3
    shift 3

    # Only scan header files for the symbol
    test_symbol $sym $(echo "$@" | sed -r 's/ [^ ]+\.c/ /g') || return
    test_export $sym "$@"
}
function do_nexport() { ! do_export "$@"; }
function do_file()
{
    shift 2; # skip action and symbol name
    for file in "$@"; do
        # check both kernel src and common header trees as
        # on debian these are separate
        if [ -f $KBUILD_SRC/$file ]; then
            return 0
        fi
        if [ -f $KPATH/$file ]; then
            return 0
        fi
    done
    return 1
}
function do_nfile()   { ! do_file "$@"; }

function do_custom()  { do_$1; }

######################################################################
# Implementation of kernel feature checking

# Special return value for deferred test
DEFERRED=42

function atexit_cleanup()
{
  rc=$?
  [ -n "$rmfiles" ] && rm -rf $rmfiles
  return $rc
}

function strip_comments()
{
    local file=$1

    cat $1 | sed -e '
/\/\*/!b
:a
/\*\//!{
N
ba
}
s:/\*.*\*/::' | sed -e '/^#include/d'
}

function test_symbol()
{
    local symbol=$1
    shift
    local file
    local prefix
    local prefix_list

    for file in "$@"; do
        # For speed, lets just grep through the file. The symbol may
        # be of any of these forms:
        #     #define SYMBOL
        #     typedef void (SYMBOL)(void)
        #     extern void SYMBOL(void)
        #     void (*SYMBOL)(void)
        #     enum { SYMBOL, } void
        #
	# Since 3.7 headers can be in both $KBUILD_SRC/include
	#     or $KBUILD_SRC/include/uapi so check both
	# If the file contains "include/linux" then build set of
        # prefixes

        prefix=$(dirname $file)
	file=$(basename $file)
        if [ "$prefix" == "include/linux" ]; then
            prefix_list="include/linux/ include/uapi/linux/"
	else
            prefix_list="$prefix/"
        fi

	for prefix in $prefix_list; do
            if [ $efx_verbose = true ]; then
                echo >&2 "Looking for '$symbol' in '$KBUILD_SRC/$prefix$file'"
            fi
            [ -f "$KBUILD_SRC/$prefix$file" ] &&  \
                strip_comments $KBUILD_SRC/$prefix$file | \
                grep -E -w "$symbol" >/dev/null && \
                return 0
        done
    done
    return 1
}

function defer_test_symtype()
{
    local sense=$1
    local symbol=$2
    local file=$3
    shift 3
    local type="$*"

    if [ ${file:0:8} != "include/" ]; then
	fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <linux/types.h>
#include <${file:8}>

#include \"_autocompat.h\"

__typeof($type) *kernel_compat_dummy = &$symbol;
"
}

function defer_test_memtype()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4
    local memtype="$*"

    if [ ${file:0:8} != "include/" ]; then
	fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
$aggtype kernel_compat_dummy_1;
__typeof($memtype) *kernel_compat_dummy_2 = &kernel_compat_dummy_1.$memname;
"
}

function defer_test_bitfield()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4

    if [ ${file:0:8} != "include/" ]; then
	fail "defer_test_bitfield() only works in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
$aggtype kernel_compat_dummy_1;
unsigned long test(void) {
	return kernel_compat_dummy_1.$memname;
}
"
}

function test_inline_symbol()
{
    local symbol=$1
    local file=$2
    local t=$(mktemp)
    rmfiles="$rmfiles $t"

    [ -f "$KBUILD_SRC/$file" ] || return

    # TODO: This isn't very satisfactory. Alternative options are:
    #   1. Come up with a clever sed version
    #   2. Do a test compile, and look for an undefined symbol (extern)

    # look for the inline..symbol. This is complicated since the inline
    # and the symbol may be on different lines.
    strip_comments $KBUILD_SRC/$file | \
	grep -E -m 1 -B 1 '(^|[,\* \(])'"$symbol"'($|[,; \(\)])' > $t
    [ $? = 0 ] || return $?

    # there is either an inline on the final line, or an inline and
    # no semicolon on the previous line
    head -1 $t | grep -E -q 'inline[^;]*$' && return
    tail -1 $t | grep -E -q 'inline' && return

    return 1
}

function test_export()
{
    local symbol=$1
    shift
    local files="$@"
    local file match

    # Looks for the given export symbol $symbol, defined in $file
    # Since this symbol is exported, we can look for it in:
    #     1. $KBUILD_MODULE_SYMVERS
    #     2. If the full source is installed, look in there.
    #        May give a false positive if the export is conditional.
    #     3. The MAP file if present. May give a false positive
    #        because it lists all extern (not only exported) symbols.
    if [[ $KBUILD_MODULE_SYMVERS && -f $KBUILD_MODULE_SYMVERS ]]; then
        if [ $efx_verbose = true ]; then
            echo >&2 "Looking for export of $symbol in $KBUILD_MODULE_SYMVERS"
	fi
	[ -n "$(awk '/0x[0-9a-f]+[\t ]+'$symbol'[\t ]+/' $KBUILD_MODULE_SYMVERS)" ]
    else
	for file in $files; do
            if [ $efx_verbose = true ]; then
		echo >&2 "Looking for export of $symbol in $KBUILD_SRC/$file"
            fi
            if [ -f $KBUILD_SRC/$file ]; then
		grep -E -q 'EXPORT_(PER_CPU)?SYMBOL(_GPL)?\('"$symbol"'\)' $KBUILD_SRC/$file && return
            fi
	done
	if [ -n "$MAP" ]; then
            if [ $efx_verbose = true ]; then
		echo >&2 "Looking for export of $symbol in $MAP"
            fi
	    grep -E -q "[A-Z] $symbol\$" $MAP && return
	fi
	return 1
    fi
}

function test_compile()
{
    local source="$1"
    local rc
    local dir=$(mktemp -d)
    echo "$source" > $dir/test.c
    cat > $dir/Makefile <<EOF
$makefile_prefix
obj-m := test.o
EOF
    make -rR -C $KPATH ${ARCH:+ARCH=$ARCH} M=$dir O=$KOUT ${CC:+CC="$CC"} >$dir/log 2>&1
    rc=$?

    if [ $efx_verbose = true ]; then
	echo >&2 "tried to compile:"
	sed >&2 's/^/    /' $dir/test.c
	echo >&2 "compiler output:"
	sed >&2 's/^/    /' $dir/log
    fi

    rm -rf $dir
    return $rc
}

function defer_test_compile()
{
    local sense=$1
    local source="$2"
    echo "$source" > "$compile_dir/test_$key.c"
    echo "obj-m += test_$key.o" >> "$compile_dir/Makefile"
    eval deferred_$sense=\"\$deferred_$sense $key\"
    return $DEFERRED
}

function read_make_variables()
{
    local regexp=''
    local split='('
    local variable
    local variables="$@"
    local dir=$(mktemp -d)

    for variable in $variables; do
	echo "\$(warning $variable=\$($variable))" >> $dir/Makefile
	regexp=$regexp$split$variable
	split='|'
    done
    make -C $KPATH $EXTRA_MAKEFLAGS ${ARCH:+ARCH=$ARCH} M=$dir 2>&1 >/dev/null | sed -r "s#$dir/Makefile:.*: ($regexp)=.*$)#\1#; t; d"
    rc=$?

    rm -rf $dir
    return $rc
}

function read_define()
{
    local variable="$1"
    local file="$2"
    cat $KOUT/$2 | sed -r 's/#define '"$variable"' (.*)/\1/; t; d'
}

efx_quiet=false
efx_verbose=false

KVER=
KPATH=
KOUT=
FILTER=
MAP=
EXTRA_MAKEFLAGS=
kompat_symbols=

# These variables from an outer build will interfere with our test builds
unset KBUILD_EXTMOD
unset KBUILD_SRC
unset M
unset TOPDIR
unset sub_make_done

# Filter out make options except for job-server (parallel make)
old_MAKEFLAGS="${MAKEFLAGS:-}"
MAKEFLAGS=
next=
for word in $old_MAKEFLAGS; do
    case "$word" in
	'-j' | '-l')
	    export MAKEFLAGS="$MAKEFLAGS $word"
	    next=1
	    ;;
	'-j'* | '-l'*)
	    export MAKEFLAGS="$MAKEFLAGS $word"
	    ;;
	'--jobserver-fds'* | '--jobs='* | '--jobs' | '--load-average'*)
	    export MAKEFLAGS="$MAKEFLAGS $word"
	    ;;
	*)
	    test -n "$next" && export MAKEFLAGS="$MAKEFLAGS $word"
	    next=
	    ;;
    esac
done

# Clean-up temporary files when we exit.
rmfiles=
trap atexit_cleanup EXIT

while [ $# -gt 0 ]; do
    case "$1" in
	-r) KVER=$2; shift;;
	-k) KPATH=$2; shift;;
	-o) KOUT=$2; shift;;
	-q) efx_quiet=true;;
	-m) MAP=$2; shift;;
	-v) efx_verbose=true;;
	-s) kompat_symbols="$2"; shift;;
	-*) usage; exit -1;;
	*)  [ -z $FILTER ] && FILTER=$1 || FILTER="$FILTER|$1";;
	*)  break;
    esac
    shift
done

vmsg "MAKEFLAGS  := $MAKEFLAGS"

# resolve KVER and KPATH
[ -z "$KVER" ] && [ -z "$KPATH" ] && KVER=`uname -r`
[ -z "$KPATH" ] && KPATH=/lib/modules/$KVER/build
[ -z "$KOUT" ] && KOUT="$KPATH"

# Need to set CC explicitly on the kernel make line
# Needs to override top-level kernel Makefile setting
# Debian (specifically Debian 10) adds ccache and/or space.
# Somehow this script does the wrong thing with space, so disable that.
# On the flip side, we should not remove CC completely, because sometimes
# it is important.  For example, when using elrepo kernels with old RHEL.
if [ -n "${CC:-}" ]; then
    CC=${CC/ccache /}
    CC=${CC/ /}
    EXTRA_MAKEFLAGS=CC=${CC}
fi

if [ -n "${CROSS_COMPILE:-}" ]; then
    EXTRA_MAKEFLAGS="${EXTRA_MAKEFLAGS} CROSS_COMPILE=${CROSS_COMPILE} ARCH=${ARCH}"
fi

# Select the right warnings - complicated by working out which options work
makefile_prefix='
ifndef try-run
try-run = $(shell set -e;		\
	TMP="$(obj)/.$$$$.tmp";		\
	TMPO="$(obj)/.$$$$.o";		\
	if ($(1)) >/dev/null 2>&1;	\
	then echo "$(2)";		\
	else echo "$(3)";		\
	fi;				\
	rm -f "$$TMP" "$$TMPO")
endif
ifndef cc-disable-warning
cc-disable-warning = $(call try-run,\
	$(CC) $(KBUILD_CPPFLAGS) $(KBUILD_CFLAGS) -W$(strip $(1)) -c -xc /dev/null -o "$$TMP",-Wno-$(strip $(1)))
endif
EXTRA_CFLAGS = -Werror $(call cc-disable-warning, unused-but-set-variable)
'

# Ensure it looks like a build tree and we can build a module
[ -d "$KPATH" ] || fail "$KPATH is not a directory"
[ -f "$KPATH/Makefile" ] || fail "$KPATH/Makefile is not present"
test_compile "#include <linux/module.h>
MODULE_LICENSE(\"GPL\");" || \
    fail "Kernel build tree is unable to build modules"

# strip the KVER out of UTS_RELEASE, and compare to the specified KVER
_KVER=
for F in include/generated/utsrelease.h include/linux/utsrelease.h include/linux/version.h; do
    [ -f $KOUT/$F ] && _KVER="$(eval echo $(read_define UTS_RELEASE $F))" && break
done
[ -n "$_KVER" ] || fail "Unable to identify kernel version from $KOUT"
if [ -n "$KVER" ]; then
    [ "$KVER" = "$_KVER" ] || fail "$KOUT kernel version $_KVER does not match $KVER"
fi
KVER=$_KVER
unset _KVER

vmsg "KVER       := $KVER"
vmsg "KPATH      := $KPATH"

# Read the following variables from the Makefile:
#  KBUILD_SRC:            Root of source tree (not the same as KPATH under SUSE)
#  ARCH:                  Target architecture name
#  SRCARCH:               Target architecture directory name (2.6.24 onward)
#  CONFIG_X86_{32,64}:    Work around ARCH = x86 madness
#  CONFIG_PTP_1588_CLOCK: PTP clock support

[ -n "${ARCH:-}" ] && export ARCH
eval $(read_make_variables KBUILD_SRC ARCH SRCARCH CONFIG_X86_32 CONFIG_X86_64 CONFIG_PTP_1588_CLOCK abs_srctree)

# Define:
#     KBUILD_SRC:         Was renamed into abs_srctree in linux-5.3
#     KBUILD_SRC:         If not already set, same as KPATH
#     SRCARCH:            If not already set, same as ARCH
#     WORDSUFFIX:         Suffix added to some filenames by the i386/amd64 merge
[ -n "${KBUILD_SRC:-}" ] || KBUILD_SRC=${abs_srctree:-}
[ -n "${KBUILD_SRC:-}" ] || KBUILD_SRC=$KPATH
[ -n "${SRCARCH:-}" ] || SRCARCH=$ARCH
if [ "$ARCH" = "x86_64" ] || [ "${CONFIG_X86_64:-}" = "y" ]; then
    WORDSUFFIX=_64
else
    WORDSUFFIX=
fi
[ -f "$KBUILD_SRC/arch/$SRCARCH/Makefile" ] || fail "$KBUILD_SRC doesn't directly build $SRCARCH"

vmsg "KBUILD_SRC := $KBUILD_SRC"
vmsg "SRCARCH    := $SRCARCH"
vmsg "WORDSUFFIX := $WORDSUFFIX"

if [ -f "$KPATH/Module.symvers" ] ; then
    KBUILD_MODULE_SYMVERS=$KPATH/Module.symvers
elif [ -n "${O:-}" -a -f "${O:-}/Module.symvers" ] ; then
    KBUILD_MODULE_SYMVERS="$O/Module.symvers"
elif [ -f "$PWD/Module.symvers" ] ; then
    KBUILD_MODULE_SYMVERS="$PWD/Module.symvers"
else
    KBUILD_MODULE_SYMVERS=""
fi
vmsg "KBUILD_MODULE_SYMVERS := $KBUILD_MODULE_SYMVERS"

# try and find the System map [used by test_export]
if [ -z "$MAP" ]; then
    if [ -f /boot/System.map-$KVER ]; then
	MAP=/boot/System.map-$KVER
    elif [ $KVER = "`uname -r`" ] && [ -f /proc/kallsyms ]; then
	MAP=/proc/kallsyms
    elif [ -f $KBUILD_MODULE_SYMVERS ]; then
	# can use this to find external symbols only
	true
    else
	log "!!Unable to find a valid System map. Export symbol checks may not work"
    fi
fi

if [ "$kompat_symbols" == "" ]; then
    kompat_symbols="$(generate_kompat_symbols)"
fi

# filter the available symbols
if [ -n "$FILTER" ]; then
    kompat_symbols="$(echo "$kompat_symbols" | grep -E "^($FILTER):")"
fi

compile_dir="$(mktemp -d)"
rmfiles="$rmfiles $compile_dir"
echo >"$compile_dir/Makefile" "$makefile_prefix"
echo >"$compile_dir/_autocompat.h"
deferred_pos=
deferred_neg=

# Note that for deferred tests this runs after the Makefile has run all tests
function do_one_symbol() {
    local key=$1
    shift
    # NB work is in the following if clause "do_${method}"
    if "$@"; then
	echo "#define $key yes"
	# So that future compile tests can consume this
	echo "#define $key yes" >> "${compile_dir}/_autocompat.h"
    elif [ $? -ne $DEFERRED ]; then
	echo "// #define $key"
    fi
}

# process each symbol
for symbol in $kompat_symbols; do
    # split symbol at colons; disable globbing (pathname expansion)
    set -o noglob
    IFS=:
    set -- $symbol
    unset IFS
    set +o noglob

    key="$1"
    method="$2"
    do_one_symbol $key do_${method} "$@"
done

# Run the deferred compile tests
eval make -C $KPATH -k $EXTRA_MAKEFLAGS O="$KOUT" M="$compile_dir" \
    >"$compile_dir/log" 2>&1 \
    || true
if [ $efx_verbose = true ]; then
    echo >&2 "compiler output:"
    sed >&2 's/^/    /' "$compile_dir/log"
fi
for key in $deferred_pos; do
    # Use existence of object file as evidence of compile without warning/errors
    do_one_symbol $key test -f "$compile_dir/test_$key.o"
done
for key in $deferred_neg; do
    do_one_symbol $key test ! -f "$compile_dir/test_$key.o"
done

#!/bin/bash -eu
#
# SPDX-License-Identifier: BSD-2-Clause
# (c) Copyright 2015 Xilinx, Inc.
#
# This is a heavily-reduced version of kernel_compat.sh, currently
# just handling symbol definition checks.
######################################################################

me=$(basename "$0")

err  () { echo >&2 "$*";    }
log  () { err "$me: $*";    }
vlog () { $verbose && err "$me: $*"; }
fail () { log "$*"; exit 1; }
try  () { "$@" || fail "'$*' failed"; }
vmsg () { $quiet || log "$@"; }

function usage()
{
    err
    err "usage:"
    err "  $me [options] <symbol1> <symbol2>"
    err
    err "description:"
    err "  Produce a list of compatability macros"
    err
    err "options:"
    err "  -q              -- Quieten the checks"
    err "  -v              -- Verbose output"
    err "  -s              -- Symbol list to use"
    err "  <symbol>        -- Symbol to evaluate."
    err "                     By default every symbol is evaluated"

}

######################################################################
# Symbol definition map

function generate_compat_symbols() {
    echo "
EFX_NEED_STRUCT_ETHTOOL_DUMP			nsymbol	ethtool_dump		include/linux/ethtool.h
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

######################################################################
# Generic methods for standard symbol types

function do_symbol()  { shift 2; test_symbol "$@"; }
function do_nsymbol() { shift 2; ! test_symbol "$@"; }
function do_custom()  { do_$1; }

######################################################################
# Implementation of feature checking

# Special return value for deferred test
DEFERRED=42

function atexit_cleanup()
{
  rc=$?
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
s:/\*.*\*/::'
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
        base_list="/usr /usr/local"

        for base in $base_list; do
            if [ $verbose = true ]; then
                echo >&2 "Looking for '$symbol' in '$base/$file'"
            fi
            [ -f "$base/$file" ] &&  \
                strip_comments $base/$file | \
                egrep -w "$symbol" >/dev/null && \
                return 0
        done
    done
    return 1
}

quiet=false
verbose=false

FILTER=
compat_symbols=

while [ $# -gt 0 ]; do
    case "$1" in
	-q) quiet=true;;
	-v) verbose=true;;
	-s) compat_symbols="$2"; shift;;
	-*) usage; exit -1;;
	*)  [ -z $FILTER ] && FILTER=$1 || FILTER="$FILTER|$1";;
	*)  break;
    esac
    shift
done

if [ "$compat_symbols" == "" ]; then
    compat_symbols="$(generate_compat_symbols)"
fi

# filter the available symbols
if [ -n "$FILTER" ]; then
    compat_symbols="$(echo "$compat_symbols" | egrep "^($FILTER):")"
fi

function do_one_symbol() {
    local key=$1
    shift
    # NB work is in the following if clause "do_${method}"
    if "$@"; then
	echo "#define $key yes"
    elif [ $? -ne $DEFERRED ]; then
	echo "// #define $key"
    fi
}

# process each symbol
for symbol in $compat_symbols; do
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

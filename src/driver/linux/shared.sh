#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2003-2018 Xilinx, Inc.
###############################################################################
# <L5_PRIVATE L5_SCRIPT>
#   Copyright: (c) Level 5 Networks Limited.
#      Author: djr
#     Started: 30/4/2003
# Description: Common shell-script stuff for load/unload scripts.
# </L5_PRIVATE>
###############################################################################

err  () { echo 1>&2 "$*";   }
log  () { err "$p: $*";     }
fail () { log "$*"; exit 1; }
try  () { "$@" || fail "ERROR: '$*' failed"; }


DIR=$(dirname "$0")

isloaded() { /sbin/lsmod | grep -q "^$1\>"; }

anyloaded() { RESULT=1; for m in "$@"; do if isloaded $m; then RESULT=0; fi; done; return $RESULT; }

isdev() { grep -qw "$1" /proc/devices; }

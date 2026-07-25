#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2015-2026 Advanced Micro Devices, Inc.

set -u

bin=$(cd "$(dirname "$0")" && /bin/pwd)
me=$(basename "$0")

err()  { echo >&2 "$*"; }
log()  { err "$me: $*"; }
fail() { rm -rf "$tempfile"; log "$*"; exit 1; }
try()  { "$@" || fail "FAILED: $*"; }

usage() {
  err
  err "usage:"
  err "  $me [options]"
  err
  err "options:"
  err "  --tarball <path>   - onload tarball to create packages for"
  err "  --out <path>       - directory to write source package to"
  err
  exit 1
}

######################################################################
# main

PATH="$bin:$PATH:/usr/sbin:/sbin"; export PATH
TOP=$(cd "$bin/.." && /bin/pwd)
tarball=
onloadtype=enterprise
onloadver=
package=
basename=
outdir=$(pwd)

while [ $# -gt 0 ]; do
  case "$1" in
  --tarball)        shift; tarball=$1;;
  --out)            shift; outdir=$1;;
  -*)               usage;;
  *)                break;;
  esac
  shift
done

if [ ! -f "$tarball" ]; then
  echo "$tarball does not appear to be a regular file";
  exit;
fi

if [ ! -d "$outdir" ]; then
  echo "$outdir does not appear to be a directory";
  exit;
fi

basename=$(basename "$tarball" .tgz)
onloadtype=$(echo "$basename" | try sed -e 's/\([^-]*\)\(-\)\(.*\)/\1/')
onloadver=$(echo "$basename" | try sed -e 's/\([^-]*\)\(-\)\(.*\)/\3/')
package="${onloadtype}_${onloadver}"
onloaddir="$onloadtype-$onloadver"
tempfile=$(mktemp -d)

[ "$onloadtype" = "${onloadtype%%onload}onload" ] || \
  fail "onload tarball name sanity check (*onload-*.tgz) failed"

echo "Creating package $package in $tempfile"

# Unpack what we need
try cp "$tarball" "$tempfile/$package.orig.tar.gz"
try cd "$tempfile"
try tar xf "$package.orig.tar.gz"
try cd "$onloaddir"

# Stamp changelog with release-ready status
try dch --maintmaint --release ''

# Build the source package
try debuild -S -i -uc -us -d
try cd "$tempfile"

echo "Using package components:"
ls ./*.[gx]z ./*.dsc

try tar zcf "$package-debiansource.tgz" --owner=root --group=root ./*.[gx]z ./*.dsc
try mv "$package-debiansource.tgz" "$outdir/"
try rm -rf "$tempfile"

echo ""
echo "Wrote $outdir/$package-debiansource.tgz"
echo ""


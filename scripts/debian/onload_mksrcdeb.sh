#!/bin/sh

bin=$(cd $(dirname "$0") && /bin/pwd)
me=$(basename "$0")

err()  { echo >&2 "$*"; }
log()  { err "$me: $*"; }
fail() { rm -rf $tempfile; log "$*"; exit 1; }
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
outdir=`pwd`

while [ $# -gt 0 ]; do
  case "$1" in
  --tarball)    shift; tarball=$1;;
  --out)        shift; outdir=$1;;
  -*)           usage;;
  *)            break;;
  esac
  shift
done

if [ ! -f $tarball ]; then
  echo "$tarball does not appear to be a regular file";
  exit;
fi

if [ ! -d $outdir ]; then
  echo "$outdir does not appear to be a directory";
  exit;
fi

basename=$(basename $tarball .tgz)
onloadtype=$(echo $basename | try sed -e 's/\([^-]*\)\(-\)\(.*\)/\1/')
onloadver=$(echo $basename | try sed -e 's/\([^-]*\)\(-\)\(.*\)/\3/')
package=$onloadtype\_$onloadver
onloaddir=$onloadtype-$onloadver
tempfile=`mktemp -d`
tempfile2=`mktemp -d`

if [ $onloadtype != "enterpriseonload" -a \
     $onloadtype != "openonload" -a \
     $onloadtype != "cloudonload" -a \
     $onloadtype != "onload" ]; then
  echo "Couldn't determine valid onload type from tarball name. Name should be"
  echo "in the format enterpriseonload-version.tgz, openonload-version.tgz,"
  echo "cloudonload-version.tgz or onload-version.tgz."
  exit
fi

echo "Creating package $package in $tempfile"

try cp $tarball $tempfile/$package.orig.tar.gz
try mkdir -p $tempfile/$onloaddir/debian

# Make any necessary replacements for the onload release we're doing in the
# control files
for i in `find $TOP/debian/debian-templ/* -type f`; do
  try sed "s/#VERSION#/$onloadver/" < $i > $tempfile2/$(basename $i);
done
for i in $tempfile2/*; do
  try sed "s/#TYPE#/$onloadtype/" < $i > $tempfile/$onloaddir/debian/$(basename $i);
done
try rm -rf $tempfile2

# Format is in a separate directory and can't have replacements, just copy it
# separately
try cp -r $TOP/debian/debian-templ/source $tempfile/$onloaddir/debian/

try cd $tempfile
try tar xf $package.orig.tar.gz
try cd $onloaddir/debian
try debuild -S -i -uc -us
try cd $tempfile

echo "Using package components:"
ls *.[gx]z *.dsc

try tar zcf $package-debiansource.tgz *.[gx]z *.dsc
try mv $package-debiansource.tgz $outdir/
try rm -rf $tempfile

echo ""
echo "Wrote $outdir/$package-debiansource.tgz"
echo ""


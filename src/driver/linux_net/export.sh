#!/bin/bash

set -e

# -k means keep the kernel kompat kode
# -kk means run kernel_compat.sh at export time
# -o means keep out-of-tree (not-upstream) code
# --suffix=<identifier> adds a suffix to the EFX_DRIVER_VERSION define
SOURCE_SED_COMMANDS=''
MAKEFILE_SED_COMMANDS=''
UNIFDEF_DEFINES=''
SUBDIR=
KCOMPAT=
AUTOCOMPAT=
VERSION_SUFFIX=
NOT_UPSTREAM=

for i in "$@"
do
case $i in
	-k)
		KCOMPAT=1
		;;
	-kk)
		KCOMPAT=1
		AUTOCOMPAT=apply
		;;
	-o)
		AUTOCOMPAT=
		NOT_UPSTREAM=1
		;;
	--suffix=*)
		VERSION_SUFFIX="${i#*=}"
		;;
	*)
		# End of arguments
		break
		;;
esac
shift
done

if [ -z "$NOT_UPSTREAM" ]; then
	UNIFDEF_DEFINES="-UEFX_NOT_UPSTREAM"
	SOURCE_SED_COMMANDS='s/\bEFX_FATAL\b/netif_err/g; '
	MAKEFILE_SED_COMMANDS='/^ifndef EFX_UPSTREAM/,/^endif # !EFX_UPSTREAM/d; '
	SUBDIR=drivers/net/sfc

	if [ -n "$KCOMPAT" ]; then
		if [ "$AUTOCOMPAT" != "apply" ]; then
			AUTOCOMPAT=keep
		fi
		UNIFDEF_DEFINES="$UNIFDEF_DEFINES -DEFX_USE_KCOMPAT"
	else
		UNIFDEF_DEFINES="$UNIFDEF_DEFINES -UEFX_USE_KCOMPAT"
		MAKEFILE_SED_COMMANDS="$MAKEFILE_SED_COMMANDS"'/^ifndef EFX_NO_KCOMPAT/,/^endif # !EFX_NO_KCOMPAT/d; '
		MAKEFILE_SED_COMMANDS="$MAKEFILE_SED_COMMANDS"'/^#$/d; ' # delete spacing comments
	fi

	UNIFDEF_DEFINES="$UNIFDEF_DEFINES -UCONFIG_SFC_DEBUGFS -UCONFIG_SFC_TRACING -UEFX_USE_MCDI_PROXY_AUTH -UEFX_USE_MCDI_PROXY_AUTH_NL -DCONFIG_SFC_I2C -DEFX_USE_GRO -UEFX_C_MODEL"
fi

MAKEFILE_SED_COMMANDS="$MAKEFILE_SED_COMMANDS/^ifdef EFX_NOT_EXPORTED/,/^endif # EFX_NOT_EXPORTED/d; "
MAKEFILE_SED_COMMANDS="$MAKEFILE_SED_COMMANDS/^ifndef NOWERROR/,/^endif # NOWERROR/d;"
UNIFDEF_DEFINES="$UNIFDEF_DEFINES -UEFX_NOT_EXPORTED -DWITH_MCDI_V2"

if [ -n "$VERSION_SUFFIX" ]; then
	SOURCE_SED_COMMANDS="$SOURCE_SED_COMMANDS s/\(#define EFX_DRIVER_VERSION.*\)\"/\1-$VERSION_SUFFIX\"/; "
fi

KPATH="$1"
shift

if [ ! -d "$KPATH" ]; then
    echo >&2 "'$KPATH' does not exist"
    exit 2
fi

if [ -n SUBDIR -a -d "$KPATH/drivers/net/ethernet" ]; then
    SUBDIR=drivers/net/ethernet/sfc
fi

sources="$*"

if ! UNIFDEF="$(which unifdef 2>/dev/null)"; then
    UNIFDEF=/misc/apps/x86_64/unifdef
    if [ -z "$UNIFDEF" -o ! -e "$UNIFDEF" ]; then
	echo >&2 "unifdef not found; try 'sudo yum install unifdef' or build it from the v5 repository"
	exit 1
    fi
fi

mkdir -p $KPATH/$SUBDIR
rm -f $KPATH/$SUBDIR/*.[ch]

if [ -n "$AUTOCOMPAT" ]; then
    # unifdef can't rewrite an #if unless every single symbol is known.
    # Which means we have to include autocompat even if we're going to
    # apply the symbols anyway
    ./kernel_compat.sh -k $KPATH -q > $KPATH/$SUBDIR/autocompat.h
    if [ "$AUTOCOMPAT" = "apply" ]; then
	# Read in from autocompat.h
	while read prefix word value; do
	    # Need to keep any #undefs after #if defined(EFX_HAVE_XDP_EXT)
	    grep -q "#undef $word" kernel_compat.h && \
		echo ".. keeping $word due to #undef detected in kernel_compat.h" && \
		continue
	    if [  $prefix = "//" ]; then
		UNIFDEF_DEFINES="$UNIFDEF_DEFINES -U$value"
	    elif [ $prefix = "#define" ]; then
		UNIFDEF_DEFINES="$UNIFDEF_DEFINES -D$word"
	    else
		echo >&2 "unable to parse '$prefix $word $value'"
		exit 1
	    fi
	done < $KPATH/$SUBDIR/autocompat.h
    fi
    # Ensure that EFX_USE_KCOMPAT is defined
    SOURCE_SED_COMMANDS="$SOURCE_SED_COMMANDS /\#include \"autocompat.h\"/i\
#define EFX_USE_KCOMPAT"
fi

# Copy top-level sources, then find required headers and copy them
while [ -n "$sources" ]; do
    missing=""
    for source in $sources; do
	case "$source" in
	    */*.h)
		dest=$KPATH/${SUBDIR:+include}/$source
		;;
	    *)
		dest=$KPATH/$SUBDIR/$source
		;;
	esac
	if [ "$source" = kernel_compat.sh -o "$source" = kernel_compat_funcs.sh ]; then
		cp $source $dest
		continue
	fi
	if ! [ -f "$source" ]; then
		continue
	fi
	mkdir -p $(dirname $dest)
	if ! [ -f $KPATH/$SUBDIR/$source ]; then
	    if [ -n "$UNIFDEF_DEFINES" ]; then
		# unifdef may return either 0 or 1 for success.
		"$UNIFDEF" $UNIFDEF_DEFINES -k -B <$source \
		    | sed "$SOURCE_SED_COMMANDS" >$dest \
		    && test ${PIPESTATUS[0]} -le 1
	    elif [ -n "$SOURCE_SED_COMMANDS" ]; then
		sed "$SOURCE_SED_COMMANDS" <$source >$dest
	    else
		cp $source $dest
	    fi
	fi
	while read header; do
	    if [ "$header" != config.h -a "$header" != autocompat.h -a \
		 \! -f $KPATH/$SUBDIR/$header ]; then
		missing="$missing $header"
	    fi
	done < <(sed 's/^#include "\([^/]*\)".*$/\1/; t; d' <$dest)
    done
    sources="$missing"
done

# Copy Makefile, deleting unwanted sections
sed "$MAKEFILE_SED_COMMANDS" <Makefile >$KPATH/$SUBDIR/Makefile

if [ -n "$SUBDIR" ]; then
    # Copy Kconfig
    cp Kconfig $KPATH/$SUBDIR/
fi

if [ "$SUBDIR" = drivers/net/sfc ]; then
    # Add a reference in the parent Makefile if it's not there already
    if ! grep -q '^obj-\$(CONFIG_SFC)' $KPATH/drivers/net/Makefile; then
	sed -i '$a\
obj-$(CONFIG_SFC) += sfc/\
' \
	    $KPATH/drivers/net/Makefile
    fi

    # Add a reference in the parent Kconfig if it's not there already
    if ! grep -q '^source "drivers/net/sfc/Kconfig"' $KPATH/drivers/net/Kconfig
	then
	sed -i '/^endif # NETDEV_10000/i\
source "drivers/net/sfc/Kconfig"\
' \
	    $KPATH/drivers/net/Kconfig
    fi
fi

# Update .config with our settings
if [ -f $KPATH/.config ];
then
    cp $KPATH/.config $KPATH/.config.old
    grep -v -E "CONFIG_SFC|CONFIG_NET_VENDOR_SOLARFLARE" $KPATH/.config.old > $KPATH/.config
    echo "CONFIG_NET_VENDOR_SOLARFLARE=y" >> $KPATH/.config

    for kernel_config in `grep "^config SFC" Kconfig | sed 's/config //'`;
    do
	set -- `grep "export CONFIG_$kernel_config " Makefile | head -1`
	if [ $# -ne 4 ];
	then
		echo "WARNING: Could not determine CONFIG_$kernel_config value from the Makefile:"
		grep "export CONFIG_$kernel_config " Makefile
		continue;
	fi
	echo "CONFIG_$kernel_config=$4" >> $KPATH/.config
    done
else
    echo "WARNING: No .config in $KPATH"
fi

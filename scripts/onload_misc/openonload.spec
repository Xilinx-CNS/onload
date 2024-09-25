# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2009-2020 Xilinx, Inc.
######################################################################
# RPM spec file for OpenOnload
#
# Authors: See Changelog at bottom.
#
# To build a source RPM:
#   rpmbuild -ts openonload-ver.tgz
# OR:
#   cp openonload-ver.tgz $RPM/SOURCES
#   cp openonload-ver/scripts/onload_misc/openonload.spec $RPM/SPECS
#   rpmbuild -bs --define "_topdir $RPM" $RPM/SPECS/openonload.spec
#
# To build a binary RPM from source:
#   rpmbuild --rebuild --define "_topdir $RPM" $RPM/SRPMS/openonload-*.src.rpm
#
# If you want to build for kernel version which differs from the one in
# uname, use:
#   --define "kernel <full-kernel-name>"
#
# If you want to ensure that 32-bit lib will be built on 64-bit add:
#   --define "build32 true"
#
# If you don't want to build the devel pacakage, use:
#   --without devel
#
# If you want debug binary packages add:
#   --define "debug true"
#
# If you want to generate debuginfo rpm package when generating release binary packages add:
#   --define "debuginfo true"
#
# If you want to install the Onload libraries with setuid add:
#   --define "setuid true"
#
# If your distribution does not provide a dist macro (e.g. CentOS) which is used
# to differentiate the filename, you may overrise it:
#    --define 'dist .el5'
#
# For PPC platform you can use IBM Advanced Toolchain. For this you should
#    --define 'ppc_at </opt cc path>
#
# If you want to specify a build profile add:
#    --define "build_profile <profile>"
#
# By default, the OpenOnload build system enables the auxiliary bus and EFCT
# support if build prerequisites are available on a build machine or implicitly
# disables them otherwise. The user can adjust this behaviour by setting or
# resetting the have_efct macro.
#
# If you want to disable EFCT support explicitly:
#    --define "have_efct 0"
#
# If you want to fail the OpenOnload build if either AUX or EFCT
# is unavailable at build time:
#    --define "have_efct 1"

%bcond_without devel # add option to skip devel builds

%define pkgversion 20100910

%undefine __brp_mangle_shebangs

%{!?kernel:  %{expand: %%define kernel %%(uname -r)}}
%{!?target_cpu:  %{expand: %%define target_cpu %{_host_cpu}}}
%{!?kpath: %{expand: %%define kpath /lib/modules/%%{kernel}/build}}
%{!?build32: %{expand: %%define build32 false}}
%{!?debuginfo: %{expand: %%define debuginfo false}}

%define knownvariants '@(BOOT|PAE|@(big|huge)mem|debug|enterprise|kdump|?(big|large)smp|uml|xen[0U]?(-PAE)|xen|rt?(-trace|-vanilla)|default|big|pae|vanilla|trace|timing)'
%define knownvariants2 '%{knownvariants}'?(_'%{knownvariants}')

# Assume that all non-suse distributions can be treated as redhat
%define redhat       %( [ "%{_vendor}" = "suse"   ] ; echo $?)

# Determine distro to use for package conflicts with SFC.  This is not
# accurate in various cases, and should be updated to use the sfc-disttag
# script that is used by the sfc spec file to generate their package name.
%define have_lsb %( ! which lsb_release > /dev/null 2>&1; echo $? )
%if %{have_lsb}
%define thisdist %(lsb_release -rs | cut -d. -f1)
%define maindist %{?for_rhel:%{for_rhel}}%{!?for_rhel:%{thisdist}}
%endif

%define kernel_installed %( [ -e "/lib/modules/%{kernel}" ] && rpm -q --whatprovides /lib/modules/%{kernel} > /dev/null && echo "1" || echo "0")

%if %kernel_installed

# kmodtool doesn't count 'rt' as a variant so manipulate name. (rpmbuild
# BuildRequires doesn't recognise that kernel-rt provides 'kernel = blah-rt'.)
# also some kernels have 2 parts in the variant
%define kvariantsuffix %(shopt -s extglob; KNOWNVARS='%{knownvariants2}'; KVER=%{kernel}; VAR=${KVER##${KVER%%%${KNOWNVARS}}}; [[ -n "$VAR" ]] && echo $VAR)
%define kvariantsuffix_dash %( KVAR='%{kvariantsuffix}'; [[ -n "${KVAR}" ]] && echo -"${KVAR}" || echo "")
%define kernel_cut   %(shopt -s extglob; KNOWNVARS='%{knownvariants2}'; KVER=%{kernel}; echo ${KVER%%%${KNOWNVARS}} | sed "s/-$//; s/_$//")
# some distros like to add architecture to the kernel name (Fedora)
%define kverrel        %(shopt -s extglob; KVER=%{kernel_cut}; echo ${KVER%%@(.i386|.i586|.i686|.x86_64|.ppc64)})

%else

# kernel for which you're trying to build is not installed on this particular host.
# We will assume that you provided us with a sensible name.

%define kvariantsuffix %(shopt -s extglob; KNOWNVARS='%{knownvariants2}'; KVER=%{kernel}; VAR=${KVER##${KVER%%%${KNOWNVARS}}}; [[ -n "$VAR" ]] && echo $VAR)
%define kvariantsuffix_dash %( KVAR='%{kvariantsuffix}'; [[ -n "${KVAR}" ]] && echo -"${KVAR}" || echo "")
%define kverrel %( echo %{kernel})

%endif  # kernel_installed

%define kpkgver %(echo '%{kverrel}' | sed 's/-/_/g')

%{echo: %{target_cpu}}

# Control debuginfo package when generating release package
%if "%{debuginfo}" != "true"
%define debug_package %{nil}
%endif

%global __python %{__python3}

###############################################################################

Summary     	: OpenOnload user-space
Name        	: openonload
Version     	: %(echo '%{pkgversion}' | sed 's/-/_/g')
Release     	: 1%{?dist}%{?setuid:SETUID}%{?debug:DEBUG}
Group       	: System Environment/Kernel
License   	: Various
URL             : http://www.openonload.org/
Vendor		: Xilinx, Inc.
Provides	: openonload = %{version}-%{release}
%if 0%{?rhel} >= 8
Recommends	: openonload-devel = %{version}-%{release}
%endif
Source0		: openonload-%{pkgversion}.tgz
BuildRoot   	: %{_builddir}/%{name}-root
AutoReqProv	: no
ExclusiveArch	: i386 i586 i686 x86_64 ppc64
BuildRequires	: gawk gcc sed make bash libpcap libpcap-devel automake libtool autoconf libcap-devel
# The glibc, python-devel, and libcap packages we need depend on distro and platform
%if %{redhat}
BuildRequires	: glibc-common python3-devel libcap
%else
BuildRequires	: glibc-devel glibc python3-devel libcap2
%ifarch x86_64
%if %{build32}
BuildRequires   : glibc-devel-32bit
%endif
%endif
%endif

%description
OpenOnload is a high performance user-level network stack.  Please see
www.openonload.org for more information.

This package comprises the user space components of OpenOnload.

###############################################################################
# Kernel version expands into NAME of RPM
%package kmod-%{kverrel}
Summary     	: OpenOnload kernel modules
Group       	: System Environment/Kernel
Requires	: openonload = %{version}-%{release}
Conflicts	: kernel-module-sfc-RHEL%{maindist}-%{kverrel}
Provides	: openonload-kmod = %{kpkgver}_%{version}-%{release}
Provides	: sfc-kmod-symvers = %{kernel}
AutoReqProv	: no

%if 0%{?have_efct:%have_efct}
%{!?efct_disttag: %global efct_disttag %(
efct_disttag() {
  if [ -f /etc/redhat-release ]; then
    awk '
      /Red Hat Linux release/ { gsub(/\\./,""); printf "RH%s\\n", $5; exit }
      /Red Hat Enterprise Linux release/ { printf "RHEL%s\\n", substr($6, 1, 1); exit }
      /Red Hat Enterprise Linux (WS|Server|Client|Workstation)/ { printf "RHEL%s\\n", substr($7, 1, 1); exit }
      /CentOS Linux release 7/ { printf "RHEL7\\n"; exit }
    ' /etc/redhat-release
  elif [ -x "$(command -v hostnamectl)" ]; then
    hostnamectl | awk '
      /SUSE Linux Enterprise Server/ { printf "SLES%s\\n", $7; exit }
    '
  else
    echo "unsupportedOS"
    return 1
  fi
  return 0
}
echo -n $(efct_disttag)
)}

BuildRequires	: kernel-module-xilinx-efct-%{efct_disttag}-%{kernel} >= 1.5.3.0

%if "%{dist}" == ".el7"
BuildRequires	: kernel-module-auxiliary-%{efct_disttag}-%{kernel} >= 1.0.4.0
Requires	: kernel-module-auxiliary-%{efct_disttag}-%{kernel} >= 1.0.4.0
%endif
%endif

%description kmod-%{kverrel}
OpenOnload is a high performance user-level network stack.  Please see
www.openonload.org for more information.

This package comprises the kernel module components of OpenOnload.

%post kmod-%{kverrel}
# If the weak-modules script is present this will handle running depmod and
# dracut for required kernels.
if [ -x "/sbin/weak-modules" ]; then
  for m in sfc sfc_resource sfc_char onload; do
    echo "/lib/modules/%{kernel}/extra/$m.ko"
  done | /sbin/weak-modules --verbose --add-modules
else
  depmod -a "%{kernel}"
  if [ -f  "/boot/initramfs-%{kernel}.img" ]; then
    if which dracut >/dev/null 2>&1; then
      kver=$(dracut --help |grep kver)
      if [ -n "$kver" ]; then
        dracut -f --kver "%{kernel}"
      else
        dracut -f "/boot/initramfs-%{kernel}.img" "%{kernel}"
      fi
    fi
  fi
fi

%postun kmod-%{kverrel}
if [ "$1" = 0 ]; then  # Erase, not upgrade
  if [ -x "/sbin/weak-modules" ]; then
    for m in sfc sfc_resource sfc_char onload; do
      echo "/lib/modules/%{kernel}/extra/$m.ko"
    done | /sbin/weak-modules --verbose --remove-modules
  else
    depmod -a "%{kernel}"
  fi
fi

%files kmod-%{kverrel}
%defattr(744,root,root)
/lib/modules/%{kernel}/*/*

###############################################################################
%if %{with devel}
%package devel
Summary 	: OpenOnload development header files
Provides	: openonload-devel = %{version}-%{release}
%if 0%{?rhel} >= 8
Supplements	: openonload = %{version}-%{release}
%endif
BuildArch	: noarch

%description devel
OpenOnload is a high performance user-level network stack.  Please see
www.openonload.org for more information.

This package comprises development headers for the components of OpenOnload.

%files devel
%defattr(-,root,root)
%{_includedir}/ci
%{_includedir}/cplane
%{_includedir}/etherfabric
%{_includedir}/onload
%endif
###############################################################################
%prep
[ "$RPM_BUILD_ROOT" != / ] && rm -rf "$RPM_BUILD_ROOT"
%setup -n %{name}-%{pkgversion}

%build

# There are a huge variety of package names and formats for the various
# kernel and debug packages.  Trying to maintain correct BuildRequires has
# proven to be fragile, leading to repeated bugs as a new name format
# emerges.  Given that, we've given up, and just fail before build with a
# (hopefully) helfpul message if we can't find the headers that we need
# in the same way as the net driver spec file does.
[ -d "%{kpath}" ] || {
  set +x
  echo >&2 "ERROR: Kernel headers not found.  They should be at:"
  echo >&2 "ERROR:   %{kpath}"
%if %{redhat}
  echo >&2 "Hint: Install the $(echo '%{kernel}' | sed -r 's/(.*)(smp|hugemem|largesmp|PAE|xen)$/kernel-\2-devel-\1/; t; s/^/kernel-devel-/') package"
%else
  echo >&2 "Hint: Install the kernel-source-$(echo '%kernel}' | sed -r 's/-[^-]*$//') package"
%endif
  exit 1
}

export KPATH=%{kpath}
export HAVE_EFCT=%{?have_efct:%have_efct}
%ifarch x86_64
./scripts/onload_build %{?build_profile:--build-profile %build_profile} \
  --kernelver "%{kernel}" %{?debug:--debug}
%else
%ifarch ppc64
# Don't try to build 32-bit userland on PPC
./scripts/onload_build %{?build_profile:--build-profile %build_profile} \
  --kernelver "%{kernel}" --kernel --user64 %{?debug:--debug} %{?ppc_at:--ppc-at %ppc_at}
%else
# Don't try to build 64-bit userland in case of 32-bit userland
./scripts/onload_build %{?build_profile:--build-profile %build_profile} \
  --kernelver "%{kernel}" --kernel --user32 %{?debug:--debug} %{?ppc_at:--ppc-at %ppc_at}
%endif
%endif

%install
export i_prefix=%{buildroot}
mkdir -p "$i_prefix/etc/modprobe.d"
mkdir -p "$i_prefix/etc/depmod.d"
./scripts/onload_install --packaged \
  %{?build_profile:--build-profile %build_profile} \
  %{?debug:--debug} %{?setuid:--setuid} \
  --userfiles --modprobe --modulesloadd \
  --kernelfiles --kernelver "%{kernel}" \
  %{?with_devel: --headers}
docdir="$i_prefix%{_defaultdocdir}/%{name}-%{pkgversion}"
mkdir -p "$docdir"
install -m 644 LICENSE* README* ChangeLog* ReleaseNotes* "$docdir"
# Removing these files is fine since they would only ever be generated on a build machine.
rm -f "$i_prefix/etc/sysconfig/modules/onload.modules"
rm -f "$i_prefix/usr/local/lib/modules-load.d/onload.conf"
mkdir -p "$i_prefix/usr/share/onload"
cp ./scripts/onload_misc/onload_modules-load.d.conf $i_prefix/usr/share/onload/onload_modules-load.d.conf
cp ./scripts/onload_misc/sysconfig_onload_modules $i_prefix/usr/share/onload/sysconfig_onload_modules

%post

if [ `cat /proc/1/comm` == systemd ]
then
  mkdir -p "/usr/local/lib/modules-load.d"
  cp /usr/share/onload/onload_modules-load.d.conf /usr/local/lib/modules-load.d/onload.conf
else
  mkdir -p "/etc/sysconfig/modules"
  cp /usr/share/onload/sysconfig_onload_modules /etc/sysconfig/modules/onload.modules
fi

/sbin/onload_tool add_cplane_user
ldconfig -n /usr/lib /usr/lib64

%preun

%postun

# Remove these files only during uninstall, not during an upgrade
if [ $1 == 0 ]; then
  if [ `cat /proc/1/comm` == systemd ]; then
    rm /usr/local/lib/modules-load.d/onload.conf
  else
    rm /etc/sysconfig/modules/onload.modules
  fi
fi

ldconfig -n /usr/lib /usr/lib64


%clean
rm -fR $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/lib*/lib*.so*
%attr(644, -, -) /usr/lib*/lib*.a
%if 0%{?setuid:1}
# Ensure SETUID is present - e.g. can get lost if RPM built using mock root
%attr(6755, -, -) /usr/lib*/libonload.so
%endif
/usr/libexec/onload/apps
/usr/libexec/onload/profiles
%{_bindir}/*
%{_sbindir}/*
/sbin/*
%dir %{_includedir}/onload
%{_includedir}/onload/extensions*.h
%dir %{_includedir}/etherfabric
%{_includedir}/etherfabric/*.h
%docdir %{_defaultdocdir}/%{name}-%{pkgversion}
%attr(644, -, -) %{_defaultdocdir}/%{name}-%{pkgversion}/*
%attr(644, -, -) %{_sysconfdir}/modprobe.d/onload.conf
%attr(644, -, -) %{_sysconfdir}/depmod.d/onload.conf
%config(noreplace) %attr(644, -, -) %{_sysconfdir}/sysconfig/openonload

/usr/share/onload/onload_modules-load.d.conf
/usr/share/onload/sysconfig_onload_modules

%{python3_sitelib}/sfc*.py
%{python3_sitelib}/__pycache__/sfc*.pyc
%{python3_sitelib}/*Onload*.egg-info
%{python_sitearch}/solar_clusterd/

%changelog
* Mon Jul 1 2019 Solarflare
- 2010-current: solarflare miscellaneous updates
- Details can found in onload Changelog

* Thu Apr 1 2010 Mike MacCana <mike.maccana@credit-suisse.com> 20100308-u1
- Fixed non-cronological changelog order
- Updated to new version
- Added 'extraversion' define as version cannot have dash in it

* Wed Oct 14 2009 David Riddoch <driddoch@solarflare.com> 20090901-1
- Substantial modifications to avoid redundancy by making onload_install
  cleverer

* Thu Aug 13 2009 Derek Whayman <Derek.Whayman@barclayscapital.com> 20090409-bc001
- Initial version

* Mon Jul 27 2009 Derek Whayman <Derek.Whayman@barclayscapital.com> 20090812-bc001
- New tarball from maintainer



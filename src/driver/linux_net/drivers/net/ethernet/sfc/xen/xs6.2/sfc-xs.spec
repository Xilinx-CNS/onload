%define binsuffix %{?flavour:-%{flavour}}
%define uname  %{kernel_version}%{?flavour}

Summary: Solarflare SFC4000/SFC9000-family network controller device driver
Name: sfc
Version: %{?version}%{!?version:1.0}
Release: %{?release}%{!?release:1}
License: GPL
Group: System Environment/Kernel
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
URL: http://www.solarflare.com/
Vendor: Solarflare Communications

%description
The Linux kernel driver for Solarflare SFC4000 and SFC9000-family 10G/40G
Ethernet controllers.

For a list of supported Solarflare products, please consult the release
notes and the user guide available from https://support.solarflare.com/.

%package modules%{binsuffix}-%{kernel_version}
Summary: %{summary}
Group: %{group}
Provides: %{name}-modules%{binsuffix} = %{kernel_version}

%description modules%{binsuffix}-%{kernel_version}
The Linux kernel driver for Solarflare SFC4000 and SFC9000-family 10G/40G
Ethernet controllers.

For a list of supported Solarflare products, please consult the release
notes and the user guide available from https://support.solarflare.com/.

%prep
%setup -q -n %{name}-%{version}

%build
pushd linux_net
%{__make} -C /lib/modules/%{uname}/build M=$(pwd) modules

%install
rm -rf $RPM_BUILD_ROOT
pushd linux_net
%{__make} -C /lib/modules/%{uname}/build M=$(pwd) INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install

# mark modules executable so that strip-to-file can strip them
find $RPM_BUILD_ROOT/lib/modules/%{uname} -name "*.ko" -type f | xargs chmod u+x

%clean
rm -rf $RPM_BUILD_ROOT

%post modules%{binsuffix}-%{kernel_version}
if [ $1 -eq 1 ]; then
  depmod %{uname}
  # Rebuild the initrd if this driver may be used to access the root filesystem
  #mkinitrd -f /boot/initrd-%{uname}.img %{uname}
fi

%postun modules%{binsuffix}-%{kernel_version}
depmod %{uname} || :
#mkinitrd -f /boot/initrd-%{uname}.img %{uname} || :

%files modules%{binsuffix}-%{kernel_version}
%defattr(-,root,root,-)
/lib/modules/%{uname}/extra/*.ko
%doc

%changelog

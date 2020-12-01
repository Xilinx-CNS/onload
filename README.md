# OpenOnload(:registered:)

Onload(:registered:) is a high performance user-level network stack,
which accelerates TCP and UDP network I/O for applications using the BSD
sockets on Linux.

## Features

* Low Application-to-application latency.
* Binary compatible with existing applications.
* Open Source (GPLv2.0 and BSD-2-Clause).

OpenOnload comprises a user-level shared library that intercepts network-
related system calls and implements the protocol stack, and supporting kernel
modules. It is compatible with the full system call API, including those
aspects that are usually problematic for user-level networking, such as fork(),
exec(), passing sockets through Unix domain sockets, and advancing the
protocol when the application is not scheduled.

## Installation and Quick Start Guide

OpenOnload is distributed as source code. Instructions for building, packaging
and installing may be found in [DEVELOPING.md](DEVELOPING.md)

For each interface on which Onload is to use AF_XDP, execute the following:

```sh
echo ens2f0 > /sys/module/sfc_resource/afxdp/register
```

The application to be Onloaded should be launched by prefixing the command
line with `onload`.

## Contributors

Please see [CONTRIBUTING.md](CONTRIBUTING.md)

## Compatible network adapters, drivers and operating systems

OpenOnload can accelerate applications on operating systems with AF_XDP support.
AF_XDP support needs Linux kernel version 5.3 or later. To support zero-copy,
Onload needs AF_XDP network adapter drivers to implement the necessary AF_XDP
primitives. Typically the latest drivers from the network adapter vendors will
support these primitives.

The following operating system distributions are known to provide an adequate
level of AF_XDP support for Onload:

* Ubuntu LTS 20.04
* Ubuntu 20.10
* Debian 10 with Linux kernel 5.8
* Redhat Enterprise Linux 8.2

Onload also works with the native ef_vi hardware interface, supported by Xilinx
network adapters. In this mode of operation, AF_XDP kernel and driver support
is not required. This allows Onload to be used on older operating systems and
take advantage of additional features. A version of the 'sfc' net driver for
Xilinx network adapters is included.

### Compatible Xilinx network adapters

The following adapters at least are able to support OpenOnload without AF_XDP:

* X2541
* X2522, X2522-25G
* SFN8042
* SFN8522, SFN8542

## Support

The publicly-hosted repository is a community-supported project.

Supported releases of OpenOnload are available from
https://support-nic.xilinx.com/wp/onload

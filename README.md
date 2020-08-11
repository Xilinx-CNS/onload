# OpenOnload

Onload(R) (OpenOnload(R)) is a high performance user-level network stack, which
accelerates TCP and UDP network I/O for applications using the BSD sockets API
on Linux.

## Features

* Application-to-application latency below 1120ns.
* Send or receive millions of messages per second per CPU core.
* Binary compatible with existing applications.
* Open Source (GPLv2.0 and BSD-2-Clause).

OpenOnload comprises a user-level shared library that intercepts network-
related system calls and implements the protocol stack, and supporting kernel
modules. It is compatible with the full system call API, including those
aspects that are usually problematic for user-level networking, such as fork(),
exec(), passing sockets through Unix domain sockets, and advancing the
protocol when the application is not scheduled.

## Installation

Onload is distributed as source code. Instructions for building, packaging
and installing may be found in [DEVELOPING.md](DEVELOPING.md)

## Contributors

Please see [CONTRIBUTING.md](CONTRIBUTING.md)

## Compatible network adapters, drivers and operating systems

Onload can accelerate applications on operating systems with AF_XDP support.
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

The following adapters at least are able to support Onload without AF_XDP:

* VCU1525
* X2541, X2542
* X2522, X2522-25G
* SFN8042
* SFN8522, SFN8522M, SFN8542, SFN8722
* SFN7142Q
* SFN7122F, SFN7322F, SFN7124F

## Quick Start Guide

On each host requiring Onload to use AF_XDP, execute the following:

```sh
echo ens2f0 > /sys/module/sfc_resource/afxdp/register
```

The application to be Onloaded should be launched by prefixing the command
line with `onload`.

## Support

Supported releases of Onload are available from
https://www.xilinx.com/products/boards-and-kits/x2-series.html#onload

Xilinx offers support contracts with guaranteed service level agreements.
Please contact the Xilinx sales team for more information.

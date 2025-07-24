# OpenOnload®️

Onload®️ is a high performance user-level network stack,
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

If there are any interfaces to be accelerated by Onload which are not
AMD Solarflare interfaces, execute the following to register those interfaces
to be accelerated using AF_XDP:

```sh
echo ens2f0 > /sys/module/sfc_resource/afxdp/register
```

The application to be Onloaded should be launched by prefixing the command
line with `onload`.

## Support

The publicly-hosted repository is a community-supported project. When raising
issues on this repository it is expected that users will be running
from the head of the git tree to pick up recent changes, not using official
versions of Onload that were typically released before recent breaking kernel
changes appeared as that is likely to lead to many duplicate issues being
raised. Incompatibilities introduced by recent kernel versions are likely
to be fixed rapidly here in this repository.

Supported releases of OpenOnload are available from
<https://www.xilinx.com/support/download/nic-software-and-drivers.html#open>.
Please raise issues on _supported releases_ of Onload with
<support-nic@amd.com>.

## Compatible Linux kernels and distributions

This source tree is expected to be compatible with the following Linux kernels
and distributions:

* Debian 12+
* Ubuntu LTS 22.04+
* EL 8.6+, 9.0+, 10.0+
* kernel.org Linux kernels 5.11 - 6.14

This list differs from the list of supported operating systems in [released
versions](#support) of OpenOnload from the AMD Solarflare software download
page.

## Onload with AMD Solarflare NICs

Onload provides optimum networking acceleration and additional features using
the native ef_vi hardware interface provided by AMD Solarflare network
adapters compared to using Linux's AF_XDP mechanism. In this mode kernel and
driver support for AF_XDP is not required.

A version of the 'sfc' net driver for AMD Solarflare network adapters is
included.

### Compatible AMD Solarflare network adapters

The following adapters are able to support OpenOnload without AF_XDP:

* SFN8522, SFN8542, SFN8042
* X2522, X2522-25G, X2541
* X3522

## Onload with AF_XDP

OpenOnload can accelerate applications on non-Solarflare network adapters
with support for AF_XDP.

### Compatible network adapters, drivers and operating systems

To support zero-copy, Onload needs AF_XDP network adapter drivers to implement
the necessary AF_XDP primitives. Typically the latest drivers from the network
adapter vendors will support these primitives.

The AF_XDP support is a community-supported work in progress that is not
currently at release quality.

If a netdriver does not support AF_XDP in native mode, Onload will try to use
generic XDP mode when registering an interface. To make it work, one has to set
up userland helper before registering the interface:
```sh
$ make -C ./src/tools/bpf_link_helper/
$ echo $(realpath ./src/tools/bpf_link_helper/bpf-link-helper) | sudo tee /sys/module/sfc_resource/parameters/bpf_link_helper
```

### Building without AMD Solarflare NICs, for AF_XDP only

OpenOnload can be built without SFC driver:
* `make`: use `HAVE_SFC=0` variable;
* `onload_build` & `onload_install`: use `--no-sfc` parameter;
* `onload_tool reload`: use `--onload-only` parameter.

Also, it can be built without EFCT and AUX support:
* `make`: use `HAVE_EFCT=0` variable;
* `onload_build`: use `--no-efct` parameter.

## Contributions

Please see [CONTRIBUTING.md](CONTRIBUTING.md)

## Copyright

This file: (c) Copyright 2020-2024 Advanced Micro Devices, Inc.


Introduction
============

 OpenOnload(R) is a high performance user-level network stack, which
 delivers absolutely the best performance to applications using the BSD
 sockets API.

 OpenOnload can be built directly from the repository for testing, or packaged
 into a tarball for distribution.


Build requirements
============
 * binutils
 * gettext
 * gawk
 * gcc
 * sed
 * make
 * bash
 * which
 * kmod
 * tar
 * gzip
 * glibc-common
 * libcap-devel
 * libmnl-devel
 * perl-Test-Harness
 * gcc-c++ or g++

 You will also need to install the kernel and its development headers (i.e. kernel
 and kernel-devel) for which you wish to build against.

 Note that these dependencies are given for building on Redhat distributions, and
 package names may differ on other distributions.

 Additionally, building RPMs requires `python3-devel` and
 automatic versioning by `onload_mkdist` requires `git`.

Distributing as tarball
============

 Onload is distributed as a tarball containing code for production environments.
 The tarball can be built using the onload_mkdist script.

    scripts/onload_mkdist

 This will create the tarball at the base of the repository.

 The tarball version depends on whether the tarball is a "release" or not.
 Non-release tarballs can be produced for test setups and will be versioned
 with the current commit hash.
 Release tarballs are intended for wider distribution and will be versioned with
 the current date only.
 Use the --release option with onload_mkdist to produce release packages.

 Please follow the README included in the tarball to install Onload on the
 target machine. Note that the built tarball can be installed with `--debug`
 to enable debugging mode, which provides additional logging and error-checking.

Distributing as DEB or RPM package
==================================

To install Onload from source as DEB or RPM packages:

    ./scripts/onload_mkpackage --install

This script can also just build binary packages (omit `--install`), including
those for different Redhat-based distributions (use `--mock-config`), or
just create source packages (use `--only-source-packages`). It can also
build specific packages (eg. `--devel --user`) and variants (eg. `--debug`).

Official Onload release bundles include the mkdist tarball detailed in
'Distributing as tarball' above, along with source packages. The User Guide
details the standard distribution build tools and package managers for
installing these source packages. Alternatively, these artifacts can simply
be specified as command line arguments to `onload_mkpackage` for use as inputs
in place of the current working tree.

Distributing as container image
===============================

 To create a container image with compiled userland components
 from a mkdist tarball:

    ./scripts/onload_mkdist
    ./scripts/onload_mkcontainer --user onload-user:latest *.tgz

 Note that the Kernel modules and control plane need separate installation.
 See further documentation specific to your use case.

 To use an existing mkdist contents container image,
 add `--user-from-source onload-source:latest`.

 To create using different UBI base images, set the env var:

    USER_DOCKER_EXTRA_ARGS="--build-arg BUILDER_UBI_BASE=... --build-arg USER_BASE=..."

 To build a debug version of Onload, set the env var:

    USER_DOCKER_EXTRA_ARGS="--build-arg ONLOAD_BUILD_PARAMS=--debug"

 To only create a container image with mkdist contents:

    ./scripts/onload_mkdist
    ./scripts/onload_mkcontainer --source onload-source:latest *.tgz

 Both `--source` and `--user` can be specified at once to create both.

 Further env vars can be specified. See
   [onload-user.Dockerfile](scripts/onload-user.Dockerfile) and
   [onload_mkcontainer](scripts/onload_mkcontainer).

 These images are designed for reuse in compatible libc environments (eg. as input
 to `COPY --from=`) rather than as a base image (ie. not `FROM onload-user`).

Building directly from repository
============

 If compiling Onload during active development, or in order to run tests, it may
 be useful to build directly out of the repository, rather than packaging into a
 tarball.

 There are two separate parts that need to be compiled:
   * Driver code: Modules to be loaded into the kernel.
   * User code:   Libraries that are used to add Onload stacks to user level programs.


 Before building either of these sets of code, the make files and build tree
 needs to be constructed.  Scripts for doing this are included in the repository.

 From the top directory of a fresh checkout, to build both build trees and compile
 both parts, do:

    export PATH="$PWD/scripts:$PATH"

    mmakebuildtree --driver
    mmakebuildtree --user

    make -C "$(mmaketool --toppath)/build/$(mmaketool --driverbuild)"
    make -C "$(mmaketool --toppath)/build/$(mmaketool --userbuild)"


 Building Onload from the repository will enable debugging mode (providing additional
 logging) by default. This can be disabled by explicitly passing the following
 argument to make:

    NDEBUG=1


Onload logging
==========
**Debugging mode must be enabled to make use of additional Onload logging**

Logging can be configured in four different places:

 * Environment variables:
   * `EF_UNIX_LOG=[bitmask]` (default 0x3) User-level logging of stuff that doesn't involve a stack
   * `TP_LOG=[bitmask]` (default 0xb)
      User-level logging of stuff that involves a stack
 * Onload module options:
   * `oo_debug_bits=[bitmask]` (default 0x1, use 0x7fffffff for all)
      Kernel logging of stuff that doesn't involve a stack
   * `ci_tp_log=[bitmask]` (default 0xf)
      Kernel logging of stuff that involves a stack

Some log statements will be output in the terminal, while some will be in syslog. All messages
can be forced to go to syslog by using `EF_LOG_VIA_IOCTL`, at the cost of overhead.

The components indicated by the bits in each of these bitmasks are defined in the following
files:

 * _"tp" (i.e. transport) bits_ - src/include/ci/internal/ip_log.h
 * _EF_UNIX_LOG bits_ - src/include/ci/internal/opts_citp_def.h
 * _oo_debug_bits_ - src/include/onload/debug.h


Unit tests
==========
The user build tree includes a number of unit tests in the tests/onload/cplane_unit
and tests/onload/oof directories.

These are written in C; running "make" inside the user tree will compile each test
into a separate binary which can be run.

For convenience, we provide a script to build and run all of the tests:

    scripts/run_unit_tests.sh


Installing from repository
============

 To use Onload after building in the repository, the drivers need to be loaded
 into the kernel and the user level processes need to load Onload libraries.

 To load drivers into the kernel:

    "$(mmaketool --toppath)/build/$(mmaketool --driverbuild)/driver/linux/load.sh" onload

 Then either use the LD_PRELOAD environment variable to load applications with
 Onload, or call them with the onload script:

    LD_PRELOAD="$(mmaketool --toppath)/build/$(mmaketool --userbuild)/lib/transport/unix/libcitransport0.so" <app>

 OR

    scripts/onload <app>

Copyright
=========

This file: (c) Copyright 2020,2023 Xilinx, Inc.

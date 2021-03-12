#! /bin/sh -e

# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2020-2021 Xilinx, Inc.

my_dir=$(cd $(dirname "$0") && pwd)
top_dir=$(dirname "${my_dir}")
export PATH="${PATH}:${my_dir}"
build_dir="$(mmaketool --toppath)/build/$(mmaketool --userbuild)"


build_tests() {
    echo "Building tests"
    if [ ! -d "${build_dir}" ]; then
        mmakebuildtree --gnu
    fi
    make -C "${build_dir}"
}


run_tests() {
    echo "Running tests"
    make -C "${build_dir}/tests/onload/oof" tests
    make -C "${build_dir}/tests/onload/cplane_unit" test
    echo "All tests PASSED"
}

build_tests
run_tests

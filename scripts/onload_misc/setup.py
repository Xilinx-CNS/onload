# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2011-2019 Xilinx, Inc.
#
# Legacy definitions used for EL packaging, to be replaced
# by pymodule.toml at the top level at some future point.
#
from setuptools import setup
setup(name='OpenOnload utilities',
      version='1.0',
      py_modules=['sfcmask', 'sfcaffinity'],
      )

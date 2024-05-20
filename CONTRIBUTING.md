# Contributing guidelines

Thank you for taking your time to improve Onload. We would appreciate if you
follow the contributing guidelines to make review of changes easier.

## Submitting changes

1. Fork Onload repository on https://github.com/Xilinx-CNS/onload
2. Make local short-lived branch off of public master.
3. Develop on branch locally. Please describe the changes you have made in
the commit messages.
4. Try to follow the coding conventions used in the files you edit.
5. Push branch to your fork of Onload repository.
6. Create a new Pull Request. Please describe what testing you have done.
7. Address review comments.
8. You need to get sign-off of two other developers before the Pull Request
can be merged.

## Summary of coding conventions

In general try to follow the style that is used in the file.
Most of the files use:

1. Line length limit of 79 characters.
2. Two space indentation.
3. C style comments (no C++ style comments).
4. Opening braces are not put on their own line.
5. No space between keyword and bracket.

For instance,

```c
/* This is a comment */
if( ! conditional_expr ) {
  statement1;
  statement2;
}
```

## Compatibility

If your change is at high risk of introducing compatibilty issues, likely
in relation to interfaces provided by the kernel, please perform a build
test with one of the older supported kernels or operating systems. The
following files help with defining compatibility definitions:

* `scripts/libc_compat.sh`
* `src/include/ci/driver/kernel_compat.h`

## Copyright

This file: (c) Copyright 2020, 2024 Advanced Micro Devices, Inc.

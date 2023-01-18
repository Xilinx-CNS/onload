# Onload UL startup tests

## dtor\_test

Tests that the Onload library destructor runs after the C++ (library and class) destructors.

Build:

```
$ PATH=$PATH:$PWD/scripts make -C "$(scripts/mmaketool --toppath)/build/$(scripts/mmaketool --userbuild)"/tests/onload/startup
```

Run:
```
$ BUILD="$(scripts/mmaketool --toppath)/build/$(scripts/mmaketool --userbuild)"
$ LD_LIBRARY_PATH="${BUILD}"/tests/onload/startup scripts/onload "${BUILD}"/tests/onload/startup/dtor_test
```

The application should gracefully exit.

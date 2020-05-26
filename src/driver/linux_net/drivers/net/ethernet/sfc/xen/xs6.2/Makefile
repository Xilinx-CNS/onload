# the following values must be changed
SPEC := sfc-xs.spec
VENDOR_CODE := sfc
VENDOR_NAME := Solarflare Communications
LABEL = $(DRIVER_NAME)
TEXT := Solarflare driver for XS62

# versioning of pack
PACK_VERSION = $(XENSERVER_VERSION)
PACK_BUILD = $(XENSERVER_BUILD)

# versioning of kernel module RPMs
RPM_VERSION := 4.4.1.1020
RPM_RELEASE := 1

# no changes below here
RPMROOT := /usr/src/redhat
ARCH := i386
FLAVOURS := xen kdump
XENSERVER_VERSION := $(shell set -- `tr '-' ' ' </etc/redhat-release` && echo $$4)
XENSERVER_BUILD := $(shell set -- `tr '-' ' ' </etc/redhat-release` && echo $$5)
KERNEL_VERSION := $(subst xen,,$(shell uname -r))
DRIVER_NAME := $(shell sed -ne 's/^Name: *//p' $(SPEC))
ISO := $(DRIVER_NAME).iso
ISO_MD5 := $(ISO).md5
TAR := $(DRIVER_NAME).tar.gz
METADATA_MD5 := $(DRIVER_NAME).metadata.md5

RPMS := $(patsubst %, $(DRIVER_NAME)-modules-%-$(KERNEL_VERSION)-$(RPM_VERSION)-$(RPM_RELEASE), $(FLAVOURS))
RPM_FILES := $(patsubst %, $(RPMROOT)/RPMS/$(ARCH)/%.$(ARCH).rpm, $(RPMS))


build-iso: build-rpms
	python setup.py --output=$(dir $(ISO)) --iso --vendor-code=$(VENDOR_CODE) "--vendor-name=$(VENDOR_NAME)" --label=$(LABEL) "--text=$(TEXT)" --version=$(PACK_VERSION) --build=$(PACK_BUILD) $(RPM_FILES)

build-tarball: build-rpms
	python setup.py --output=$(dir $(ISO)) --tar --vendor-code=$(VENDOR_CODE) "--vendor-name=$(VENDOR_NAME)" --label=$(LABEL) "--text=$(TEXT)" --version=$(PACK_VERSION) --build=$(PACK_BUILD) $(RPM_FILES)

build-rpms:
	for flavour in xen kdump; do \
	rpmbuild -bb --define "kernel_version $(KERNEL_VERSION)" --define "flavour $$flavour" --define "version $(RPM_VERSION)" --define "release $(RPM_RELEASE)" $(SPEC); \
	done

build-srctarballs:
	tar zcvf $(RPMROOT)/SOURCES/$(DRIVER_NAME)-$(RPM_VERSION).tar.gz $(DRIVER_NAME)-$(RPM_VERSION)

clean:
	rm -f $(ISO) $(ISO_MD5) $(TAR) $(METADATA_MD5)

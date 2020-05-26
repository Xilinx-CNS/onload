# Kernel source directory
ifndef KPATH
KPATH := /lib/modules/$(shell uname -r)/build
endif

KERNEL_DOC := $(KPATH)/scripts/kernel-doc
sources := $(shell grep -l '^/\*\*\( \|$$\)' ../*.[ch])

all : doc

doc : clean
	mkdir html
	@# On the first run, show warnings/errors except Perl warnings
	$(KERNEL_DOC) -html $(sources) 2>&1 >html/index.html \
	| grep -v '^Use of uninitialized value in '
	mkdir man
	@# On the second run, don't repeat them
	$(KERNEL_DOC) -man $(sources) 2>/dev/null | ./split-man.pl man

clean :
	rm -rf html man

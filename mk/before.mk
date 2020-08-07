# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.
######################################################################
# Make the key variables globally visible.
#
export TOPPATH
export BUILD
export BUILDPATH
export CURRENT
export THISDIR
export PLATFORM
export VPATH
export VPATH_ENABLED
export SUBDIRS
export IMPORT
export BUILD_TREE_COPY
export DRIVER
export DRIVER_TYPE
export DRIVER_SIZE
export MAKE_SANITY_DONE
export MAKEWORLD
export INSTALLER

# Ensure these environment variables are not inherited.
cflags :=
cppflags :=
cxxflags :=
export cflags
export cppflags
export cxxflags


######################################################################
# Cancel some built-in rules.
#
%.o: %.c
%.o: %.cc
%:   %.c
%:   %.cc
%:   %.o


######################################################################
# Include directories.
#
MMAKE_INCLUDE_DIR	:= $(TOPPATH)/src/include
MMAKE_INCLUDE		:= -I. -I$(BUILD)/include -I$(MMAKE_INCLUDE_DIR)



######################################################################
# Some useful commands.
#
SUBDIRS	:=
DRIVER_SUBDIRS :=
INSTALLER_SUBDIRS :=

define MakeAllSubdirs
([ "$$subdirs" = "" ] && subdirs='$(SUBDIRS) $(OTHER_SUBDIRS)'; \
 [ "$$target" = "" ]  && target='$@'; \
 for d in $$subdirs ; do \
   [ ! -d "$$d" ] || $(MAKE) -C "$$d" $(passthruparams) "$$target" || exit ; done \
)
endef

ifeq ($(MAKECMDGOALS),world)

MAKEWORLD:=1

endif

ifeq ($(MAKEWORLD),1)

MakeSubdirs=$(MakeAllSubdirs)

else 

define MakeSubdirs
([ "$$subdirs" = "" ] && subdirs='$(SUBDIRS)'; \
 [ "$$target" = "" ]  && target='$@'; \
 for d in $$subdirs ; do \
   [ ! -d "$$d" ] || $(MAKE) -C "$$d" $(passthruparams) "$$target" || exit ; done \
)
endef

endif


define MakeClean
rm -f *.a *.so *.o *.ko *.d *.lib *.dll *.exp *.pdb $(TARGET) $(TARGETS); $(MakeAllSubdirs)
endef


######################################################################
# Misc.
#

# Other makefiles may define rules before we get to the makefile in the
# directory, but we don't want them to be the default!
default_all:	all

.PHONY: all clean lib default buildtree

# Do not delete intermediates (needed for dependancy checks).
.SECONDARY:

nullstring:=
space=$(nullstring) #<-do not edit this line

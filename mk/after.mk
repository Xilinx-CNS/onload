# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
######################################################################
# Sanity checks (correct build path and platform?)
#
ifndef MAKE_SANITY_DONE # only do sanity checks on first make, not recursive makes
MAKE_SANITY_DONE:=1
platform := $(shell cat $(BUILD)/mmake_platform)
ifneq ($(platform),$(PLATFORM))
$(shell echo >&2 "Platform inconsistency. Run mmakebuildtree again.")
$(error Platform inconsistency. Run mmakebuildtree again.)
endif
buildpath := $(shell mmaketool --buildpath)
ifeq ($(buildpath),)
$(shell echo >&2 "Please ensure mmaketool is the path.")
$(error Please ensure mmaketool is the path.)
endif
ifneq ($(buildpath),$(BUILDPATH))
$(shell echo >&2 "Build path inconsistency. Run mmakebuildtree again.")
$(error Build path inconsistency. Run mmakebuildtree again.)
endif

ifneq ($(BUILDENV),)
buildenv := $(shell mmaketool --distribution)-$(shell gcc -dumpmachine)

ifneq ($(buildenv),$(BUILDENV))
$(shell echo >&2 "********** Warning: building on different host environment. **********")
$(shell echo >&2 "**********          wanted='$(BUILDENV)' got='$(buildenv)'")
ifdef DRIVER
$(error Build host inconsistency for driver build.)
endif
endif
endif

# NDEBUG must be undefined, or defined as 1.
ifdef NDEBUG
ifneq ($(NDEBUG),1)
$(error NDEBUG must be undefined, or defined as 1.)
endif
endif

endif

######################################################################
# Get lists of source files.

MMAKE_ORIG_SRCS := \
    $(filter-out $(addprefix $(TOPPATH)/$(CURRENT)/,$(MMAKE_GEN_SRCS)), \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.S) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.inc) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.inf) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.inx) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.rc) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.def) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.c) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.cc) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.h) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.mof) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.manifest) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.mc) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.ico) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.cs) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.resx) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.sln) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.csproj) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.settings) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.config) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.datasource) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.user) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.bmp) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.asm) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.ldpre) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.plist) \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.common) \
    $(addprefix $(TOPPATH)/$(CURRENT)/,$(IMPORT)))

MMAKE_C_SRCS := $(notdir $(filter %.c, ${MMAKE_ORIG_SRCS}))
MMAKE_CXX_SRCS := $(notdir $(filter %.cc, ${MMAKE_ORIG_SRCS}))
MMAKE_LDPRE_SRCS := $(notdir $(filter %.ldpre, ${MMAKE_ORIG_SRCS}))
MMAKE_S_SRCS := $(notdir $(filter %.S, ${MMAKE_ORIG_SRCS}))

# list of files that should always be copied
MMAKE_COPY_SRCS := \
    $(wildcard $(TOPPATH)/$(CURRENT)/*.sh)

######################################################################
# Set up stuff for VPATH

IMPORT :=$(sort $(IMPORT))

ifndef VPATH_ENABLED
$(error VPATH_ENABLED not set, please remove your existing build tree and rerun mmakebuildtree)
endif

ifeq ($(VPATH_ENABLED),1)

VPATH := $(VPATH) $(TOPPATH)/$(CURRENT) $(addprefix $(TOPPATH)/$(CURRENT)/,$(sort $(dir $(IMPORT))))

VPATH_INCLUDES := $(addprefix -I,$(VPATH))
MMAKE_INCLUDE		:= $(MMAKE_INCLUDE) $(VPATH_INCLUDES)

endif # ifeq ($(VPATH_ENABLED),1)

######################################################################
# Do file copying

ifndef MMAKEBUILDTREE

ifeq ($(VPATH_ENABLED),1)

copy.done: ${MMAKE_COPY_SRCS} $(TOPPATH)/$(CURRENT)/mmake.mk $(TOPPATH)/mk/after.mk
	@for SRC in ${MMAKE_COPY_SRCS} _o ; do \
	    if [ "$$SRC" != "_o" ]; then \
		DST=`basename "$$SRC"` ; \
	        if /usr/bin/env test \( \! -f "$$DST" \) -o \( "$$DST" -ot "$$SRC" \) ; then \
                    cp -f "$$SRC" "$$DST" ; \
	            chmod -w "$$DST" ; \
	      	fi ; \
	    fi ; \
	done
	@touch "$@"

else  # ifeq ($(VPATH_ENABLED),1) ... else

copy.done: ${MMAKE_COPY_SRCS} ${MMAKE_ORIG_SRCS} $(TOPPATH)/$(CURRENT)/mmake.mk $(TOPPATH)/mk/after.mk
	@for SRC in ${MMAKE_ORIG_SRCS} ${MMAKE_COPY_SRCS}; do \
	    DST=`basename "$$SRC"` ; \
	    if [ \( \! -f "$$DST" \) -o \( "$$DST" -ot "$$SRC" \) ] ; then \
	        cp -f "$$SRC" "$$DST" ; \
	        chmod -w "$$DST" ; \
	    fi ; \
	done
	@touch "$@"

endif  # ifeq ($(VPATH_ENABLED),1

# The contents of the file don't matter, but this forces its
# dependencies to be rebuilt.  DON'T UPDATE THE TIMESTAMP ON THE FILE
# UNLESS NECESSARY BECAUSE THAT WOULD CAUSE THE MAKEFILE TO BE REREAD.
# Don't use "echo -n" because Solaris doesn't support that.
copy.depends: copy.done
	@[ -f "$@" ] || echo >$@
sinclude copy.depends

endif # ifndef MMAKEBUILDTREE

######################################################################
# How to compile C and C++ sources.
#
$(MMAKE_OBJ_PREFIX)%.o: %.c
	$(MMakeCompileC)

$(MMAKE_OBJ_PREFIX)%.o: %.cc
	$(MMakeCompileCXX)

$(MMAKE_OBJ_PREFIX)%.o: %.cpp
	$(MMakeCompileCXX)

$(MMAKE_OBJ_PREFIX)%.o: %.cxx
	$(MMakeCompileCXX)

$(MMAKE_OBJ_PREFIX)%.o: %.S
	$(MMakeCompileASM)

ifeq ($(DRIVER),1)
MMAKE_TYPE	:= $(MMAKE_TYPE)_DRIVER
endif

ifeq ($(INSTALLER),1)
MMAKE_TYPE	:= $(MMAKE_TYPE)_INSTALLER
endif

mmake_c_compile = $(MMAKE_INCLUDE)
mmake_c_compile += $(MMAKE_DIR_CPPFLAGS) $(CPPFLAGS) $(MMAKE_CPPFLAGS)
mmake_c_compile += $(MMAKE_CFLAGS_$(MMAKE_TYPE)) $(MMAKE_DIR_CFLAGS)
mmake_c_compile += $(MMAKE_CFLAGS) $(CFLAGS)

mmake_masm_compile = $(MMAKE_INCLUDE)

mmake_cxx_compile = $(MMAKE_INCLUDE)
mmake_cxx_compile += $(MMAKE_DIR_CPPFLAGS) $(CPPFLAGS) $(MMAKE_CPPFLAGS)
mmake_cxx_compile += $(MMAKE_CXXFLAGS_$(MMAKE_TYPE)) $(MMAKE_DIR_CXXFLAGS)
mmake_cxx_compile += $(MMAKE_CXXFLAGS) $(CXXFLAGS)

ifeq ($(DRIVER),1)
SUBDIRS := $(DRIVER_SUBDIRS)
OTHER_SUBDIRS := $(OTHER_DRIVER_SUBDIRS)
endif

ifeq ($(INSTALLER),1)
SUBDIRS := $(INSTALLER_SUBDIRS)
OTHER_SUBDIRS := $(OTHER_INSTALLER_SUBDIRS)
endif


######################################################################
# Default rule for single-source apps.
#
$(AppPattern): %.o $(MMAKE_LIB_DEPS)
	@(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))


######################################################################
# Generate dependencies automagically :-)
#
ifndef MMAKE_NO_DEPS

ifneq ($(MAKECMDGOALS),clean) # don't make dependencies for clean

ifdef USE_MAKEDEPEND

MMAKE_DEPS_CXX_OPT:=$(mmake_cxx_compile)
MMAKE_DEPS_C_OPT:=$(mmake_c_compile)

MMAKE_DEPS_C_OPT:=-nostdinc -Y. 

makedepend.d: $(MMAKE_C_SRCS) $(MMAKE_CXX_SRCS)
	@echo Generating dependencies
	@makedepend -f-  -- $(MMAKE_DEPS_C_OPT) -- $(filter %.cc,$^) $(filter %.c,$^)  2>/dev/null |    \
	 sed 's/^.*[/]\([^/]*\)\.o[ :]*/$(MMAKE_OBJ_PREFIX)\1.o $@ : /g' >$@




ifneq ($(strip $(MMAKE_C_SRCS)$(MMAKE_CXX_SRCS)),)
sinclude makedepend.d
endif

else  # ifdef USE_MAKEDEPEND

ifndef MMAKE_USE_KBUILD
%.d: %.c
	@set -e; $(CC) $(mmake_c_compile) -M $< 2>/dev/null |    \
	 sed 's/\($*\)\.o[ :]*/$(MMAKE_OBJ_PREFIX)\1.o $@ : /g' >$@
	@[ -s $@ ] || rm -f $@

%.d: %.cc
	@set -e; $(CXX) $(mmake_cxx_compile) -M $< 2>/dev/null |  \
	 sed 's/\($*\)\.o[ :]*/$(MMAKE_OBJ_PREFIX)\1.o $@ : /g' >$@
	@[ -s $@ ] || rm -f $@

ifneq ($(MMAKE_C_SRCS),)
sinclude $(subst .c,.d,$(MMAKE_C_SRCS))
endif

ifneq ($(MMAKE_CXX_SRCS),)
sinclude $(subst .cc,.d,$(MMAKE_CXX_SRCS))
endif

ifneq ($(MMAKE_DBI_SRCS),)
sinclude $(subst .dbi,.d,$(MMAKE_DBI_SRCS))
endif


endif  # ifdef MMAKE_USE_KBUILD

endif  # ifdef USE_MAKEDEPEND

endif  # ifneq ($(MAKECMDGOALS),clean)
endif  # ifndef MMAKE_NO_DEPS


######################################################################
# Some targets.
#
.PHONY: lndir
lndir:
	lndir "$(TOPPATH)/$(CURRENT)"

.PHONY: force
force: clean
	$(MAKE) all

.PRECIOUS: $(MMAKE_PRECIOUS)

.PHONY: relink
relink:
	rm -f $(TARGET) $(TARGETS); $(MAKE) $(TARGET) $(TARGETS)


######################################################################
# Misc stuff to help various scripts.
#

# For mmakebuildtree
.PHONY: buildtree
buildtree:
	@mmakebuildtree_gen
	@cd "$(TOPPATH)/$(CURRENT)" && for dir in $(SUBDIRS) $(OTHER_SUBDIRS) ""; do if [ -d "$$dir" ]; then echo "$$dir"; fi; done

.PHONY: echo_subdirs
echo_subdirs:
	@cd "$(TOPPATH)/$(CURRENT)" && for dir in $(SUBDIRS) $(OTHER_SUBDIRS) ""; do if [ -d "$$dir" ]; then echo "$$dir"; fi; done

# For mmakerelease
.PHONY: echo_targets
echo_targets:
	@echo $(TARGETS) $(TARGET)

.PHONY: world
world: all


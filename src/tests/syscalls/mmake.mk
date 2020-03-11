read		:= $(patsubst %,$(AppPattern),read)
write		:= $(patsubst %,$(AppPattern),write)
writev		:= $(patsubst %,$(AppPattern),writev)
dup     	:= $(patsubst %,$(AppPattern),dup)
streams 	:= $(patsubst %,$(AppPattern),streams)
execve		:= $(patsubst %,$(AppPattern),execve)
printf		:= $(patsubst %,$(AppPattern),printf)
ci_log		:= $(patsubst %,$(AppPattern),ci_log)
close		:= $(patsubst %,$(AppPattern),close)
sendfile	:= $(patsubst %,$(AppPattern),sendfile)
sendfile_clnt	:= $(patsubst %,$(AppPattern),sendfile_clnt)
splice		:= $(patsubst %,$(AppPattern),splice)

TARGETS	:= $(read) $(write) $(writev) $(printf) $(ci_log) $(dup) $(streams) \
	   $(execve) $(close) $(splice)

ifeq ($(GNU),1)
TARGETS	+= $(sendfile) $(sendfile_clnt)
endif

all: $(TARGETS)

clean:
	@$(MakeClean)

$(ci_log): ci_log.o $(CITOOLS_LIB_DEPEND)
	libs="$(LINK_CITOOLS_LIB)"; $(MMakeLinkCApp)

$(dup): dup.o $(CITOOLS_LIB_DEPEND) $(CIAPP_LIB_DEPEND) $(LINK_CIUL_LIB_DEPEND)
	libs="$(LINK_CIAPP_LIB) $(LINK_CIUL_LIB) $(LINK_CITOOLS_LIB) -ldl -lrt"; $(MMakeLinkCApp)

$(streams): streams.o $(CITOOLS_LIB_DEPEND) $(CIAPP_LIB_DEPEND)
	libs="$(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB) -ldl -lrt"; $(MMakeLinkCApp)


ifneq ($(strip $(USE_SSL)),)

MMAKE_INCLUDE += -I /usr/kerberos/include

sendfile.o: sendfile.c $(MMAKE_LIB_DEPS)
	$(CC) $(mmake_c_compile) -DUSE_SSL -c $< -o $@
sendfile_clnt.o: sendfile_clnt.c $(MMAKE_LIB_DEPS)
	$(CC) $(mmake_c_compile) -DUSE_SSL -lpthread -c $< -o $@

$(sendfile): sendfile.o $(CITOOLS_LIB_DEPEND) $(CIAPP_LIB_DEPEND)
	libs="$(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB) -lrt -lssl"; $(MMakeLinkCApp)
$(sendfile_clnt): sendfile_clnt.o $(CITOOLS_LIB_DEPEND) $(CIAPP_LIB_DEPEND)
	libs="$(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB) -lrt -lssl"; $(MMakeLinkCApp)

else

$(sendfile): sendfile.o $(CITOOLS_LIB_DEPEND) $(CIAPP_LIB_DEPEND)
	libs="$(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB) -lrt"; $(MMakeLinkCApp)
$(sendfile_clnt): sendfile_clnt.o $(CITOOLS_LIB_DEPEND) $(CIAPP_LIB_DEPEND)
	libs="$(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB) -lrt"; $(MMakeLinkCApp)

endif

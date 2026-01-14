# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2014-2020 Xilinx, Inc.

APPS := orm_json

SRCS := orm_json orm_json_lib

OBJS := $(patsubst %,%.o,$(SRCS))
OBJS += $(TOPPATH)/src/tools/ip/libstack.o

MMAKE_LIB_DEPS	:= $(CIIP_LIB_DEPEND) $(CIAPP_LIB_DEPEND) \
		   $(CITOOLS_LIB_DEPEND) $(CIUL_LIB_DEPEND) \
		   $(CPLANE_LIB_DEPEND)

ifeq  ($(shell CC="${CC}" CFLAGS="${CFLAGS} ${MMAKE_CFLAGS}" check_library_presence pcap.h pcap 2>/dev/null),1)
MMAKE_LIBS_LIBPCAP=-lpcap
CFLAGS += -DCI_HAVE_PCAP=1
else
CFLAGS += -DCI_HAVE_PCAP=0
endif

ifeq  ($(shell CC="${CC}" CFLAGS="${CFLAGS} ${MMAKE_CFLAGS}" check_library_presence czmq.h czmq 2>/dev/null),1)
APPS	+= orm_zmq_publisher zmq_subscriber
ZMQ_LIBS	:= -lzmq -lczmq
ZMQ_INCS	:= -I/usr/include
endif

MMAKE_LIBS	:= $(LINK_CIIP_LIB) $(LINK_CIAPP_LIB) $(MMAKE_LIBS_LIBPCAP) \
		   $(LINK_CITOOLS_LIB) $(LINK_CIUL_LIB) \
		   -lpthread $(LINK_CPLANE_LIB)
MMAKE_INCLUDE	+= -I$(TOPPATH)/src/tools/ip

LIBS      += $(MMAKE_LIBS) $(ZMQ_LIBS)
INCS      += $(MMAKE_INCLUDE) $(ZMQ_INCS)
DEPS      += $(OBJS) $(MMAKE_LIB_DEPS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

all: $(APPS)

orm_json: $(DEPS)
	(libs="$(LIBS)"; $(MMakeLinkCApp))

orm_zmq_publisher: orm_zmq_publisher.o orm_json_lib.o $(TOPPATH)/src/tools/ip/libstack.o
	(libs="$(LIBS)"; $(MMakeLinkCApp))

zmq_subscriber: zmq_subscriber.o
	(libs="$(LIBS)"; $(MMakeLinkCApp))

clean:
	@$(MakeClean)
	rm -f *.o $(APPS)

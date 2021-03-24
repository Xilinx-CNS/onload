/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

/* BPF program to redirect inbound packets to AF_XDP sockets.
 *
 * Currently, this is not built automatically and requires manual translation
 * to the binary data loaded by xdp_prog_load (see af_xdp.c). One approach is:
 *
 * 1. Obtain a compiler which can produce BPF. This example uses clang.
 *
 * 2. Compile this file:
 *     $ clang -target bpf -O2 -c af_xdp_bpf.c
 *   (use -DUSE_SHADOW_MAP=1 to compile for older kernels)
 *
 * 3. Extract the bytecode from the compiled object. Objdump gives a reasonable
 *    starting point:
 *     $ objdump -s -j .text af_xdp_bpf.o
 *
 *    You'll probably need to invert the byte order to get nice 64-bit values.
 *    A ghastly sed script can do that, assuming objdump's output format is
 *    reasonably consistent:
 *      /^ /!d;      # filter out lines without leading space
 *      s/^ \S* //;  # remove address from start of line
 *      s/  .*$//;   # remove ASCII representation from end of line
 *      s/\(\S\S\)\(\S\S\)\(\S\S\)\(\S\S\)/\4\3\2\1/g;  # swap bytes in words
 *      s/\(\S\{8\}\) \(\S\{8\}\)/0x\2\1,/g;            # swap and combine words
 *
 * 4. Identify the instructions which need adjusting to reference the BPF maps.
 *
 *    Objdump can report their offsets from the relocation entries:
 *     $ objdump -r af_xdp_bpf.o
 *
 *    These instructions typically have an opcode like 0x0118: load(18)
 *    immediate value(0) into register(1), in order to pass to a function.
 *
 *    The adjustments needed are:
 *     * change 0 to 1 in the fourth nibble of the opcode (the "source" field)
 *       to indicate a map reference (e.g. 0x0118->0x1118)
 *     * at runtime, insert the map's file descriptor into the upper 32 bits of
 *       the opcode (the "immediate value" field).
 */

#include <linux/bpf.h>

#define ETHERTYPE_VLAN 0x0081
#define ETHERTYPE_IPv4 0x0008

/* We do not handle IPv6 yet, see ON-12563 */
#define ETHERTYPE_IPv6 0xdd86

#define PROTO_TCP 6
#define PROTO_UDP 17

extern struct bpf_map_def xsks_map;

static int (*bpf_redirect_map)(void *map, int key, int flags) =
        (void *) BPF_FUNC_redirect_map;

int xdp_sock_prog(struct xdp_md *ctx)
{
  char* data = (char*)(long)ctx->data;
  char* end = (char*)(long)ctx->data_end;

  /* Guarantee that any offsets below are within limits:
   * Ethernet header + vlan header + IP header. */
  if( data + 14 + 4 + 20 > end )
    return XDP_PASS;

  /* Pass broadcast packets */
  if( (*(unsigned long*)data & 0xffffffffffff) == 0xffffffffffff )
    return XDP_PASS;

  unsigned short ethertype = *(unsigned short*)(data+12);
  if( ethertype == ETHERTYPE_VLAN ) {
    data += 4;
    ethertype = *(unsigned short*)(data+12);
  }

  unsigned char proto;
  if( ethertype == ETHERTYPE_IPv4 )
    proto = *(unsigned char*)(data+23);
  else
    /* Todo: add IPv6 support when we can do IPv6 filters.
     * It should be present in cloud build only.
     */
    return XDP_PASS;

  if( proto != PROTO_TCP && proto != PROTO_UDP )
    return XDP_PASS;

  int index = ctx->rx_queue_index;
  return bpf_redirect_map(&xsks_map, index, XDP_PASS);
}


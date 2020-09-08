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
#define ETHERTYPE_IPv6 0xdd86

#define PROTO_TCP 6
#define PROTO_UDP 17

extern struct bpf_map_def xsks_map;
extern struct bpf_map_def shadow_map;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
        (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_redirect_map)(void *map, int key, int flags) =
        (void *) BPF_FUNC_redirect_map;

int xdp_sock_prog(struct xdp_md *ctx)
{
  char* data = (char*)(long)ctx->data;
  char* end = (char*)(long)ctx->data_end;
  if( data + 14 + 20 > end )
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
  else if( ethertype == ETHERTYPE_IPv6 )
    proto = *(unsigned char*)(data+20);
  else
    return XDP_PASS;

  if( proto != PROTO_TCP && proto != PROTO_UDP )
    return XDP_PASS;

  int index = ctx->rx_queue_index;
  int rc = bpf_redirect_map(&xsks_map, index, XDP_PASS);
  if( rc != XDP_ABORTED )
    return rc;

  /* Workaround for older kernels (pre-5.3) which do not support passing a
   * fallback action to bpf_redirect_map. We need to check the shadow map to
   * figure out whether the redirection should succeed, and return XDP_PASS
   * otherwise.
   *
   * We need the shadow map in addition to the socket map because older kernels
   * also don't support lookup on a socket map.
   */
  if( ! bpf_map_lookup_elem(&shadow_map, &index) )
    return XDP_PASS;

  return bpf_redirect_map(&xsks_map, index, 0);
}


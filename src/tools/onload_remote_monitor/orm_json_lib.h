/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/* flags to control which info gets output */
#define ORM_OUTPUT_NONE 0
#define ORM_OUTPUT_STATS 0x1
#define ORM_OUTPUT_MORE_STATS 0x2
#define ORM_OUTPUT_TCP_STATS_COUNT 0x4
#define ORM_OUTPUT_TCP_EXT_STATS_COUNT 0x8
#define ORM_OUTPUT_STACK 0x10
#define ORM_OUTPUT_SOCKETS 0x20
#define ORM_OUTPUT_VIS 0x40
#define ORM_OUTPUT_OPTS 0x100
#define ORM_OUTPUT_EXTRA 0x100000
#define ORM_OUTPUT_LOTS 0xFFFFF
#define ORM_OUTPUT_SUM (ORM_OUTPUT_STATS | ORM_OUTPUT_MORE_STATS | \
                        ORM_OUTPUT_TCP_STATS_COUNT | \
                        ORM_OUTPUT_TCP_EXT_STATS_COUNT)

struct orm_cfg {
  const char* stackname;
  const char* filter;
  bool sum;
  bool meta;
  bool flat;
};

/* Convert argv[] to output_flags for orm_do_dump()
 * Returns -EINVAL if any unrecognised options are provided
 */
extern int orm_parse_output_flags(int argc, const char* const* argv);

/* Generate JSON output to the given stream
 * Return 0 on success, or negative error code
 */
extern int orm_do_dump(const struct orm_cfg* cfg, int output_flags,
                       FILE* output_stream);


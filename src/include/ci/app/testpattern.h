/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */

#ifndef __CI_APP_TESTPATTERN_H__
#define __CI_APP_TESTPATTERN_H__


/*! Comment? */
extern void ci_write_dword_pattern(volatile void* p, unsigned len_dwords);
/*! Comment? */
extern int  ci_check_dword_pattern(const volatile void* p, unsigned len_dwords,
				   int analyse_errors, int start_off);

/*! Comment? */
extern void ci_byte_pattern_write(volatile void* p, unsigned len_bytes,
				  unsigned start_n, ci_uint8 seed);

extern int  ci_byte_pattern_check(const volatile void* p, unsigned len_bytes,
				  unsigned start_n, ci_uint8 seed,
				  int analyse_errors, int start_off);
  /*!< Returns true if pattern is okay, 0 otherwise. */

extern int  ci_byte_pattern_valid(const volatile void* p, unsigned len_bytes,
				  unsigned* start_n_out, ci_uint8* seed_out);
  /*!< Returns true if the buffer contains a valid pattern.  Note that the
  ** value returned in [start_n_out] is only correct modulo 256.
  */

extern void ci_byte_pattern_repeat(volatile void* buf, int buf_bytes,
				   const void* patn, int patn_bytes);
  /*!< Copies the pattern into the buffer repeatedly. */

/* The following standard patterns are recognised by the byte pattern
** checking code.
*/
#define CI_DEADBEEF    CI_BSWAPC_BE32(0xDEADBEEF)
#define CI_CABBAGES    CI_BSWAPC_BE32(0xCABBA9E5)
#define CI_DECEASED    CI_BSWAPC_BE32(0xDECEA5ED)
#define CI_DEADCODE    CI_BSWAPC_BE32(0xDEADC0DE)
#define CI_ACCESSED    CI_BSWAPC_BE32(0xACCE55ED)
#define CI_DEFFACED    CI_BSWAPC_BE32(0xDEFFACED)

ci_inline void ci_byte_pattern(volatile void* buf, int buf_bytes,
			       ci_uint32 pattern)
{ ci_byte_pattern_repeat(buf, buf_bytes, &pattern, sizeof(pattern)); }
  /*!< Use this to write one of the above 'standard' patterns. */

extern int ci_byte_pattern_find(const void* buf, int buf_bytes,
				ci_uint32 pattern);
  /*!< Returns offset at which [pattern] (written by ci_byte_pattern())
  ** starts, or [buf_bytes] if the whole pattern has been overwritten.
  */

/*! Return an unsigned 2's complement sum of the data. */
extern ci_uint8  ci_sum_bytes(const volatile void* p, unsigned len_bytes);
/*! Return an unsigned 2's complement sum of the data. */
extern ci_uint32 ci_sum_dwords(const volatile void* p, unsigned len_dwords);


/**********************************************************************
 ** Ethernet test packet.
 */

/*! Comment? */
typedef struct {
  ci_ether_hdr     hdr;
  ci_uint16        len_le16;  /*!< length of test pattern     */
  ci_uint32        seq_le32;  /*!< increasing sequence number */
  /*! test pattern follows... */
} ci_test_ethpkt_t;


#define CI_TEST_ETHPKT_MIN_LEN    (sizeof(ci_test_ethpkt_t) + 4)


extern void ci_test_ethpkt_write(volatile void* buf,
				 unsigned total_pkt_len, unsigned seq);
  /*!< NB. Doesn't write anything into the ethernet header. */

extern int  ci_test_ethpkt_check(const volatile void* pkt,
				 unsigned seq_expected, int analyse_errors);
  /*!< Returns true if the packet is okay, 0 otherwise.  Use 0 for
  ** [seq_expected] if you don't care.
  */


#endif  /* __CI_APP_TESTPATTERN_H__ */

/*! \cidoxg_end */

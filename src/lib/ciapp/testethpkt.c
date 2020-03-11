/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>


#define CI_TEST_ETHPKT_MAX_LEN  (ETH_FRAME_LEN - sizeof(ci_test_ethpkt_t))


void ci_test_ethpkt_write(volatile void* pkt, unsigned len, unsigned seq)
{
  ci_test_ethpkt_t* p;

  ci_assert(pkt);
  ci_assert(len >= CI_TEST_ETHPKT_MIN_LEN);
  ci_assert(len <= ETH_FRAME_LEN);

  p = (ci_test_ethpkt_t*) pkt;
  len -= sizeof(ci_test_ethpkt_t);

  p->len_le16 = CI_BSWAP_LE16(len);
  p->seq_le32 = CI_BSWAP_LE32(seq);

  ci_byte_pattern_write((char*) p + sizeof(ci_test_ethpkt_t),
			len, len, (ci_uint8) seq);
}


int  ci_test_ethpkt_check(const volatile void* pkt, unsigned seq_expected,
			  int analyse_errors)
{
  const ci_test_ethpkt_t* p;
  unsigned len, seq;
  int bad = 0;

  ci_assert(pkt);

  p = (const ci_test_ethpkt_t*) pkt;
  len = CI_BSWAP_LE16(p->len_le16);
  seq = CI_BSWAP_LE32(p->seq_le32);

  if( seq_expected && seq != seq_expected ) {
    bad = 1;
    if( analyse_errors )
      ci_log("ci_test_ethpkt_check: wrong seq (0x%x != 0x%x)",
	     seq, seq_expected);
  }
  if( len > CI_TEST_ETHPKT_MAX_LEN ) {
    bad = 1;
    if( analyse_errors )
      ci_log("ci_test_ethpkt_check: bad len (%u > %u)",
	     len, (unsigned) CI_TEST_ETHPKT_MAX_LEN);
    len = CI_TEST_ETHPKT_MAX_LEN;
  }
  if( len < CI_TEST_ETHPKT_MIN_LEN ) {
    bad = 1;
    if( analyse_errors )
      ci_log("ci_test_ethpkt_check: bad len (%u < %u)",
	     len, (unsigned) CI_TEST_ETHPKT_MIN_LEN);
  }

  if( !ci_byte_pattern_check((char*) p + sizeof(ci_test_ethpkt_t),
			     len, len, (ci_uint8) seq, 0,
			     sizeof(ci_test_ethpkt_t)) ) {
    bad = 1;
    if( analyse_errors ) {
      ci_log("ci_test_ethpkt_check: bad test pattern (seq=%u bytes=%u)",
	     seq, len);
      if( ci_byte_pattern_check((char*) p + sizeof(ci_test_ethpkt_t),
				len, len, (ci_uint8) seq_expected, 0,
				sizeof(ci_test_ethpkt_t)) ) {
	ci_log("ci_test_ethpkt_check: pattern okay (seq == %u)", seq_expected);
      }
      else {
	/* analyse this time... */
	ci_byte_pattern_check((char*) p + sizeof(ci_test_ethpkt_t),
			      len, len, (ci_uint8) seq, 1,
			      sizeof(ci_test_ethpkt_t));
      }
    }
  }

  return !bad;
}

/*! \cidoxg_end */

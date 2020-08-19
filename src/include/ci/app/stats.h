/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
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

#ifndef __CI_APP_STATS_H__
#define __CI_APP_STATS_H__


/*! Comment? */
extern void ci_iarray_mean_and_limits(const int* start, const int* end,
			       int* mean_out, int* min_out, int* max_out);

/*! Comment? */
extern void ci_iarray_variance(const int* start, const int* end,
				int mean, ci_int64* variance_out);

/*! Comment? */
extern int ci_qsort_compare_int(const void*, const void*);

/*! Comment? */
extern void ci_iarray_median(const int* s, const int* e, int* median_out);

/*! Comment? */
extern void ci_iarray_mode(const int* start, const int* end, int* mode_out);


#if CI_INCLUDE_ASSERT_VALID
	/*! Comment? */
  extern void ci_iarray_assert_valid(const int* start, const int* end);
	/*! Comment? */
  extern void ci_iarray_assert_sorted(const int* start, const int* end);
#else
# define ci_iarray_assert_valid(s,e)
# define ci_iarray_assert_sorted(s,e)
#endif


#endif  /* __CI_APP_STATS_H__ */

/*! \cidoxg_end */

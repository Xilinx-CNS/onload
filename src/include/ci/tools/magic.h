/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Magic number checks for non-copyable objects.
**   \date  2003/04/25
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_MAGIC_H__
#define __CI_TOOLS_MAGIC_H__


#define CI_DO_MAGIC_CHECKS  1


typedef unsigned int ci_magic_t;


# define CI_MAGIC(p, type) \
  (((unsigned int)(type) << 28) | \
   (((unsigned int)(ci_ptr_arith_t)(p)) & 0x0fffffffu))


#if ! CI_DO_MAGIC_CHECKS

# define CI_MAGIC_SET(p, type)
# define CI_MAGIC_CLEAR(p, type)
# define CI_MAGIC_CHECK_TYPE(p, type)
# define CI_MAGIC_OKAY(p, type)    1
# define CI_MAGIC_CHECK(p, type)

#else

# define CI_MAGIC_SET(p, type) \
  do { \
    (p)->magic = CI_MAGIC((p), (type)); \
  } while (0)

# define CI_MAGIC_CLEAR(p, type) \
  do { \
    (p)->magic = !CI_MAGIC((p), !(type)); \
  } while (0)

# define CI_MAGIC_CHECK_TYPE(p, type) \
  do { \
    ci_assert_equal((((p)->magic & 0xf0000000u) >> 28), \
                    (unsigned int)(type)); \
  } while (0)

# define CI_MAGIC_OKAY(p, type) \
  ((p)->magic == CI_MAGIC((p), (type)))

# define CI_MAGIC_CHECK(p, type) \
  do { \
    if (!CI_MAGIC_OKAY((p), (type))) \
      ci_fail(("MAGIC CHECK FAIL: %p, %x, %x", (p),	(p)->magic, \
              CI_MAGIC((p),(type))));	\
  } while(0)

#endif


#endif  /* __CI_TOOLS_MAGIC_H__ */

/*! \cidoxg_end */

/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author cgg
**  \brief Header file for ci_user_opts_t struct.
**   \date 17/01/2006
**    \cop (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci */

#ifndef __USER_OPTS_H__
#define __USER_OPTS_H__


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
  /* These fields are defined in a separate file that is also used by the 
  ** configuration subsystem
  */
#define _CI_CFG_BITFIELD
#define _CI_CFG_BITFIELD1  :1
#define _CI_CFG_BITFIELD2  :2
#define _CI_CFG_BITFIELD3  :3
#define _CI_CFG_BITFIELD4  :4
#define _CI_CFG_BITFIELD8  :8
#define _CI_CFG_BITFIELD16 :16
#define _CI_CFG_BITFIELDA8 CI_ALIGN(8)
    
#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_OPTGROUP

#define CI_CFG_OPTFILE_VERSION(version)
#define CI_CFG_OPTGROUP(group, category, expertise)
#define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, presentation) \
        type name _CI_CFG_BITFIELD##bits;

#include <ci/internal/opts_user_def.h>
} ci_user_opts_t;


#ifdef __cplusplus
}
#endif


#endif  /* __USER_OPTS_H__ */

/*! \cidoxg_end */

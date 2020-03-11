#ifndef __EF_VI_EF100_H__
#define __EF_VI_EF100_H__

#include "ef100_hw_defs.h"
#include "logging.h"

ef_vi_inline void
ef100_unsupported_msg(const char *func_name)
{
  ef_log("ERROR: %s is not supported", func_name);
#ifndef __KERNEL__
  abort();
#endif
}

#endif  /* __EF_VI_EF100_H__ */

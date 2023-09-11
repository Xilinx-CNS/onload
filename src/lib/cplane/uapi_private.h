#ifndef INCLUDED_LIB_CPLANE_UAPI_PRIVATE_H_
#define INCLUDED_LIB_CPLANE_UAPI_PRIVATE_H_
#include <cplane/api.h>
#include <cplane/cplane.h>

#define EF_CP_PUBLIC_API __attribute__((visibility("default")))

struct llap_extra {
  void *cookie;
  bool is_registered;
};

struct ef_cp_handle {
  int drv_fd;
  struct oo_cplane_handle cp;
  struct llap_extra *llap_extra;
};

#endif

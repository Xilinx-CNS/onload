#ifndef __OOF_TEST_ONLOAD_KERNEL_COMPAT_H__
#define __OOF_TEST_ONLOAD_KERNEL_COMPAT_H__

#include <ci/kcompat.h>

struct net;
extern void put_net(struct net* net);
extern struct net* get_net(struct net* net);

struct seq_file;
static inline void seq_printf(struct seq_file *m, const char *fmt, ...)
{
}

#endif /* __OOF_TEST_ONLOAD_KERNEL_COMPAT_H__ */

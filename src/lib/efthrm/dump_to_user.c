/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <onload/drv/dump_to_user.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>


struct dump_to_buf {
  char* buf;
  int   buf_len;
  int   off;
};


static void oo_dump_to_buf(void* opaque, const char* fmt, ...)
{
  struct dump_to_buf* ds = opaque;
  va_list args;
  int rc;
  if( ds->off >= 0 && ds->off < ds->buf_len ) {
    va_start(args, fmt);
    rc = vsnprintf(ds->buf + ds->off, ds->buf_len - ds->off, fmt, args);
    va_end(args);
    if( rc < 0 ) {
      ds->off = -1;
    }
    else if( rc >= ds->buf_len - ds->off ) {
      /* vsnprintf() will return a larger value to indicate how many
       * bytes it would have written.  Simplify this to "the buffer is
       * full" 
       */
      ds->off = ds->buf_len;
    }
    else {
      ds->off += rc;
      if( ds->off < ds->buf_len )
        ds->buf[ds->off++] = '\n';
      if( ds->off < ds->buf_len )
        ds->buf[ds->off] = '\0';
    }
  }
}


int oo_dump_to_user(oo_dump_fn_t dump_fn, void* dump_fn_arg,
                    void* user_buf, int user_buf_len)
{
  struct dump_to_buf ds;
  int rc;
  ds.buf_len = 4096;
  while( 1 ) {
    ds.buf = vmalloc(ds.buf_len);
    if( ds.buf == NULL )
      return -ENOMEM;
    ds.off = 0;
    dump_fn(dump_fn_arg, oo_dump_to_buf, &ds);
    if( ds.off < 0 ) {
      rc = -EBADE;
      break;
    }
    if( ds.off < ds.buf_len ) {
      ++ds.off;  /* Include terminator. */
      rc = ds.off;
      if( ds.off <= user_buf_len && copy_to_user(user_buf, ds.buf, ds.off) )
        rc = -EFAULT;
      break;
    }
    vfree(ds.buf);
    ds.buf_len *= 2;
  }
  vfree(ds.buf);
  return rc;
}

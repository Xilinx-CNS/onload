/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  Andrew Rybchenko
**  \brief  Memory leaks debugging
**   \date  2004/10/05
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_citools */

#include <ci/tools.h>

#ifdef __ci_driver__

#if CI_MEMLEAK_DEBUG_ALLOC_TABLE

#define ci_alloc_table_lock()   lock_kernel()
#define ci_alloc_table_unlock() unlock_kernel()


/*!
 * Add address, size and call-site information in allocation table.
 *
 * \param addr      Address
 * \param size      Size of the memory block
 * \param type      Type of allocation (k/v)malloc (0/1)
 * \param file      Filename of call-site
 * \param ln        Line number of call-site
 */
void
ci_alloc_table_add(void *addr, size_t size, int type, const char *file, unsigned ln)
{
  struct ci_alloc_entry *entry = NULL;
  unsigned int           sz;
  unsigned int           i;

again:
  sz = ci_alloc_table_sz;
  for (i = 0; i < sz; ++i) {
    entry = &(ci_alloc_table[i >> CI_ALLOC_TABLE_BULK_2]
                            [i & (CI_ALLOC_TABLE_BULK_SZ - 1)]);
    if (entry->file == NULL)
      break;
  }
  if (i == sz) {
    struct ci_alloc_entry *new_table;
    
    new_table = __ci_alloc(sizeof(struct ci_alloc_entry) *
                             CI_ALLOC_TABLE_BULK_SZ);
    if (new_table == NULL) {
      ci_log("%s: malloc() of ci_alloc_table element failed", __FUNCTION__);
      return;
    }
    /* Preset table by zeros */
    memset(new_table, 0,
           sizeof(struct ci_alloc_entry) * CI_ALLOC_TABLE_BULK_SZ);
    ci_alloc_table_lock();
    if (sz != ci_alloc_table_sz) {
      ci_alloc_table_unlock();
      __ci_free(new_table);
      ci_log("%s: ci_alloc_table_sz has beed changed, try again",
             __FUNCTION__);
      goto again;
    }
    ci_alloc_table[ci_alloc_table_sz >> CI_ALLOC_TABLE_BULK_2] = new_table;
    ci_alloc_table_sz += CI_ALLOC_TABLE_BULK_SZ;
    ci_alloc_table_unlock();
    ci_log("%s: new ci_alloc_table size is %u",
           __FUNCTION__, ci_alloc_table_sz);
    /* Get the first entry in new table */
    entry = new_table;
  }
  ci_alloc_table_lock();
  if (entry->file != NULL) {
    ci_alloc_table_unlock();
    ci_log("%s: estimated entry has just been used, try again", __FUNCTION__);
    goto again;
  }
  entry->addr   = addr;
  entry->size   = size;
  entry->type   = type;
  entry->file   = file;
  entry->line   = ln;
  ci_alloc_table_unlock();
}


/*!
 * Delete address from allocation table.
 *
 * \param addr      Target address
 * \param type      Type of allocation (k/v)malloc (0/1)
 */
void
ci_alloc_table_del(void *addr, int type) {
  struct ci_alloc_entry *entry;
  unsigned int           i;

  for (i = 0; i < ci_alloc_table_sz; ++i) {
    entry = &(ci_alloc_table[i >> CI_ALLOC_TABLE_BULK_2]
                            [i & (CI_ALLOC_TABLE_BULK_SZ - 1)]);
    if ((entry->file != NULL) && 
        (entry->addr == addr) &&
        (entry->type == type)) {
      entry->file = NULL;
      return;
    }
  }
  ci_backtrace();
  ci_log("%s: ERROR unable to unregister from ci_alloc_table (addr=%p, type=%s)", 
          __FUNCTION__, addr, type?"vfree":"free");

}

void ci_alloc_memleak_test(void) {
  int bulk, memleakcount=0, i, pos;
  for (i = 0; i < ci_alloc_table_sz; ++i) {
    bulk=i>>CI_ALLOC_TABLE_BULK_2;
    pos=i&(CI_ALLOC_TABLE_BULK_SZ-1);
    if (ci_alloc_table[bulk][pos].file != NULL) {
      if ( memleakcount == 0) {
        ci_log("WARNING: POTENTIAL MEMORY LEAK DETECTED:");
        ci_log("Type   Caller    Size (bytes)");
      }
      ci_log("%d     %s:%u    %lu",
             ci_alloc_table[bulk][pos].type,
             ci_alloc_table[bulk][pos].file,
             ci_alloc_table[bulk][pos].line,
             (unsigned long)ci_alloc_table[bulk][pos].size);
      memleakcount++;
    }
  }
  if (!memleakcount)
  {
    ci_log("No memory leaks have been detected");
  }
}

struct call_site {
    const char *file;
    unsigned    line;
    unsigned    allocs;
    size_t      total;
};

/* Called for /proc population of memory leaks */
int ci_alloc_memleak_readproc (char *buf, char **start, off_t offset,
                               int count, int *eof, void *data)
{
  enum {call_sites_max = 1024};
  static struct call_site call_sites [call_sites_max];
  unsigned call_sites_n = 0;
  unsigned i;
  int bulk, pos;
  int len;

  ci_alloc_table_lock();
  memset (&call_sites, 0, sizeof call_sites);

  len = 1 + snprintf (buf, count, "%d allocations outstanding.%s\n",
                      ci_alloc_table_sz,
                      ci_alloc_table_sz ? "  Top offenders are:" : "");
  if (len > count) len = count;
  count -= len;

  for (i = 0; i < ci_alloc_table_sz; ++i) {
    int j=0;
    bulk=i>>CI_ALLOC_TABLE_BULK_2;
    pos=i&(CI_ALLOC_TABLE_BULK_SZ-1);

    if (ci_alloc_table [bulk][pos].size == 0) continue;

    /* First - let's see if we're already counting this call-site */
    for (j = 0; j < call_sites_n; j++) {
      if ((call_sites [j].file == ci_alloc_table [bulk][pos].file) &&
          (call_sites [j].line == ci_alloc_table [bulk][pos].line)) {
        call_sites [j].allocs++;
        call_sites [j].total += ci_alloc_table [bulk][pos].size;
        break;
      }
    }

    /* Nope - haven't seen that call-site yet */
    if (j == call_sites_n && call_sites_n < call_sites_max) {
      /* New call-site */
      call_sites [j].file = ci_alloc_table [bulk][pos].file;
      call_sites [j].line = ci_alloc_table [bulk][pos].line;
      call_sites [j].allocs = 1;
      call_sites [j].total = ci_alloc_table [bulk][pos].size;
      call_sites_n++;
    }
  }

  /* Now sort the list of call-sites (most offending first).
   * -- just do a dumb bubble sort in the interests of simplicity
   */
  for (i = 0; i < call_sites_max; i++) {
    int j;
    for (j = 0; j < call_sites_max - 1 - i; j++) {
      if (call_sites [j].total < 
          call_sites [j+1].total) {
        /* swap */
        struct call_site temp = call_sites [j];
        call_sites [j] = call_sites [j+1];
        call_sites [j+1] = temp;
      }
    }
  }

  *eof = 1;
  for (i = 0; i < call_sites_n; i++) {
    size_t s = snprintf (buf + len, count, "%s:%u %lu bytes in %u allocs\n",
                         call_sites [i].file, call_sites [i].line,
                         (unsigned long)call_sites [i].total, call_sites [i].allocs);
    if (s >= count) {
      *eof = 0;
      len += (count+1);
      break;
    }
    len +=   (s+1);
    count -= (s+1);
  }

  ci_alloc_table_unlock();
  return len;
}


#endif /* CI_MEMLEAK_DEBUG_ALLOC_TABLE */


/*--------------------------------------------------------------------
 *
 *
 *--------------------------------------------------------------------*/

// non-zero enables this support - find value from /boot/System.map-??? file
// - 0xc04caa80  for 2.4.21-15
// - 0xc04d3aa0  for 2.4.21-32 
// - 0xc042c584  for 2.6.9-5.ELsmp
// - 0xc0439084  for 2.6.9-22.ELsmp
//                   (all 32-bit)
#define LINUX_VM_LIST_LOCATION  0


#if LINUX_VM_LIST_LOCATION

#include <linux/vmalloc.h>	

/* paste these into files for debugging
extern int  vmarea_get_current_number(void);
extern void vmarea_store_initial_state(void);
extern void vmarea_compare_with_initial_state(void);
*/

/* for holding snapshot of VM statuis on driver load */
#define NO_VMALLOC_ADDR 1024
void * vmalloc_addr[NO_VMALLOC_ADDR];

/* returns a count of the the number of VM areas */
int 
vmarea_get_current_number(void)
{
  struct vm_struct **p, *tmp;
  int i;

  i=0;
  for (p = (struct vm_struct **)LINUX_VM_LIST_LOCATION; 
      (tmp = *p) != NULL ;
      p = &tmp->next) {
    i++;
  }
  return i;
}

/* store state on driver load */
void
vmarea_store_initial_state(void)
{
  struct vm_struct **p, *tmp;
  int i = 0;

  ci_log("%s - assuming vmlist is at = 0x%x, STAND BACK", 
          __FUNCTION__, LINUX_VM_LIST_LOCATION);
  for (p = (struct vm_struct **)LINUX_VM_LIST_LOCATION; 
       (tmp = *p) != NULL;
       p = &tmp->next) {
    if (i < NO_VMALLOC_ADDR)
      vmalloc_addr[i] = tmp->addr;
    i++;
  }
  ci_log("%s: %d vm_areas in total at startup", __FUNCTION__, i);
}

/* compare on driver unload */
void
vmarea_compare_with_initial_state(void)
{
  struct vm_struct **p, *tmp;
  int i, count=0, found;

  for (p = (struct vm_struct **)LINUX_VM_LIST_LOCATION; 
       (tmp = *p) != NULL;
       p = &tmp->next) {
    
    count++;

    found = 0;
    for(i=0; i < NO_VMALLOC_ADDR;i++) {
      if (tmp->addr == vmalloc_addr[i]) {
        found = 1;
        vmalloc_addr[i] = 0;
        break;
      }
    }
    if (!found) {
      ci_log("%s: likely vm leak - addr=%p size=%ld, flags=0x%lx", 
                  __FUNCTION__, tmp->addr, tmp->size, tmp->flags);
    }
  }
  ci_log("%s: %d at unload ----------", __FUNCTION__, count);
}
#endif

/*--------------------------------------------------------------------
 *
 *
 *--------------------------------------------------------------------*/



/*--------------------------------------------------------------------
 *
 *
 *--------------------------------------------------------------------*/

#endif /* __ci_driver__ */

/*! \cidoxg_end */

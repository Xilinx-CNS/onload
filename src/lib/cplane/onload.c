/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
/* Cplane interface to be used from Onload */
#include <cplane/cplane.h>
#include <cplane/mmap.h>

#ifdef __KERNEL__
#include <ci/driver/kernel_compat.h>
#else
#include <cplane/create.h>
#endif

#ifdef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__
#error "don't include ci/internal/transport_config_opt.h from binary-only code"
#endif


#ifndef __KERNEL__
/* Maps the shared memory regions that are used as the interface between the
 * control plane and its clients.  On failure, this function will clean up any
 * partially-initialised state. */
int
oo_cp_create(int fd, struct oo_cplane_handle* cp, enum cp_sync_mode mode,
             ci_uint32 flags)
{
  static const ci_uint32 SUPPORTED_FLAGS = CP_CREATE_FLAGS_INIT_NET;

  size_t fwd_offset, fwd_len, fwd_rw_offset, fwd_rw_len;

  struct cp_mibs* mibs = cp->mib;
  int rc;
  void* mib_mem;
  void* fwd_mem;
  ci_uint32 op;

  if( flags & ~SUPPORTED_FLAGS )
    return -EINVAL;

  /* Check user-kernel interface version. */
  rc = cp_ioctl(fd, OO_IOC_CP_CHECK_VERSION, &oo_cplane_api_version);
  if( rc != 0 )
    return rc;

  /* If the caller has requested init_net, we need to associate the file with
   * that instance before we do any other cplane ioctls. */
  if( flags & CP_CREATE_FLAGS_INIT_NET ) {
    op = CP_SELECT_INSTANCE_INIT_NET;
    rc = cp_ioctl(fd, OO_IOC_CP_SELECT_INSTANCE, &op);
    if( rc != 0 ) {
      ci_log("ERROR: failed to select control plane instance: %s",
             strerror(-rc));
      return rc;
    }
  }

  /* Wait for the control plane server to start if necessary.  This ioctl does
   * an interruptible sleep while waiting.  If a non-fatal signal is received
   * while we're asleep, the ioctl will fail with EINTR, and we want to try
   * again. */
  op = mode;
  do {
    rc = cp_ioctl(fd, OO_IOC_CP_WAIT_FOR_SERVER, &op);
  } while( rc == -EINTR );
  if( rc != 0 )
    return rc;

  /* Find out the MIB size */
  rc = cp_ioctl(fd, OO_IOC_CP_MIB_SIZE, &cp->bytes);
  if( rc != 0 )
    return rc;

  ci_assert(cp->bytes);
  ci_assert_equal(cp->bytes & (CI_PAGE_SIZE - 1), 0);

  /* Mmap MIBs */
  mib_mem = mmap(NULL, cp->bytes, PROT_READ , MAP_SHARED, fd,
                 OO_MMAP_MAKE_OFFSET(OO_MMAP_TYPE_CPLANE,
                                     OO_MMAP_CPLANE_ID_MIB));
  if( mib_mem == MAP_FAILED ) {
    ci_log("ERROR: failed to mmap cplane MIBs: %s", strerror(errno));
    return -errno;
  }

  /* Build MIBs */
  mibs[1].dim = mibs[0].dim = mib_mem;
  cp_init_mibs(mib_mem, mibs);

  /* Mmap fwd (and associated fields) memory */
#ifdef CP_SYSUNIT
  fwd_len = CP_SHIM_FWD_BYTES;
#else
  fwd_len = CI_ROUND_UP(cp_calc_fwd_blob_size(mibs[0].dim), CI_PAGE_SIZE);
#endif
  fwd_offset = CP_MMAP_LOCAL_FWD_OFFSET();
  fwd_mem = mmap(NULL, fwd_len, PROT_READ, MAP_SHARED, fd, fwd_offset);
  if( fwd_mem == MAP_FAILED ) {
    ci_log("ERROR: failed to mmap fwd part of Control Plane memory: %s",
           strerror(errno));
    rc = -errno;
    munmap(mib_mem, cp->bytes);
    return rc;
  }
  mibs[0].fwd_table.mask = mibs[1].fwd_table.mask = mibs->dim->fwd_mask;
  cp_init_mibs_fwd_blob(fwd_mem, mibs);

  /* Mmap fwd_rw memory */
#ifdef CP_SYSUNIT
  fwd_rw_len = CP_SHIM_FWD_RW_BYTES;
#else
  fwd_rw_len = CI_ROUND_UP(cp_calc_fwd_rw_size(mibs[0].dim), CI_PAGE_SIZE);
#endif
  fwd_rw_offset = CP_MMAP_LOCAL_FWD_RW_OFFSET();
  mibs[1].fwd_table.rw_rows = mibs[0].fwd_table.rw_rows = mmap(
          NULL, fwd_rw_len, PROT_READ | PROT_WRITE, MAP_SHARED,
          fd, fwd_rw_offset);
  if( mibs[0].fwd_table.rw_rows == MAP_FAILED ) {
    ci_log("ERROR: failed to mmap fwd_rw part of Control Plane memory: %s",
           strerror(errno));
    rc = -errno;
    munmap(fwd_mem, CI_ROUND_UP(cp_calc_fwd_blob_size(mibs[0].dim),
                                CI_PAGE_SIZE));
    munmap(mib_mem, cp->bytes);
    return rc;
  }

  cp->fd = fd;

  return 0;
}

/* Tear down the mappings of the control plane.  Necessary only if
 * oo_cp_create() succeeded. */
void
oo_cp_destroy(struct oo_cplane_handle* cp)
{
  munmap(cp->mib->fwd_table.rows, /* rows pointer is equivalent to fwd_blob */
         CI_ROUND_UP(cp_calc_fwd_blob_size(cp->mib->dim), CI_PAGE_SIZE));
  munmap(cp->mib->fwd_table.rw_rows,
         CI_ROUND_UP(cp_calc_fwd_rw_size(cp->mib->dim), CI_PAGE_SIZE));
  munmap(cp->mib->dim, cp->bytes);
}
#endif

#if !defined(__KERNEL__)
static int
oo_op_route_resolve(struct oo_cplane_handle* cp, struct cp_fwd_key* key)
{
  int rc;

  rc = cp_ioctl(cp->fd, OO_IOC_CP_FWD_RESOLVE, key);
  /* Fixme: should we re-start in case of EAGAIN? */
  if( rc < 0 )
    return rc;
  return 0;
}
#endif


#ifdef __KERNEL__
static DEFINE_PER_CPU(unsigned, seed);
#endif
static int oo_cp_multipath_hash(struct cp_fwd_key* key, int max)
{
  /* We'd better use hash from the key and some data from the connection -
   * ports, socket_id, etc.
   * However we do not have enough info here, and it is not easy to pass such
   * data.  So we just do a very basic pseudo-random number generator.
   *
   * The specific LCRNG parameters here are taken from the C spec's
   * recommendation.
   */

  unsigned p;
#define NEXT_SEED(seed) (1103515245 * (seed) + 12345)
#ifdef __KERNEL__
  /* NB: not worrying about the possibility of preemption in this function.
   * It'll just make the randomness slightly lower quality.
   * See also the comments for raw_cpu_read in
   * driver/linux_affinity/kernel_compat.h. */
  p = NEXT_SEED(raw_cpu_read(seed));
  raw_cpu_write(seed, p);
#else
  static __thread unsigned seed = 0;
  seed = p = NEXT_SEED(seed);
#endif
  return ((p >> 16) & 0x7fff) % max;
}

int __oo_cp_route_resolve(struct oo_cplane_handle* cp,
                          cicp_verinfo_t* verinfo,
                          struct cp_fwd_key* key,
                          int/*bool*/ ask_server,
                          struct cp_fwd_data* data,
                          cp_fwd_table_id fwd_table_id)
{
  struct cp_fwd_table* fwd_table = oo_cp_get_fwd_table(cp, fwd_table_id);
  cp_version_t ver, old_ver;
  cicp_mac_rowid_t id;
  struct cp_fwd_row* fwd;
  int first_pass = 1;
  ci_uint32 weight = CP_FWD_MULTIPATH_WEIGHT_NONE;

 find_again:
  id = cp_fwd_find_match(fwd_table, key, weight);
  if( id == CICP_MAC_ROWID_BAD ||
      ~(fwd = cp_get_fwd_by_id(fwd_table, id))->flags &
        CICP_FWD_FLAG_DATA_VALID ||
      ! cp_fwd_find_row_found_perfect_match(fwd_table, id, key) ) {
    if( ! ask_server )
      return -ENOENT;
    oo_op_route_resolve(cp, key CI_KERNEL_ARG(fwd_table_id));
    ask_server = CI_FALSE;
    first_pass = 1;
    weight = CP_FWD_MULTIPATH_WEIGHT_NONE;
    goto find_again;
  }

  ver = OO_ACCESS_ONCE(*cp_fwd_version(fwd));
  do {
    if( ~ fwd->flags & CICP_FWD_FLAG_DATA_VALID ||
        ! cp_fwd_key_match(fwd, key) )
        goto find_again;
    ci_rmb();
    *data = *cp_get_fwd_data_current(fwd);
    if( first_pass && data->weight.end > 1 ) {
      weight = oo_cp_multipath_hash(key, data->weight.end);
      first_pass = 0;
      if( ! cp_fwd_weight_match(weight, &data->weight) )
        goto find_again;
    }

    /* We can accidentally increase TTL for a wrong row  - we do not care */
    if( fwd->flags & CICP_FWD_FLAG_STALE )
      fwd_table->rw_rows[id].frc_used = ci_frc64_get();
    old_ver = ver;
    ci_rmb();
  } while( old_ver != (ver = OO_ACCESS_ONCE(*cp_fwd_version(fwd))) );

  verinfo->id = id;
  verinfo->version = ver;

  /* Cplane server will refresh ARP when it reads rw_rows[id], but it may
   * happen after some time.  Ask for the ARP immediately.
   * This also guarantees that we do not stick in ARP_FAILED state
   * without trying to re-resolve the MAC address when a new socket starts
   * using it.
   */
  if( ask_server && ! (data->flags & CICP_FWD_DATA_FLAG_ARP_VALID) )
    oo_cp_arp_resolve(cp, verinfo, fwd_table_id);
  return 0;
}

int
oo_cp_get_hwport_properties(struct oo_cplane_handle* cp, ci_hwport_id_t hwport,
                            cp_hwport_flags_t* out_mib_flags,
                            cp_nic_flags_t* out_nic_flags,
                            cp_xdp_prog_id_t* out_xdp_prog_id)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int rc;

  CP_VERLOCK_START(version, mib, cp)

  rc = 0;

  if( cicp_hwport_row_is_free(&mib->hwport[hwport]) ) {
    rc = -ENOENT;
    goto out;
  }

  if( out_mib_flags != NULL )
    *out_mib_flags = mib->hwport[hwport].flags;
  if( out_nic_flags != NULL )
    *out_nic_flags = mib->hwport[hwport].nic_flags;
  if( out_xdp_prog_id != NULL )
    *out_xdp_prog_id = mib->hwport[hwport].xdp_prog_id;

 out:
  CP_VERLOCK_STOP(version, mib)
  return rc;
}


ci_ifid_t
oo_cp_get_hwport_ifindex(struct oo_cplane_handle* cp, ci_hwport_id_t hwport)
{
  struct cp_mibs* mib;
  cp_version_t version;
  ci_ifid_t ifindex;

  ci_assert(cp);

  CP_VERLOCK_START(version, mib, cp)
  ifindex = cp_get_hwport_ifindex(mib, hwport);
  CP_VERLOCK_STOP(version, mib)

  return ifindex;
}


#ifdef __KERNEL__

/* Retrieves all hwports that allows Onload to run.  The return
 * value is a bitmap of hwports. */
cicp_hwport_mask_t oo_cp_get_hwports(struct oo_cplane_handle* cp)
{
  struct cp_mibs* mib;
  cp_version_t version;
  cicp_hwport_mask_t all_hwports = 0;

  ci_assert(cp);

  CP_VERLOCK_START(version, mib, cp)

  all_hwports =
    cp_get_hwports(mib,
                   cp_hwport_make_mask(mib->dim->hwport_max) - 1);

  CP_VERLOCK_STOP(version, mib)

  return all_hwports;
}


int oo_cp_get_acceleratable_llap_count(struct oo_cplane_handle* cp)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int llap_count = 0;

  ci_assert(cp);

  CP_VERLOCK_START(version, mib, cp)
  llap_count = cp_get_acceleratable_llap_count(mib);
  CP_VERLOCK_STOP(version, mib)

  return llap_count;
}


/* The current use-case for this function is the installation of scalable
 * filters on all interfaces.  Otherwise, iterating over ifindices is probably
 * the wrong approach. */
int oo_cp_get_acceleratable_ifindices(struct oo_cplane_handle* cp,
                                      ci_ifid_t* ifindices, int max_count)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int llap_count = 0;

  ci_assert(cp);

  CP_VERLOCK_START(version, mib, cp)
  llap_count = cp_get_acceleratable_ifindices(mib, ifindices, max_count);
  CP_VERLOCK_STOP(version, mib)

  return llap_count;
}

#endif

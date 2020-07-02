/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>

#include <etherfabric/base.h>
#include <etherfabric/pd.h>
#include <etherfabric/internal/cluster_protocol.h>
#include "ef_vi_internal.h"
#include "logging.h"


#define DEFAULT_GETPW_R_BUF_SIZE 1024
static char* get_username(void)
{
  struct passwd passwd;
  char* user = NULL;
  int buf_size;
  char* buf;
  struct passwd* result;
  uid_t uid;
  int rc;

  buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
  if( buf_size == -1 )
    buf_size = DEFAULT_GETPW_R_BUF_SIZE;

  buf = malloc(buf_size);
  if( buf == NULL ) {
    LOG(ef_log("%s: ERROR: malloc(%d) failed: %d",
               __FUNCTION__, buf_size, errno));
    return NULL;
  }

  uid = getuid();
  rc = getpwuid_r(uid, &passwd, buf, buf_size, &result);
  if( rc != 0) {
    LOG(ef_log("%s: ERROR: getpwuid_r(buf_size=%d) failed: %d",
               __FUNCTION__, buf_size, rc));
    errno = rc;
  }
  else if( result == NULL ) {
    errno = ENOENT;
  }
  else {
    user = strdup(result->pw_name);
  }

  free(buf);
  return user;
}


/* Connect to solar_clusterd.  Returns socket to daemon on success or
 * negative error code on failure.
 */
static int clusterd_connect(int* sock_out)
{
  struct sockaddr_un sockaddr;
  char* user;
  char* sock_path;
  int rc;

  if( (*sock_out = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 )
    return -errno;

  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sun_family = AF_UNIX;

  if( (sock_path = getenv("EF_VI_CLUSTER_SOCKET")) != NULL ) {
    strncpy(sockaddr.sun_path, sock_path, sizeof(sockaddr.sun_path) - 1);
  }
  else {
    user = get_username();
    if( user == NULL )
      return -errno;

    rc = asprintf(&sock_path, "%s%s/%s", DEFAULT_CLUSTERD_DIR, user,
                  DEFAULT_CLUSTERD_SOCK_NAME);
    free(user);
    if( rc < 0 )
      return -errno;
    strncpy(sockaddr.sun_path, sock_path, sizeof(sockaddr.sun_path) - 1);
    free(sock_path);
  }

  if( connect(*sock_out, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0 ) {
    close(*sock_out);
    return -errno;
  }

  return 0;
}


/* Receive a response message from the clusterd, optionally with a
 * file descriptor.
 */
static int clusterd_recv(int sock, char* resp_buf, int resp_buflen, int* fd_out)
{
  struct msghdr hdr;
  struct cmsghdr* chdr;
  struct iovec data;
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  int rc;

  data.iov_base = resp_buf;
  data.iov_len = resp_buflen;

  memset(&hdr, 0, sizeof(hdr));
  hdr.msg_iov = &data;
  hdr.msg_iovlen = 1;
  hdr.msg_control = cmsgbuf;
  hdr.msg_controllen = sizeof(cmsgbuf);

  rc = recvmsg(sock, &hdr, 0);
  if( rc < 0 ) {
    LOG(ef_log("%s: ERROR: recv() failed: %d", __FUNCTION__, errno));
    return -errno;
  }
  if( rc == 0 ) {
    LOG(ef_log("%s: ERROR: unexpected EOF in recv()", __FUNCTION__));
    return -EOF;
  }
  resp_buf[rc] = '\0';

  if( fd_out ) {
    chdr = CMSG_FIRSTHDR(&hdr);
    if( chdr && chdr->cmsg_len == CMSG_LEN(sizeof(int)) &&
        chdr->cmsg_level == SOL_SOCKET &&
        chdr->cmsg_type == SCM_RIGHTS )
      memmove(fd_out, CMSG_DATA(chdr), sizeof(int));
  }

  return 0;
}


static int clusterd_check_version(int sock, int my_version)
{
  char* req_buf;
  int rc, req_buf_len, nargs;
  char resp_buf[16];
  int reply, result;

  /* Send query request */
  req_buf_len = asprintf(&req_buf, "%d %d\n", CLUSTERD_VERSION_REQ, my_version);
  if( req_buf_len < 0 ) {
    LOG(ef_log("%s: ERROR: asprintf() failed: %d", __FUNCTION__, -errno));
    return -errno;
  }
  rc = send(sock, req_buf, req_buf_len, MSG_NOSIGNAL);
  free(req_buf);
  if( rc != req_buf_len ) {
    LOG(ef_log("%s: ERROR: send() failed: %d", __FUNCTION__, -errno));
    return -errno;
  }

  /* Read reply */
  rc = clusterd_recv(sock, resp_buf, sizeof(resp_buf), NULL);
  if( rc < 0 ) {
    LOG(ef_log("%s: ERROR: clusterd_recv() failed: %d", __FUNCTION__, rc));
    return rc;
  }

  nargs = sscanf(resp_buf, "%d %d", &reply, &result);
  if( nargs == 2 ) {
    if( reply == CLUSTERD_VERSION_RESP ) {
      if( result == CLUSTERD_ERR_SUCCESS )
        return 0;
      else if( result == CLUSTERD_ERR_FAIL )
        return -EBADRQC;
    }
  }
  LOG(ef_log("%s: ERROR: Unexpected reponse from daemon.  Wanted 2, got %d",
             __FUNCTION__, nargs));
  return -EIO;
}


/* Send an alloc cluster request and receive response.
 */
static int clusterd_alloc_cluster(int sock, const char* cluster_name,
                                  enum ef_pd_flags pd_flags,
                                  ef_driver_handle* cluster_dh_out,
                                  unsigned* pd_res_id_out,
                                  unsigned* viset_res_id_out,
                                  char* intf_name_out)
{
  char *req_buf = NULL;
  int req_len;
  char resp_buf[128];
  char intf_name[128];
  int nargs, r0, r1, r2, r3;
  int rc;

  /* Send request */
  req_len = asprintf(&req_buf, "%d %s %d\n", CLUSTERD_ALLOC_CLUSTER_REQ,
                     cluster_name, pd_flags);
  if( req_len < 0 ) {
    LOG(ef_log("%s: ERROR: asprintf() failed: %d", __FUNCTION__, errno));
    return -errno;
  }
  rc = send(sock, req_buf, req_len, MSG_NOSIGNAL);
  free(req_buf);
  if( rc != req_len ) {
    LOG(ef_log("%s: ERROR: send() failed: %d", __FUNCTION__, errno));
    return -errno;
  }

  /* Read reply */
  rc = clusterd_recv(sock, resp_buf, sizeof(resp_buf), cluster_dh_out);
  if( rc < 0 ) {
    LOG(ef_log("%s: ERROR: clusterd_recv() failed: %d", __FUNCTION__, rc));
    return rc;
  }

  nargs = sscanf(resp_buf, "%d %d %d %d %s", &r0, &r1, &r2, &r3, intf_name);
  if( nargs == 5 ) {
    if( r0 == CLUSTERD_ALLOC_CLUSTER_RESP ) {
      if( r1 == CLUSTERD_ERR_SUCCESS ) {
        *pd_res_id_out = r2;
        *viset_res_id_out = r3;
        strncpy(intf_name_out, intf_name, IF_NAMESIZE);
        intf_name_out[IF_NAMESIZE] = '\0';
        return 0;
      }
      else if( r1 == CLUSTERD_ERR_FAIL ) {
        LOG(ef_log("%s: ERROR: daemon returned error %d", __FUNCTION__, r2));
        return -r2;
      }
    }
  }
  LOG(ef_log("%s: ERROR: Unexpected reponse from daemon.  Wanted 5, got %d",
             __FUNCTION__, nargs));
  return -EIO;
}


int ef_pd_alloc_by_name(ef_pd* pd, ef_driver_handle pd_dh,
                        const char* cluster_or_intf_name,
                        enum ef_pd_flags flags)
{
  int rc, sock, ifindex;
  ef_driver_handle cluster_dh;
  unsigned pd_id = 0, viset_id = 0; /* Initialise to shutup the compiler */
  const char* cluster_name = cluster_or_intf_name;
  const char* s;
  char* end;

  if( (s = getenv("EF_VI_PD_FLAGS")) != NULL ) {
    if( strstr(s, "vf") != NULL )
      flags |= EF_PD_VF;
    if( strstr(s, "phys") != NULL )
      flags |= EF_PD_PHYS_MODE;
  }

  if( flags & EF_PD_VF )
    flags |= EF_PD_PHYS_MODE;

  pd->pd_intf_name = malloc(IF_NAMESIZE);
  if( pd->pd_intf_name == NULL ) {
    LOGVV(ef_log("%s: malloc failed", __FUNCTION__));
    return -ENOMEM;
  }

  /* Cluster name has format [idx@]name.  The idx gives the index of the
   * channel within the cluster.  If not given, then any channel will do.
   */
  pd->pd_cluster_viset_index = -1;
  errno = 0;
  int idx = strtol(cluster_name, &end, 10);
  if( errno == 0 && end != cluster_name && *end == '@' ) {
    pd->pd_cluster_viset_index = idx;
    cluster_name = end + 1;
  }

  if( (rc = clusterd_connect(&sock)) < 0 ) {
    LOGV(ef_log("%s: solar_clusterd not present.  Trying ef_pd_alloc()",
                __FUNCTION__));
    goto alloc_locally;
  }

  if( (rc = clusterd_check_version(sock, CLUSTERD_PROTOCOL_VERSION)) < 0 ) {
    LOG(ef_log("%s: ERROR: clusterd_check_version() failed: %d",
               __FUNCTION__, rc));
    close(sock);
    return rc;
  }

  if( (rc = clusterd_alloc_cluster(sock, cluster_name, flags,
                                   &cluster_dh, &pd_id, &viset_id,
                                   pd->pd_intf_name)) < 0 ) {
    close(sock);
    if( rc == -ENOENT ) {
      LOGV(ef_log("%s: cluster '%s' does not exist.  Trying ef_pd_alloc()",
                  __FUNCTION__, cluster_name));
      goto alloc_locally;
    }
    free(pd->pd_intf_name);
    LOG(ef_log("%s: ERROR: clusterd_alloc_cluster() failed: %d", __FUNCTION__,
               rc));
    return rc;
  }

  pd->pd_cluster_name = strdup(cluster_name);
  pd->pd_cluster_sock = sock;
  pd->pd_cluster_dh = cluster_dh;
  pd->pd_resource_id = pd_id;
  pd->pd_cluster_viset_resource_id = viset_id;
  pd->pd_flags = flags;
  return 0;

 alloc_locally:
  if( pd->pd_intf_name )
    free(pd->pd_intf_name);
  ifindex = if_nametoindex(cluster_or_intf_name);
  if( ifindex == 0 )
    return -errno;
  return ef_pd_alloc(pd, pd_dh, ifindex, flags);
}


int ef_pd_cluster_free(ef_pd* pd, ef_driver_handle pd_dh)
{
  free(pd->pd_cluster_name);
  close(pd->pd_cluster_sock);
  close(pd->pd_cluster_dh);
  EF_VI_DEBUG(memset(pd, 0, sizeof(*pd)));
  return 0;
}

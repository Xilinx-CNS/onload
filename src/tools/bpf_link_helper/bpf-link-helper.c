/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2022 Xilinx, Inc. */

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef __NR_bpf
# if defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# else
#  error __NR_bpf not defined. The arch is unsupported.
# endif
#endif

static inline int
sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
  return syscall(__NR_bpf, cmd, attr, size);
}

static int
netlink_recv(int sock, __u32 nl_pid, int seq)
{
  bool multipart = true;
  struct nlmsgerr *err;
  struct nlmsghdr *nh;
  char buf[4096];
  int len;

  while( multipart ) {
    multipart = false;
    len = recv(sock, buf, sizeof(buf), 0);
    if( len < 0 )
      return -1;
    else if( len == 0 )
      break;

    for( nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len) ) {
      if (nh->nlmsg_pid != nl_pid)
        return -1;
      if (nh->nlmsg_seq != seq)
        return -1;
      if (nh->nlmsg_flags & NLM_F_MULTI)
        multipart = true;
      switch (nh->nlmsg_type) {
        case NLMSG_ERROR:
          err = (struct nlmsgerr *)NLMSG_DATA(nh);
          if( !err->error )
            continue;
          fprintf(stderr, "%s(): netlink returned error\n", __func__);
          return -1;
        case NLMSG_DONE:
          return 0;
        default:
          break;
      }
    }
  }

  return 0;
}

static int
netlink_open(__u32 *nl_pid)
{
  struct sockaddr_nl sa;
  socklen_t addrlen;
  int sock;

  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;

  sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if( sock < 0 )
    return -1;

  if( bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0 )
    goto cleanup;

  addrlen = sizeof(sa);
  if( getsockname(sock, (struct sockaddr *)&sa, &addrlen) < 0 )
    goto cleanup;

  if( addrlen != sizeof(sa) )
    goto cleanup;

  *nl_pid = sa.nl_pid;
  return sock;

cleanup:
  close(sock);
  return -1;
}

static int
xdp_link_netlink(int prog_fd, int ifindex)
{
  int sock, seq = 0, ret = 0;
  struct nlattr *nla, *nla_xdp;
  struct {
    struct nlmsghdr  nh;
    struct ifinfomsg ifinfo;
    char             attrbuf[64];
  } req;
  __u32 nl_pid;
  __u32 flags;

  sock = netlink_open(&nl_pid);
  if( sock < 0 )
    return sock;

  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.nh.nlmsg_type = RTM_SETLINK;
  req.nh.nlmsg_pid = 0;
  req.nh.nlmsg_seq = ++seq;
  req.ifinfo.ifi_family = AF_UNSPEC;
  req.ifinfo.ifi_index = ifindex;

  /* started nested attribute for XDP */
  nla = (struct nlattr *)(((char *)&req) + NLMSG_ALIGN(req.nh.nlmsg_len));
  nla->nla_type = NLA_F_NESTED | IFLA_XDP;
  nla->nla_len = NLA_HDRLEN;

  /* add XDP fd */
  nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
  nla_xdp->nla_type = IFLA_XDP_FD;
  nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
  memcpy((char *)nla_xdp + NLA_HDRLEN, &prog_fd, sizeof(prog_fd));
  nla->nla_len += nla_xdp->nla_len;

  flags = XDP_FLAGS_SKB_MODE;
  nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
  nla_xdp->nla_type = IFLA_XDP_FLAGS;
  nla_xdp->nla_len = NLA_HDRLEN + sizeof(flags);
  memcpy((char *)nla_xdp + NLA_HDRLEN, &flags, sizeof(flags));
  nla->nla_len += nla_xdp->nla_len;

  req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

  if( send(sock, &req, req.nh.nlmsg_len, 0) < 0 ) {
    ret = -1;
    goto cleanup;
  }

  ret = netlink_recv(sock, nl_pid, seq);

cleanup:
  close(sock);
  return ret;
}

static int
__bpf_prog_get_next_id(__u32 start_id, __u32 *next_id)
{
  union bpf_attr attr;
  int err;

  memset(&attr, 0, sizeof(attr));
  attr.start_id = start_id;

  err = sys_bpf(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
  if( !err )
    *next_id = attr.next_id;

  return err;
}

static int
__bpf_prog_get_fd_by_id(__u32 id)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.prog_id = id;

  return sys_bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
}

static int
__bpf_obj_get_info_by_fd(int bpf_fd, void *info, size_t info_len)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.info.bpf_fd = bpf_fd;
  attr.info.info_len = (__u32)info_len;
  attr.info.info = (__u64)info;

  return sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

int main(int argc, char *argv[])
{
  __u32 id = 0;
  char *ifname;
  unsigned int ifindex;
  char *prog_name;
  struct stat stat;

  /* Redirect output to kernel buffer */
  if( fstat(STDOUT_FILENO, &stat) != 0 ) {
    int fd = open("/dev/kmsg", O_WRONLY);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
  }

  if( argc != 3 && argc != 2 ) {
    fprintf(stderr, "Usage: %s ifname [prog_name]\n", argv[0]);
    return -1;
  }

  ifname = argv[1];
  prog_name = argc == 3 ? argv[2] : NULL;

  ifindex = if_nametoindex(ifname);

  if( prog_name == NULL ) {
    int rc;

    printf("Unlinking from %s\n", ifname);
    rc = xdp_link_netlink(-1, ifindex);
    if( rc != 0 )
      fprintf(stderr, "Failed to unlink\n");
    return rc;
  }

  while( true ) {
    int fd;
    struct bpf_prog_info info = {};
    int err = __bpf_prog_get_next_id(id, &id);

    if (err) {
      if (errno == ENOENT) {
        break;
      }
      fprintf(stderr, "can't get next program: %s%s\n", strerror(errno),
              errno == EINVAL ? " -- kernel too old?" : "");
      return -1;
    }

    fd = __bpf_prog_get_fd_by_id(id);
    if (fd < 0) {
      if (errno == ENOENT)
        continue;
      fprintf(stderr, "can't get prog by id (%u): %s\n",
              id, strerror(errno));
      return -1;
    }

    err = __bpf_obj_get_info_by_fd(fd, &info, sizeof(info));
    if (err) {
      fprintf(stderr, "can't get prog info: %s\n", strerror(errno));
      return -1;
    }

    if( strcmp(info.name, prog_name) == 0 ) {
      printf("Found bpf program \"%s\" fd=%d id=%d ifindex=%u\n",
             info.name, fd, info.id, info.ifindex);
      printf("Linking to %s\n", ifname);
      err = xdp_link_netlink(fd, ifindex);
      if( err )
        fprintf(stderr, "Failed to link\n");
      return err;
    }

    close(fd);
  }

  fprintf(stdout, "No onload BPF programs were found\n");
  return 0;
}

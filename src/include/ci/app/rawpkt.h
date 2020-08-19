/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  djr
**  \brief  An interface for sending/receive raw packets.
**   \date  2003/06/04
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */

#ifndef __CI_APP_RAWPKT_H__
#define __CI_APP_RAWPKT_H__


typedef struct ci_rawpkt_s ci_rawpkt_t;

/*! Comment? */
struct ci_rawpkt_s {
  int		rd;
  int		wr;
  ssize_t	(*read)(ci_rawpkt_t*, void* buf, size_t count);
  ssize_t	(*write)(ci_rawpkt_t*, const void* buf, size_t count);
  ssize_t       (*sendfile)(ci_rawpkt_t*, int fd_in, off_t *offset, size_t count);
  int		padding;
  unsigned char	mac[6];
};


/*! Comment? */
extern int  ci_rawpkt_ctor(ci_rawpkt_t*, char *spec);
/*! Comment? */
extern void ci_rawpkt_dtor(ci_rawpkt_t*);

/*! Comment? */
extern int  ci_rawpkt_set_block_mode(ci_rawpkt_t*, int blocking);

/*! Comment? */
extern int ci_rawpkt_clrbuff(ci_rawpkt_t* rp);

/*! Comment? */
extern int  ci_rawpkt_send(ci_rawpkt_t*, const volatile void*, int len);
/*! Comment? */
extern int  ci_rawpkt_recv(ci_rawpkt_t*, volatile void*, int len);
/*! Comment? */
extern int  ci_rawpkt_sendfile(ci_rawpkt_t* rp, int fd_in, off_t *offset, int len);

#define CI_RAWPKT_WAIT_RECV   0x1
#define CI_RAWPKT_WAIT_SEND   0x2

/*! Comment? */
extern int ci_rawpkt_wait(ci_rawpkt_t*, int what_in, int* what_out,
			  const struct timeval*);

  /*! This function allows you to override the routines to read/write the
  ** interface.  This is a bit of a hack to cope with unix preload-induced
  ** deadlock.
  */
extern void ci_rawpkt_override_io(
	  ssize_t (*read)(int fd, void* buf, size_t count),
	  ssize_t (*write)(int fd, const void* buf, size_t count));


#endif  /* __CI_APP_RAWPKT_H__ */

/*! \cidoxg_end */

/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc. */
/****************************************************************************
 * Copyright (c) 2013, Solarflare Communications Inc,
 *
 * Maintained by Solarflare Communications
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include <Python.h>
#include <sys/types.h>
#include <net/if.h>
#include <onload/version.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>
#include <etherfabric/internal/cluster_protocol.h>
#include "internal.h"


#define MODULE_INT_CONST(module, name)          \
  PyModule_AddIntConstant(module, #name, name);
#define MODULE_STR_CONST(module, name)                  \
  PyModule_AddStringConstant(module, #name, name)


struct cp_vi {
  ef_driver_handle   dh;
  enum ef_pd_flags   pd_flags;
  ef_pd              pd;
  ef_vi_set          viset;
  int                n_vis;
  char*              interface;
};


static struct cp_vi** cp_vis;
static int n_cp_vis;


static int do_send(int sock, int fd, char* msg, int msglen)
{
  struct msghdr hdr;
  struct cmsghdr* chdr;
  struct iovec data;
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  int rc;

  data.iov_base = msg;
  data.iov_len = msglen;

  memset(&hdr, 0, sizeof(hdr));
  hdr.msg_iov = &data;
  hdr.msg_iovlen = 1;
  hdr.msg_control = cmsgbuf;
  hdr.msg_controllen = CMSG_LEN(sizeof(int));

  chdr = CMSG_FIRSTHDR(&hdr);
  chdr->cmsg_len = CMSG_LEN(sizeof(int));
  chdr->cmsg_level = SOL_SOCKET;
  chdr->cmsg_type = SCM_RIGHTS;
  memmove(CMSG_DATA(chdr), &fd, sizeof(int));

  if( (rc = sendmsg(sock, &hdr, 0)) != msglen ) {
    if( rc == -1 ) {
      fprintf(stderr, "%s: ERROR: sendmsg() failed: %d\n", __FUNCTION__, errno);
      return -errno;
    }
    fprintf(stderr, "%s: ERROR: sendmsg() sent %d, wanted %d\n", __FUNCTION__,
            rc, msglen);
    return -EIO;
  }
  return 0;
}


static PyObject* sendfd(PyObject *self, PyObject *args)
{
  char* msg;
  int rc, sock, fd, msglen;

  if( ! PyArg_ParseTuple(args, "iis#", &sock, &fd, &msg, &msglen) )
    return NULL;

  if( (rc = do_send(sock, fd, msg, msglen)) < 0 ) {
    errno = -rc;
    return PyErr_SetFromErrno(PyExc_IOError);
  }
  return Py_BuildValue("i", rc);
}


static PyObject* open_driver(PyObject *self, PyObject *args)
{
  int rc;
  ef_driver_handle dh;

  if( (rc = ef_driver_open(&dh)) < 0 ) {
    errno = -rc;
    return PyErr_SetFromErrno(PyExc_OSError);
  }

  return Py_BuildValue("i", dh);
}


static PyObject* vi_set_alloc(PyObject *self, PyObject *args)
{
  int rc, ifindex, cp_vi_index;
  struct cp_vi* cp_vi = calloc(1, sizeof(struct cp_vi));
  cp_vis = realloc(cp_vis, (n_cp_vis + 1) * sizeof(*cp_vis));
  cp_vis[n_cp_vis] = cp_vi;
  cp_vi_index = n_cp_vis++;

  if( ! PyArg_ParseTuple(args, "isii", &cp_vi->dh, &cp_vi->interface,
                         &cp_vi->n_vis, &cp_vi->pd_flags) )
    return NULL;

  if( (ifindex = if_nametoindex(cp_vi->interface)) == 0 ) {
    PyErr_Format(PyExc_ValueError, "No such interface '%s'", cp_vi->interface);
    return NULL;
  }

  rc = ef_pd_alloc(&cp_vi->pd, cp_vi->dh, ifindex, cp_vi->pd_flags);
  if( rc < 0 ) {
    errno = -rc;
    return PyErr_SetFromErrno(PyExc_OSError);
  }

  rc = ef_vi_set_alloc_from_pd(&cp_vi->viset, cp_vi->dh, &cp_vi->pd, cp_vi->dh,
                               cp_vi->n_vis);
  if( rc < 0 ) {
    errno = -rc;
    return PyErr_SetFromErrno(PyExc_OSError);
  }

  return Py_BuildValue("iii", cp_vi_index, cp_vi->pd.pd_resource_id,
                       cp_vi->viset.vis_res_id);
}


static PyObject* vi_set_add_stream(PyObject* self, PyObject* args)
{
  struct cp_vi* cp_vi;
  int rc, cp_vi_index;
  char* stream;

  if( ! PyArg_ParseTuple(args, "is", &cp_vi_index, &stream) )
    return NULL;

  cp_vi = cp_vis[cp_vi_index];
  rc = ef_vi_set_filter_string_add(&cp_vi->viset, cp_vi->dh, stream);
  if( rc < 0 ) {
    errno = -rc;
    return PyErr_SetFromErrno(PyExc_OSError);
  }

  Py_RETURN_NONE;
}


static PyMethodDef cluster_protocol_methods[] = {
  {"sendfd",       sendfd,       METH_VARARGS, "sendfd(sock, fd, msg)"},
  {"open_driver",  open_driver,  METH_VARARGS, "open_driver() -> handle"},
  {"vi_set_alloc", vi_set_alloc, METH_VARARGS, "vi_set_alloc()"},
  {"vi_set_add_stream", vi_set_add_stream, METH_VARARGS, "vi_set_add_stream()"},
  {NULL,           NULL,         0,             NULL}
};


static struct PyModuleDef cluster_module = {
  PyModuleDef_HEAD_INIT,
  "cluster_protocol",
  "",
  -1,
  cluster_protocol_methods
};


PyMODINIT_FUNC PyInit_cluster_protocol(void)
{
  PyObject *module = PyModule_Create(&cluster_module);

  MODULE_STR_CONST(module, onload_version);

  MODULE_STR_CONST(module, DEFAULT_CLUSTERD_DIR);
  MODULE_STR_CONST(module, DEFAULT_CLUSTERD_SOCK_NAME);

  MODULE_INT_CONST(module, CLUSTERD_PROTOCOL_VERSION);

  MODULE_INT_CONST(module, CLUSTERD_VERSION_REQ);
  MODULE_INT_CONST(module, CLUSTERD_VERSION_RESP);
  MODULE_INT_CONST(module, CLUSTERD_ALLOC_CLUSTER_REQ);
  MODULE_INT_CONST(module, CLUSTERD_ALLOC_CLUSTER_RESP);

  MODULE_INT_CONST(module, CLUSTERD_ERR_SUCCESS);
  MODULE_INT_CONST(module, CLUSTERD_ERR_FAIL);
  MODULE_INT_CONST(module, CLUSTERD_ERR_BAD_REQUEST);

  MODULE_INT_CONST(module, EF_PD_DEFAULT);
  MODULE_INT_CONST(module, EF_PD_VF);
  MODULE_INT_CONST(module, EF_PD_PHYS_MODE);
  MODULE_INT_CONST(module, EF_PD_RX_PACKED_STREAM);
  MODULE_INT_CONST(module, EF_PD_VPORT);

  return module;
}

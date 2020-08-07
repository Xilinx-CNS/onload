# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc.

import os, sys, pwd, grp, errno
import fcntl
import resource
import signal
import atexit
import logging
from logging import handlers

def daemonize(directory, user=None, group=None, verbose=False):
    pid = os.fork()
    if pid < 0:
        sys.stderr.write("Fork failed")
        sys.exit(1)
    if pid != 0:
        sys.exit(0)

    pid = os.setsid()
    if pid == -1:
        sys.stderr.write("setsid failed")
        sys.exit(1)

    syslog = handlers.SysLogHandler('/dev/log')
    if verbose:
        syslog.setLevel(logging.DEBUG)
    else:
        syslog.setLevel(logging.INFO)
    # Try to mimic to normal syslog messages.
    formatter = logging.Formatter("%(asctime)s %(name)s: %(message)s",
                                  "%b %e %H:%M:%S")
    syslog.setFormatter(formatter)
    logger = logging.getLogger('solar_clusterd')
    logger.addHandler(syslog)

    # This is the same as 027.  There is no compatible way to specify
    # octals between 2.4, 2.6, 3.x so specifying in decimal.
    os.umask(23)
    os.chdir("/")

    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            sys.stderr.write("Group {0} not found".format(group))
            sys.exit(1)
        try:
            os.setgid(gid)
        except OSError:
            sys.stderr.write("Unable to change gid.")
            sys.exit(1)
    if user:
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            sys.stderr.write("User {0} not found.".format(user))
            sys.exit(1)
        try:
            os.setuid(uid)
        except OSError:
            sys.stderr.write("Unable to change uid.")
            sys.exit(1)

    if os.path.exists(directory):
        sys.stderr.write('ERROR: directory %s already exists.  Either '
                         'another instance running or previous instance '
                         'did not clean up properly.  If no other '
                         'instance is running, please manually remove the '
                         'directory\n' % directory)
        sys.exit(1)
    os.makedirs(directory)

    os.close(0)
    os.close(1)
    os.close(2)
    os.open('/dev/null', os.O_RDWR)
    os.dup(0)
    os.dup(0)

    logger.warn("Starting daemon.")
    return logger

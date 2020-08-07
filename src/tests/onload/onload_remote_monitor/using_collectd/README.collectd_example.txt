.. SPDX-License-Identifier: BSD-2-Clause
.. X-SPDX-Copyright-Text: (c) Copyright 2016-2019 Xilinx, Inc.
This is an example of how to gather Onload stack statistics using collectd.
Other configurations of Onload Remote Monitor with/without collectd are
possible.

1. Install collectd (https://collectd.org) ensuring the curl_json plugin is
   enabled.
2. Add config to your collectd.conf to request stats from Onload.  An example
   is provided in
   src/tests/onload/onload_remote_monitor/using_collectd/collectd_example.conf
3. Run the Onload Remote Monitor web server on the server you wish to monitor:
   orm_webserver 9000 # this runs on port 9000
4. Check web service is running by pointing a browser to
   http://<server-ip>:9000/onload/lots/
5. Start (or restart) collectd to begin collecting Onload stack statistics.
6. With the example configuration, collectd will automatically pick up
   additional Onload stacks as they are created.
7. If using the suggested csv configuration, the stats will be saved to
   /opt/collectd/var/lib/collectd/csv/<host>/curl_json-onload_stack_stats/

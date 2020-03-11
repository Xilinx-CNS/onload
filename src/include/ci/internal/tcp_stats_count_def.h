/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

OO_STAT("Number of times TCP connections have made a direct "
        "transition to the SYN-SENT state from the CLOSED state.",
        CI_IP_STATS_TYPE, tcp_active_opens, count)
OO_STAT("Number of times TCP connections have made a direct "
        "transition to the SYN-RCVD state from the LISTEN state.",
        CI_IP_STATS_TYPE, tcp_passive_opens, count)
OO_STAT("Number of times TCP connections have made a direct transition to "
        "the CLOSED state from either the ESTABLISHED state or the CLOSE-WAIT "
        "state.",
        CI_IP_STATS_TYPE, tcp_estab_resets, count)
OO_STAT("Number of TCP connections for which the current state is either "
        "ESTABLISHED or CLOSE-WAIT.",
        CI_IP_STATS_TYPE, tcp_curr_estab, count)
OO_STAT("Total number of segments received, including those "
        "received in error.",
        CI_IP_STATS_TYPE, tcp_in_segs, count)
OO_STAT("Total number of segments sent, including those on current "
        "connections but excluding those containing only retransmitted octets .",
        CI_IP_STATS_TYPE, tcp_out_segs, count)
OO_STAT("Total number of segments retransmitted.",
        CI_IP_STATS_TYPE, tcp_retran_segs, count)
OO_STAT("Number of RST segments sent.",
        CI_IP_STATS_TYPE, tcp_out_rsts, count)

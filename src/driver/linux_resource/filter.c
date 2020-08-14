/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains /proc/driver/sfc_resource/ implementation.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
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
#include <linux/device.h>
#include <linux/ctype.h>
#include <linux/ethtool.h>

#include "linux_resource_internal.h"
#include <ci/driver/driverlink_api.h>
#include "kernel_compat.h"
#include <ci/driver/internal.h>
#include <ci/tools/byteorder.h>
#include <ci/net/ipv4.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efrm/kernel_proc.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/mc_driver_pcol.h>
#include <ci/efhw/af_xdp.h>
#include <ci/tools/bitfield.h>


/* ************************************* */
/* Types, not needed outside this module */
/* ************************************* */

struct efrm_filter_rule_s;
struct efrm_filter_table_s;
struct efrm_interface_name_s;

typedef enum efrm_protocol_e {
	ep_tcp        = 0,
	ep_udp        = 1,
	ep_ip         = 2,
	ep_eth        = 3
} efrm_protocol_t;

typedef struct efrm_filter_table_s
{
	struct efrm_filter_rule_s*    efrm_ft_first_rule;
	struct efrm_filter_rule_s*    efrm_ft_last_rule;
	struct efrm_filter_table_s*   efrm_ft_prev;
	struct efrm_filter_table_s*   efrm_ft_next;
        struct net*                   efrm_ft_netns;
        struct efrm_interface_name_s* efrm_ft_interface_name;
	char*                         efrm_ft_pcidev_name;
} efrm_filter_table_t;

typedef enum efrm_filter_ruletype_e
{
	EFRM_FR_PORTRANGE,
	EFRM_FR_MACADDRESS
} efrm_filter_ruletype_t;

typedef enum efrm_filter_action_e {
	EFRM_FR_ACTION_UNSUPPORTED  = 0,
	EFRM_FR_ACTION_ACCEPT,
	EFRM_FR_ACTION_DROP
} efrm_filter_action_t;

typedef struct efrm_filter_rule_portrange_s {
	unsigned short        efrp_lcl_min;
	unsigned short        efrp_lcl_max;
	unsigned short        efrp_rmt_min;
	unsigned short        efrp_rmt_max;
	__be32                efrp_lcl_ip;
	__be32                efrp_rmt_ip;
	__be32                efrp_lcl_mask;
	__be32                efrp_rmt_mask;
} efrm_filter_rule_portrange_t;

typedef struct efrm_filter_rule_macaddress_s {
	char                  efrm_lcl_mac     [6];
	char                  efrm_lcl_mask    [6];
} efrm_filter_rule_macaddress_t;

typedef struct efrm_filter_rule_s
{
	efrm_filter_ruletype_t                eit_ruletype;
	struct efr_rules {
		/* Conceptually a union; but the starting values don't match */
		efrm_filter_rule_portrange_t  efr_range;
		efrm_filter_rule_macaddress_t efr_macaddess;
	}                                     efrm_rule;
	unsigned short                        efrm_vlan_id;
	unsigned char                         efr_protocol;
	efrm_filter_action_t                  efr_action;

	struct efrm_filter_rule_s*            efrm_fr_next;
}  efrm_filter_rule_t;

typedef struct efrm_interface_name_s
{
        struct efrm_interface_name_s* efrm_in_next;
        struct efrm_interface_name_s* efrm_in_prev;
	char                          efrm_in_interface_name[IFNAMSIZ];
	efrm_pd_handle                efrm_in_directory;
	efrm_pd_handle                efrm_in_rules_file;
        int                           efrm_in_n_tables;
        efrm_filter_table_t*          efrm_in_root_table;
} efrm_interface_name_t;

/* ******* */
/* Globals */
/* ******* */

static DEFINE_SPINLOCK(efrm_ft_lock);
static DEFINE_MUTEX(efrm_ft_mutex);
static efrm_interface_name_t* efrm_in_first_interface = NULL;
static char const* efrm_protocol_names[5] = {
	"tcp",
	"udp",
	"ip",
	"eth",
	"???"
};
static char const* efrm_action_names[3] = { "???" , "ACCEPT", "DECELERATE" };
static efrm_pd_handle efrm_pd_add_rule = NULL;
static efrm_pd_handle efrm_pd_del_rule = NULL;

/* ************************************************************ */
/* String parsing code.  sscanf() isn't available in the kernel */
/* ************************************************************ */


static int efrm_is_mac_spec( struct efx_filter_spec const* spec )
{
	return spec->match_flags &
	       (EFX_FILTER_MATCH_LOC_MAC | EFX_FILTER_MATCH_LOC_MAC_IG);
}

static int efrm_atoi( const char** src, size_t* length )
{
	/* This function works much like atoi, but modifies its inputs to make
	   progress through the data stream. */
	int rval = 0;
	int multiplier = 1;
	if ( !*length ) return -1;

	if ( **src == '-' ) {
		*src = *src + 1;
		*length = *length - 1;
		multiplier = -1;
	}

	while ( *length ) {
		char c = **src;
		if ( c >= '0' && c <= '9' ) {
			rval *= 10;
			rval += ( c - '0' );
		}
		else {
			break;
		}
		*src = *src + 1;
		*length = *length - 1;
	}
	return rval * multiplier;
}

static int efrm_hextoi( const char** src, size_t* length )
{
	/* This function works much like atoi, but modifies its inputs to make
	   progress through the data stream. */
	int rval = 0;
	while ( *length ) {
		char c = **src;
		if ( c >= '0' && c <= '9' ) {
			rval *= 16;
			rval += ( c - '0' );
		}
		else if ( c >= 'a' && c <= 'f' ) {
			rval *= 16;
			rval += 10 + ( c - 'a' );
		}
		else if ( c >= 'A' && c <= 'F' ) {
			rval *= 16;
			rval += 10 + ( c - 'A' );
		}
		else {
			break;
		}
		*src = *src + 1;
		*length = *length - 1;
	}
	return rval;
}


static void efrm_skip_num( const char** src, size_t* length, int num )
{
	/* Skip forward num characetrs */
	if ( *length < num )
		num = *length;
	*length = *length - num;
	*src = *src + num;
}

static void efrm_skip_whitespace( const char** src, size_t* length )
{
	/* Skip past arbitary whitespace but not '\n' which terminates rules */
	while ( *length && **src != '\n' && isspace(**src) ) {
		*src = *src + 1;
		*length = *length - 1;
	}
}

static int efrm_consume_next_word( const char** src, size_t* length,
                                   char* dest, size_t destlen )
{
	/* Read non-whitespace until you run out of buffer, or reach
	   whitespace.*/
	int rval = 0;

	if ( !src || !*src || !length || !*length || !dest )
		return -EINVAL;

  /* Iterate over src buffer copying to dest buffer.  Terminate if
   *  - there is no more data to copy
   *  - we are in last entry of dest buffer so it can be '\0' terminated
   *  - we reach a word separator (space or end of string)
   */
	while ( *length && destlen > 1 && !isspace(**src) && **src != '\0' ) {
		*dest++ = **src;
		*src = *src + 1;
		*length = *length - 1;
		destlen--;
		rval++;
	}
	*dest = '\0';
	return rval;
}

static int efrm_compare_and_skip( const char** src, size_t* length,
                                  char const* compare )
{
	/* Returns strncmp() and moves on if it matches. */
	size_t compare_length;
	int mismatch;

	compare_length = strlen(compare);
	if ( compare_length > *length ) {
		return -1;
	}
	mismatch = strncmp( *src, compare, compare_length );
	if ( !mismatch ) {
		efrm_skip_num( src, length, compare_length );
	}
	return mismatch;
}

static int efrm_consume_portrange( const char** src, size_t* length,
                                   unsigned short* low, unsigned short* high )
{
	/* Matches (\d+)[:(\d+)] outputting the matches.  Returns 0 if ok. */
	*low = efrm_atoi( src, length );
	*high = *low;
	if ( efrm_compare_and_skip( src, length, ":" ) == 0
			 || efrm_compare_and_skip( src, length, "-" ) == 0 ) {
		*high = efrm_atoi( src, length );
	}
	if ( *low > *high ) return -EINVAL;
	return 0;
}

static int efrm_fill_top_bits( int n, unsigned char* out, int length )
{
	/* Used for making masks, sets the top n bits of a buffer.
	   Does not cleasr the other bits. */
	int w;
	if ( n < 0 || (n > length * 8) )
		return 0;

	w = 0;
	while ( n > 0 ) {
		unsigned char c = 0;
		if ( n >= 8 ) {
			c = 0xff;
			n -= 8;
		}
		else {
			for ( ; n>0; --n )
			{
				c >>= 1;
				c |= 0x80;
			}
		}
		out[w++] = c;
	}
	return 1;
}

static int efrm_get_ip_trit( const char** src, size_t* length, ci_uint8* ip )
{
	/* Reads "0" to "255" and returns 0 if the value was in range. */
	int v = efrm_atoi( src, length );
	if ( v < 0 || v > 255 ) return -EINVAL;
	*ip = (ci_uint8) ( v&255 );
	return 0;
}

static int
efrm_consume_ip( const char** src, size_t* length, ci_uint8* trits )
{
	if ( ( efrm_get_ip_trit( src, length, trits + 0 ) < 0 ) ||
	     ( efrm_compare_and_skip( src, length, "." ) ) ||
	     ( efrm_get_ip_trit( src, length, trits + 1 ) < 0 ) ||
	     ( efrm_compare_and_skip( src, length, "." ) ) ||
	     ( efrm_get_ip_trit( src, length, trits + 2 ) < 0 ) ||
	     ( efrm_compare_and_skip( src, length, "." ) ) ||
	     ( efrm_get_ip_trit( src, length, trits + 3 ) < 0 ) )
	{
		return 0;
	}
	return 1;
}

static int efrm_consume_ip_mask( const char** src, size_t* length,
                                 __be32* ip, __be32* mask )
{
	/* Reads a standard IPv4 address and mask, in either form.
	   Expect to consume a.b.c.d, possibly with suffix of /e.f.g.h or /n */
	ci_uint8* ip_ptr = (ci_uint8*) ip;
	ci_uint8* mask_ptr = (ci_uint8*) mask;

	if ( !efrm_consume_ip( src, length, ip_ptr ) )
		return 0;

	if ( efrm_compare_and_skip( src, length, "/" ) ) {
		/* IP without mask, default to /32. */
		*mask = 0xffffffff;
	}
	else if ( !efrm_consume_ip( src, length, mask_ptr ) )
	{
		return efrm_fill_top_bits( mask_ptr[0], mask_ptr, 4 );
	}
	return 1;
}

static int efrm_consume_mac_seperator( const char** src, size_t* length )
{
	if ( efrm_compare_and_skip( src, length, ":" ) &&
	     efrm_compare_and_skip( src, length, "-" ) )
		return 1;
	return 0;
}

static int efrm_consume_hex( const char** src, size_t* length,
                             unsigned char* out )
{
	out[0] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[1] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[2] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[3] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[4] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[5] = efrm_hextoi( src, length );

	return 1;
}

static int efrm_consume_mac( const char** src, size_t* length,
                             unsigned char* mac, unsigned char* mask )
{
	/* Consumes a mac address, with mask. */
	memset( mac, 0, 6 );
		memset( mask, 0xff, 6 );

	if ( !efrm_consume_hex( src, length, mac ) )
		return 0;

	if ( !efrm_compare_and_skip( src, length, "/" ) ) {
		if ( !efrm_consume_hex( src, length, mask ) )
		{
			return efrm_fill_top_bits( mask[0], mask, 6 );
		}
	}
	return 1;
}

static char const* efrm_get_protocol_name( efrm_protocol_t proto )
{
	/* Turns a protocol into a printable name */
	if ( proto < 0 || proto > 3 )
		return efrm_protocol_names[4];

	return efrm_protocol_names[proto];
}

static int
efrm_protocol_matches( struct efx_filter_spec *spec, efrm_protocol_t proto )
{
	/* Returns a truth value - does the spec match the protocol? */

	if ( (spec->match_flags & EFX_FILTER_MATCH_ETHER_TYPE) &&
	     (spec->ether_type == htons(ETH_P_IP)) ) {
		if( proto == ep_ip )
			return 1;

		if( spec->match_flags & EFX_FILTER_MATCH_IP_PROTO ) {
			if( (spec->ip_proto == IPPROTO_TCP) &&
			    (proto == ep_tcp) )
				return 1;
			if( (spec->ip_proto == IPPROTO_UDP) &&
			    (proto == ep_udp) )
				return 1;
		}
	}

	/* TODO support remote MAC address matching */
	if ( efrm_is_mac_spec(spec) && (proto == ep_eth) )
		return 1;

	return 0;
}


static char const* efrm_get_action_name( efrm_filter_action_t action )
{
	/* Turn an action into a printable string. */
	if ( action < 1 || action > 2 )
		return efrm_action_names[0];
	return efrm_action_names[action];
}

static inline char const* efrm_get_pciname_from_device( const struct device* dev )
{
	/* This returns something of the form 0000:13:00.0
	   This matches the PHYSICAL port, but is unique */
	return dev_name(dev);
}

static char const*
efrm_get_interfacename_from_index( int ifindex, struct net_device** ndev )
{
	/* This returns something of the form eth4, but can only be found when
	   driver is initialised.
	   You MUST call dev_put(ndev) when you're done with it. */
	char const* dev_name = NULL;
	*ndev = dev_get_by_index(&init_net, ifindex);
	if (*ndev) {
		dev_name = (*ndev)->name;
	}
	return dev_name;
}

static int
efrm_correct_table_pciname( efrm_filter_table_t* table, char const* pciname )
{
	/* Returns a truth value, is this table for the given port? */
	if ( !table || !pciname || !table->efrm_ft_pcidev_name ) {
		EFRM_ERR("%s: Internal err %p %p", __func__, table, pciname );
		return 0;
	}
	return strcmp( pciname, table->efrm_ft_pcidev_name ) == 0;
}

/* ******************************************************************** */
/* Table/Rule manipulation functions - these spinlock and the only ones */
/* ******************************************************************** */
static void ethrm_link_table( efrm_interface_name_t* name,
                              efrm_filter_table_t* table )
{
	/* Add the table to the root list of tables. */
	spin_lock_bh(&efrm_ft_lock);
	table->efrm_ft_prev = NULL;
	table->efrm_ft_next = name->efrm_in_root_table;
	if ( name->efrm_in_root_table ) {
		name->efrm_in_root_table->efrm_ft_prev = table;
	}
	name->efrm_in_root_table = table;
        table->efrm_ft_interface_name = name;

	spin_unlock_bh(&efrm_ft_lock);
}

static void ethrm_unlink_table( efrm_filter_table_t* table )
{
        efrm_interface_name_t* name;

        /* Remove the table from the list of tables. */
	if ( !table ) return;

        name = table->efrm_ft_interface_name;

        if ( !name ) return;

	spin_lock_bh(&efrm_ft_lock);

	/* Update links to other tables */
	if ( table->efrm_ft_prev )
		table->efrm_ft_prev->efrm_ft_next = table->efrm_ft_next;
	if ( table->efrm_ft_next )
		table->efrm_ft_next->efrm_ft_prev = table->efrm_ft_prev;

	/* Update the root of the table, if needed. */
	if ( name->efrm_in_root_table == table ) {
		name->efrm_in_root_table = table->efrm_ft_next;
	}

	/* Added safety; make sure this table won't be matched in future */
	table->efrm_ft_interface_name = NULL;
        table->efrm_ft_netns = NULL;
	*table->efrm_ft_pcidev_name = '\0';

	spin_unlock_bh(&efrm_ft_lock);
}


static void
ethrm_link_rule( efrm_filter_rule_t* rule, efrm_filter_table_t* table,
                 efrm_filter_rule_t* prev, efrm_filter_rule_t* next )
{
	/* Add the rule into the table, between prev and next. */
	spin_lock_bh(&efrm_ft_lock);

	/* Insert it in place. */
	if ( prev ) {
		rule->efrm_fr_next = next;
		prev->efrm_fr_next = rule;
	}
	else {
		/* Was the previous NULL?  Then we're start of table. */
		rule->efrm_fr_next = table->efrm_ft_first_rule;
		table->efrm_ft_first_rule = rule;
	}

	/* Was the previous the end of the table?  Update that. */
	if ( prev == table->efrm_ft_last_rule ) {
		table->efrm_ft_last_rule = rule;
	}

	spin_unlock_bh(&efrm_ft_lock);
}

static void
ethrm_unlink_rule( efrm_filter_rule_t* rule, efrm_filter_table_t* table,
                   efrm_filter_rule_t* prev )
{
	/* Remove the rule from the table, pulling up prev into its place. */
	spin_lock_bh(&efrm_ft_lock);

	/* Special handling for first rule */
	if ( !prev ) {
		table->efrm_ft_first_rule = rule->efrm_fr_next;
	}
	else {
		prev->efrm_fr_next = rule->efrm_fr_next;
	}

	/* Special handling for last rule */
	if ( rule == table->efrm_ft_last_rule ) {
		table->efrm_ft_last_rule = prev;
	}

	spin_unlock_bh(&efrm_ft_lock);
}


/* ***************************************************************** */
/* Allocation/Removal functions, must be mutexed, but not spinlocked */
/* ***************************************************************** */

static void efrm_remove_files( efrm_filter_table_t* table )
{
        efrm_interface_name_t* name = table->efrm_ft_interface_name;
        efrm_filter_table_t* t;

        /* We must only remove the files from /proc if _all_ tables
         * for this ifname are empty. */
        for( t = name->efrm_in_root_table; t; t = t->efrm_ft_next ) {
                if( t->efrm_ft_first_rule )
                        return;
        }

	/* Remove the /proc/ files associated with this name. */
	if ( name && name->efrm_in_rules_file ) {
		efrm_proc_remove_file( name->efrm_in_rules_file );
		name->efrm_in_rules_file = NULL;
	}
	if ( name && name->efrm_in_directory ) {
		efrm_proc_intf_dir_put(name->efrm_in_directory);
		name->efrm_in_directory = NULL;
	}
}

static const struct proc_ops efrm_fops_rules;

static void efrm_add_files( efrm_filter_table_t* table )
{
        efrm_interface_name_t* name = table->efrm_ft_interface_name;

	/* Create the /proc/ files for this name. */
	if ( !name )
		return;

	if ( !name->efrm_in_directory ) {
		char const* ifname = name->efrm_in_interface_name;
		name->efrm_in_directory = efrm_proc_intf_dir_get(ifname);
	}
	if ( name->efrm_in_directory && !name->efrm_in_rules_file ) {
		name->efrm_in_rules_file = efrm_proc_create_file(
				"firewall_rules", 0444,
				name->efrm_in_directory,
				&efrm_fops_rules, name
				);
	}
}

static int
find_interface_name( char const* ifname,
                     efrm_interface_name_t** devname )
{
	/* Find an interface name record matching this name.
	   Returns a truth value, outputs the name. */
	efrm_interface_name_t* cur_name = efrm_in_first_interface;

	if ( !ifname || !devname ) {
		EFRM_ERR("%s:Internal error %p %p", __func__, ifname, devname );
		return 0;
	}

	while ( cur_name ) {
		if ( !strcmp( ifname, cur_name->efrm_in_interface_name ) ) {
			*devname = cur_name;
			return 1;
		}
		cur_name = cur_name->efrm_in_next;
	}

        cur_name = kmalloc( sizeof(efrm_interface_name_t), GFP_KERNEL );
        if( !cur_name )
                return 0;
        memset( cur_name, 0, sizeof(efrm_interface_name_t) );

        strlcpy( cur_name->efrm_in_interface_name, ifname, IFNAMSIZ );
        cur_name->efrm_in_n_tables = 0;

        spin_lock_bh(&efrm_ft_lock);

        cur_name->efrm_in_prev = NULL;
	cur_name->efrm_in_next = efrm_in_first_interface;
	if ( efrm_in_first_interface ) {
		efrm_in_first_interface->efrm_in_prev = cur_name;
	}
	efrm_in_first_interface = cur_name;

        spin_unlock_bh(&efrm_ft_lock);

        *devname = cur_name;
	return 1;
}

static void
remove_interface_name( efrm_interface_name_t* name )
{
        BUG_ON( name == NULL );
        BUG_ON( name->efrm_in_root_table != NULL );

        spin_lock_bh( &efrm_ft_lock );

        if( name->efrm_in_next )
                name->efrm_in_next->efrm_in_prev = name->efrm_in_prev;

        if( name->efrm_in_prev )
                name->efrm_in_prev->efrm_in_next = name->efrm_in_next;
        else
                efrm_in_first_interface = name->efrm_in_next;

        spin_unlock_bh( &efrm_ft_lock );

        kfree( name );
}

static int
find_table_by_ifname( struct net* netns, char const* ifname,
                      efrm_filter_table_t** table )
{
	/* Find a table matching this interface name in this namespace.
	   Returns a truth value, outputs the table. */
        efrm_interface_name_t *name;
        efrm_filter_table_t* cur_table;

        if( !find_interface_name( ifname, &name ) )
                return 0;

        cur_table = name->efrm_in_root_table;
	while ( cur_table ) {
		if ( netns == cur_table->efrm_ft_netns ) {
			*table = cur_table;
			return 1;
		}
		cur_table = cur_table->efrm_ft_next;
	}
	return 0;
}

static int
find_table_by_pcidevice( char const* pciname, efrm_filter_table_t** table )
{
	/* Find a table matching this pci device name.
	   Returns a truth value, outputs the table. */
        efrm_interface_name_t* cur_name = efrm_in_first_interface;

	if ( !pciname || !table ) {
		EFRM_ERR("%s:Internal error %p %p", __func__, pciname, table );
		return 0;
	}

	while( cur_name ) {
                efrm_filter_table_t* cur_table = cur_name->efrm_in_root_table;
                while ( cur_table ) {
                        if ( efrm_correct_table_pciname( cur_table, pciname ) ) {
                                *table = cur_table;
                                return 1;
                        }
                        cur_table = cur_table->efrm_ft_next;
                }
                cur_name = cur_name->efrm_in_next;
	}
	return 0;
}

static int
interface_has_rules( struct net* netns, char const* ifname )
{
	efrm_filter_table_t* table;
	int got_table = find_table_by_ifname( netns, ifname, &table );
	if ( got_table ) {
		return table->efrm_ft_first_rule != NULL;
	}
	return 0;
}

static efrm_filter_table_t*
efrm_allocate_new_table( char const* pci_name,
                         struct net* netns, char const* if_name )
{
	/* Allocates a new, efrm_filter_table_t structure, fills in the name,
	   and plugs it into the table list.
	   Returns the table, or NULL if kmalloc() fails.
	   MUST NOT BE IN THE SPINLOCK */
	static const size_t size = sizeof(efrm_filter_table_t)
	                           + IFNAMSIZ;
	char* buf = (char*) kmalloc( size, GFP_KERNEL );
	efrm_filter_table_t* table = (efrm_filter_table_t*) buf;
	if ( table ) {
		char* pcidev_name = buf
		                     + sizeof(efrm_filter_table_t);

		pcidev_name[0] = '\0';

                table->efrm_ft_netns = netns;
		table->efrm_ft_first_rule = NULL;
		table->efrm_ft_last_rule = NULL;
		table->efrm_ft_prev = NULL;
		table->efrm_ft_next = NULL;
		table->efrm_ft_pcidev_name = pcidev_name;
		table->efrm_ft_interface_name = NULL;
		if ( pci_name ) {
			strlcpy( pcidev_name, pci_name, IFNAMSIZ );
		}
	}
	return table;
}

static efrm_filter_table_t*
efrm_insert_new_table( char const* pci_name,
                       struct net* netns, char const* if_name )
{
	/* Create and link a table with these names. */
        efrm_interface_name_t* name;
	efrm_filter_table_t* table = efrm_allocate_new_table(pci_name,
                                                             netns,
	                                                     if_name );
	if ( table && find_interface_name( if_name, &name ) ) {
		ethrm_link_table( name, table );
	}
	return table;
}

static int
add_rule_to_table( efrm_filter_table_t* table, efrm_filter_rule_t* rule,
                   int position )
{
	/* Insert the given rule at the assigned position -
	   negative positions mean "At end"
	   Returns 0 (no errors are currently possible). */

	efrm_filter_rule_t* next;
	efrm_filter_rule_t* prev;

	if ( !table || !rule ) {
		return -EINVAL;
	}

	 /* Find the entry previous to this in the table. */
	if ( position < 0 ) {
		prev = table->efrm_ft_last_rule;
		next = NULL;
		position = 0;
	} else {
		prev = NULL;
		next = table->efrm_ft_first_rule;
		while ( position > 0 && next ) {
			prev = next;
			next = next->efrm_fr_next;
			position -= 1;
		}
	}

	if ( position ) {
		EFRM_ERR( "%s: Rule is %d beyond the end, adding instead.",
				__func__, position );
		prev = table->efrm_ft_last_rule;
		next = NULL;
	}
	/* And put the new rule into the table */
	ethrm_link_rule( rule, table, prev, next );
	/* In case this was the first rule, create the access files */
        efrm_add_files( table );

	return 0;
}

static int
remove_rule_from_table( efrm_filter_table_t* table, int position )
{
	/* Remove the nth rule from a table. */

	efrm_filter_rule_t* prev_rule = NULL;
	efrm_filter_rule_t* rule = NULL;
	int rc = 0;

	rule = table->efrm_ft_first_rule;

	/* Walk to the correct rule. */
	while ( rule && position ) {
		prev_rule = rule;
		rule = rule->efrm_fr_next;
		position -= 1;
	}
	if ( rule ) {
		ethrm_unlink_rule( rule, table, prev_rule );
		kfree( rule );
		/* If there are no rules, remove the associated files */
		if ( !table->efrm_ft_first_rule ) {
			efrm_remove_files( table );
		}
	} else {
		/* Insufficient rules in table. */
		rc = -EINVAL;
	}

	return rc;
}

static void remove_all_rules_from_table( efrm_filter_table_t* table )
{
	/* Remove all the rules from the table */

	efrm_filter_rule_t* rule = table->efrm_ft_first_rule;
	while ( rule ) {
		efrm_filter_rule_t* next = rule->efrm_fr_next;
		kfree( rule );
		rule = next;
	}
	table->efrm_ft_first_rule = NULL;
	table->efrm_ft_last_rule = NULL;
	efrm_remove_files( table );
}

static int remove_table( efrm_filter_table_t* table )
{
        efrm_interface_name_t* name;

	/* Free up a table, maintaining the table of tables.
	   Returns zero or a negative value on failure */
	if ( !table )
		return -EINVAL;
        name = table->efrm_ft_interface_name;
	remove_all_rules_from_table(table);
	ethrm_unlink_table(table);
	kfree( table );
        /* If this was the last table for this interface name, free
         * the interface name too. */
        if( name->efrm_in_root_table == NULL )
                remove_interface_name( name );

	return 0;
}


static int remove_all_rules( struct net* netns, char const* ifname )
{
	/* Remove all rules associated with a device.
	   Returns 0 on success, or a negative failure value. */
	efrm_filter_table_t* table;
	int rc = -EINVAL;
	int found;

	found = find_table_by_ifname( netns, ifname, &table );
	if ( found ) {
		remove_all_rules_from_table(table);
		rc = 0;
	}
	return rc;
}


static int remove_rule( struct net* netns, char const* ifname, int position )
{
	/* Remove the the rule at position from the table associated with
	   this device.
	   Returns 0 or a negative error code. */
	efrm_filter_table_t* table;
	int found;
        found = find_table_by_ifname( netns, ifname, &table );
	if ( !found )
		return -EINVAL;
	return remove_rule_from_table( table, position );
}

#ifdef CONFIG_NET_NS
static void filter_exit_net( struct net* net )
{
        efrm_interface_name_t *name, *name_n;
        efrm_filter_table_t *table, *table_n;

	mutex_lock( &efrm_ft_mutex );

        for( name = efrm_in_first_interface; name; name = name_n ) {
                name_n = name->efrm_in_next;

                for( table = name->efrm_in_root_table; table; table = table_n ) {
                        table_n = table->efrm_ft_next;

                        if( table->efrm_ft_netns == net )
                                remove_table( table );
                }
        }

	mutex_unlock( &efrm_ft_mutex );
}

static struct pernet_operations filter_net_ops = {
        .exit = filter_exit_net,
};
#endif

static int print_eth_rule ( struct seq_file *seq, char const* iface,
                                int number, char const* action,
                                efrm_filter_rule_macaddress_t const* rule,
                                unsigned short vlan_id )
{
	seq_printf( seq, "if=%s rule=%d protocol=eth "
		"mac=%02x:%02x:%02x:%02x:%02x:%02x"
		"/%02x:%02x:%02x:%02x:%02x:%02x vlan=%d action=%s\n",
		iface ? iface : "?", number,
		(unsigned char) rule->efrm_lcl_mac[0] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[1] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[2] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[3] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[4] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[5] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[0] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[1] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[2] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[3] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[4] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[5] & 0xff,
		vlan_id,
		action );
	return 0;
};

static int print_ip_rule ( struct seq_file *seq, char const* iface,
                               int number, char const* action,
                               efrm_filter_rule_portrange_t const* rule,
                               efrm_protocol_t protocol,
                               unsigned short vlan_id )
{
	seq_printf( seq, "if=%s rule=%d protocol=%s"
		" local_ip=" CI_IP_PRINTF_FORMAT "/" CI_IP_PRINTF_FORMAT
		" remote_ip=" CI_IP_PRINTF_FORMAT "/" CI_IP_PRINTF_FORMAT
		" local_port=%d-%d remote_port=%d-%d vlan=%d action=%s\n",
		iface ? iface : "?", number,
		efrm_get_protocol_name( protocol ),
		CI_IP_PRINTF_ARGS( &rule->efrp_lcl_ip ),
		CI_IP_PRINTF_ARGS( &rule->efrp_lcl_mask ),
		CI_IP_PRINTF_ARGS( &rule->efrp_rmt_ip ),
		CI_IP_PRINTF_ARGS( &rule->efrp_rmt_mask ),
		rule->efrp_lcl_min, rule->efrp_lcl_max,
		rule->efrp_rmt_min, rule->efrp_rmt_max,
		vlan_id,
		action );
	return 0;
}

static int print_rule ( struct seq_file *seq,
                        efrm_filter_rule_t const* rule, int number )
{
	/* Print a rule in a human readable form (that the parser can read
	   back in) to the specified buffer.
	   Returns the number of characters printed. */

	/* TODO: Really should indicate a desire to print past the end of the
	   buffer, and handle the user reading further. */
	efrm_filter_table_t const* table;
	char const* iface;
	char const* action;

	action = efrm_get_action_name( rule->efr_action );
	table = seq ? (efrm_filter_table_t const*) seq->private : NULL;
	iface = table ? table->efrm_ft_interface_name->efrm_in_interface_name : NULL;

	if ( rule->efr_protocol == ep_eth ) {
		return print_eth_rule( seq, iface, number, action,
		                       &rule->efrm_rule.efr_macaddess,
		                       rule->efrm_vlan_id );
	} else {
		return print_ip_rule( seq, iface, number, action,
		                      &rule->efrm_rule.efr_range,
		                      rule->efr_protocol,
		                      rule->efrm_vlan_id );
	}
}


/* As not all filters will have ipv4 hosts/ports etc.  use this which
   checks the spec match_flags field first */
static inline int efx_filter_get_ipv4(const struct efx_filter_spec *spec,
				      __be32 *host1, __be16 *port1,
				      __be32 *host2, __be16 *port2)
{
	if( (spec->match_flags & EFX_FILTER_MATCH_ETHER_TYPE) &&
	    (spec->ether_type == htons(ETH_P_IP)) ) {
		if( spec->match_flags & EFX_FILTER_MATCH_LOC_HOST )
			*host2 = spec->loc_host[0];
		else
			*host2 = 0;

		if( spec->match_flags & EFX_FILTER_MATCH_REM_HOST )
			*host1 = spec->rem_host[0];
		else
			*host1 = 0;

		if( spec->match_flags & EFX_FILTER_MATCH_LOC_PORT )
			*port2 = spec->loc_port;
		else
			*port2 = 0;

		if( spec->match_flags & EFX_FILTER_MATCH_REM_PORT )
			*port1 = spec->rem_port;
		else
			*port1 = 0;

		return 0;
	}
	else
		return -EINVAL;
}


static inline int efx_get_vlan(const struct efx_filter_spec *spec, u16* vid )
{
	/* TODO support inner VLAN tag matching */
	if( spec->match_flags & EFX_FILTER_MATCH_OUTER_VID )
		*vid = CI_BSWAP_BE16(spec->outer_vid);
	else
		*vid = EFX_FILTER_VID_UNSPEC;
	return 0;
}

static inline int
efx_filter_get_mac(const struct efx_filter_spec *spec, u8 *addr, u16* vid )
{
	int rc = efx_get_vlan(spec, vid);
	if ( rc < 0 )
		return rc;

	/* TODO support remote MAC address matching */
	if( !efrm_is_mac_spec( spec ) )
		return -EINVAL;

	memcpy(addr, spec->loc_mac, ETH_ALEN);
	return 0;
}

/* TODO: Move these helper functions to their own section */
static int within( int low, int high, int test )
{
	return ( test >= low ) && ( test <= high );
}

static int ip_matches( __be32 ip, __be32 mask, __be32 test )
{
	/* Unspecified IP, or match the mask? */
	if ( !test )
		return 1;
	return ( test & mask ) == ( ip & mask );
}

static int mac_byte_matches( char mac, char mask, char test )
{
	return ( test & mask ) == ( mac & mask );
}

static int efrm_vlan_matches( u16 vlan, efrm_filter_rule_t const* rule )
{
	/* If a filter could be included by the rule, it is -
	   So vlan0 matches everything, and unspecified is matched by any.
	*/
	unsigned short rule_vlan = rule->efrm_vlan_id;
	return (rule_vlan == 0) ||
	       (vlan == EFX_FILTER_VID_UNSPEC) ||
	       (vlan == rule_vlan);
}

static int efrm_portrange_match( struct efx_filter_spec *spec,
                                        efrm_filter_rule_t const* rule )
{
	__be32 rmt = 0, lcl = 0;
	__be16 port1 = 0, port2 = 0;
	int lcl_prt, rmt_prt;
	efrm_protocol_t protocol = rule->efr_protocol;
	u16 vlan = EFX_FILTER_VID_UNSPEC;
	efrm_filter_rule_portrange_t const* range = &rule->efrm_rule.efr_range;

	efx_filter_get_ipv4(spec, &rmt, &port1, &lcl, &port2);
	/* TODO: Ensure endianness of ef_iptble in a nicer way that this. */
	rmt_prt = CI_BSWAP_BE16(port1);
	lcl_prt = CI_BSWAP_BE16(port2);
	efx_get_vlan( spec, &vlan );

	/* right protocol?  In range?  Ip's match? */
	return efrm_protocol_matches(spec, protocol ) &&
	       within( range->efrp_lcl_min, range->efrp_lcl_max, lcl_prt ) &&
	       within( range->efrp_rmt_min, range->efrp_rmt_max, rmt_prt ) &&
	       ip_matches( range->efrp_lcl_ip, range->efrp_lcl_mask, lcl ) &&
	       ip_matches( range->efrp_rmt_ip, range->efrp_rmt_mask, rmt ) &&
	       efrm_vlan_matches( vlan, rule );
}

static int efrm_mac_match( efrm_filter_rule_t const* rule,
                           struct efx_filter_spec* spec )
{
	/* Does the mac+vlan in the spec match the mac rule? */
	efrm_filter_rule_macaddress_t const* mac;
	u16 vlan;
	int matches = 0;
	char addr[6];
	int i;
	mac = &(rule->efrm_rule.efr_macaddess);

	if ( !efrm_is_mac_spec(spec) )
		return 0;

	efx_filter_get_mac(spec, addr, &vlan );
	for ( i=0; i<6; ++i ) {
		matches += mac_byte_matches( mac->efrm_lcl_mac[i],
		                             mac->efrm_lcl_mask[i],
		                             addr[i] );
	}
	return (matches == 6) && efrm_vlan_matches( vlan, rule );
}

static inline int efrm_filter_check (const struct device* dev,
                                     struct efx_filter_spec *spec)
{
	/* This is the function that actually checks whether a filter spec
	   matches one of the rules for this interface.
	   Returns -EACCES if the filter should be dropped, zero otherwise
	   (including if it matches an ACCEPT rule)
	   As it runs at driver level, it cannot grab the mutex; so it must
	   take the spinlock instead.
	   TODO: Ideally, should enforce mac rules against IP and vice versa.
	*/
	efrm_filter_action_t rc = EFRM_FR_ACTION_UNSUPPORTED;
	efrm_filter_rule_t* rule = NULL;
	efrm_filter_table_t* table = NULL;
	char const* pci = efrm_get_pciname_from_device(dev);
	int unsupported = 0;

	spin_lock_bh(&efrm_ft_lock);

	if ( !find_table_by_pcidevice( pci, &table ) )
	{
		/* No rules for this interface, so accept. */
		goto check_filter_complete;
	}
	rule = table->efrm_ft_first_rule;

	while ( rule )
	{
		if ( rule->eit_ruletype == EFRM_FR_PORTRANGE ) {
			if ( efrm_portrange_match(
			     spec,
			     rule ) )
			{
				/* Matched rule, take its action and stop */
				rc = rule->efr_action;
				break;
			}
		}
		else if ( rule->eit_ruletype == EFRM_FR_MACADDRESS )
		{
			/* TODO include remote MAC filters */
			if ( efrm_mac_match( rule, spec ) )
			{
				rc = rule->efr_action;
				break;
			}
		}
		else {
			/* UNSUPPORTED RULE!
			   Have to get out of the spinlock to report it */
			unsupported = 1;
			break;
		}
		rule = rule->efrm_fr_next;
	}

check_filter_complete:
	spin_unlock_bh(&efrm_ft_lock);

	if ( unsupported ) {
		EFRM_ERR( "efrm_filter_check unsupported rule type %d\n",
		          rule ? rule->eit_ruletype : -1 );
	}
	return ( rc == EFRM_FR_ACTION_DROP ) ? -EACCES : 0;
}

static efrm_filter_rule_t* efrm_allocate_blank_rule(void) {
	/* Create a new rule structure. */
	efrm_filter_rule_t* rule = kmalloc( sizeof(efrm_filter_rule_t),
	                                    GFP_KERNEL );
	memset( rule, 0, sizeof(efrm_filter_rule_t) );
	rule->eit_ruletype = EFRM_FR_PORTRANGE;
	rule->efrm_rule.efr_range.efrp_lcl_max = 65535;
	rule->efrm_rule.efr_range.efrp_rmt_max = 65535;
	memset( rule->efrm_rule.efr_macaddess.efrm_lcl_mac, 0xff, 6 );
	rule->efr_protocol = ep_tcp;
	rule->efr_action = EFRM_FR_ACTION_ACCEPT;
	return rule;
}

static int
efrm_read_if ( const char** buf, size_t* remain, int* done,
               char* name, int* seen )
{
	if ( efrm_compare_and_skip( buf, remain, "if=" ) != 0 )
		return 0;

	if ( *seen ) {
		EFRM_WARN( "%s: Seen multiple interfaces", __func__ );
		*done = 1;
	} else {
		*seen = efrm_consume_next_word( buf, remain, name, IFNAMSIZ );
	}
	return 1;
}

static int
efrm_read_rule ( const char** buf, size_t* remain, int* done,
                 int* rule_number )
{
	if ( efrm_compare_and_skip( buf, remain, "rule=" ) != 0 )
		return 0;

	if ( *rule_number == -1 ) {
		*rule_number = efrm_atoi( buf, remain );
	} else {
		EFRM_ERR("%s: Seen multiple rule numbers", __func__ );
		*done = 1;
	}
	return 1;
}

static int
efrm_read_action ( const char** buf, size_t* remain, int* done,
                   efrm_filter_action_t* action, int* seen )
{
	if ( efrm_compare_and_skip( buf, remain, "action=" ) != 0 )
		return 0;

	if ( *seen ) {
		EFRM_WARN("%s: Seen multiple actions", __func__ );
		*done = 1;
	} else {
		if ( !efrm_compare_and_skip( buf, remain, "ACCEPT" ) ||
		     !efrm_compare_and_skip( buf, remain, "ACCELERATE" ) )
		{
			*action = EFRM_FR_ACTION_ACCEPT;
			*seen = 1;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "REJECT" ) ||
		          !efrm_compare_and_skip( buf, remain, "DROP" ) ||
		          !efrm_compare_and_skip( buf, remain, "DECELERATE" ) )
		{
			*action = EFRM_FR_ACTION_DROP;
			*seen = 1;
		} else {
			EFRM_ERR("%s: Unable to understand action: %s (%d)",
					 __func__, *buf, (int)*remain );
			*done = 1;
		}
	}
	return 1;
}

static int
efrm_read_protocol( const char** buf, size_t* remain, int* done,
                    char* protocol,
                    efrm_filter_ruletype_t* ruletype,
                    int* seen )
{
	if ( efrm_compare_and_skip( buf, remain, "protocol=" ) != 0 )
		return 0;

	if ( *seen )
	{
		EFRM_WARN("%s: Seen multiple protocols", __func__ );
		*done = 1;
	} else {
		if ( !efrm_compare_and_skip( buf, remain, "tcp" ) ) {
			*protocol = ep_tcp;
			*ruletype = EFRM_FR_PORTRANGE;
			*seen = 1;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "udp" ) ) {
			*protocol = ep_udp;
			*ruletype = EFRM_FR_PORTRANGE;
			*seen = 1;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "ip" ) ) {
			*protocol = ep_ip;
			*ruletype = EFRM_FR_PORTRANGE;
			*seen = 1;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "eth" ) ) {
			*protocol = ep_eth;
			*ruletype = EFRM_FR_MACADDRESS;
			*seen = 1;
		}
		else {
			EFRM_ERR("%s: Unable to understand protocol: %s",
			         __func__, *buf );
			*done = 1;
		}
	}
	return 1;
}

static int
efrm_read_lcl_ip( const char** buf, size_t* remain, int* done,
                  efrm_filter_rule_portrange_t* range )
{
	if ( efrm_compare_and_skip( buf, remain, "local_ip=" ) )
		return 0;

	if ( !efrm_consume_ip_mask(buf, remain, &range->efrp_lcl_ip,
	                           &range->efrp_lcl_mask ) ) {
		EFRM_ERR("%s: Invalid local_ip rule.\n", __func__ );
		*done = 1;
		return 0;
	}
	return 1;
}

static int
efrm_read_rmt_ip( const char** buf, size_t* remain, int* done,
                  efrm_filter_rule_portrange_t* range )
{
	if ( efrm_compare_and_skip( buf, remain, "remote_ip=" ) )
		return 0;

	if ( !efrm_consume_ip_mask(buf, remain, &range->efrp_rmt_ip,
	                           &range->efrp_rmt_mask ) ) {
		EFRM_ERR("%s: Invalid remote_ip rule.\n", __func__ );
		*done = 1;
		return 0;
	}
	return 1;
}

static int efrm_read_lcl_port( const char** buf, size_t* remain, int* done,
                               efrm_filter_rule_portrange_t* range )
{
	if ( efrm_compare_and_skip( buf, remain, "local_port=" ) )
		return 0;

	efrm_consume_portrange( buf, remain,
	                        &range->efrp_lcl_min, &range->efrp_lcl_max );
	return 1;
}

static int efrm_read_rmt_port( const char** buf, size_t* remain, int* done,
                               efrm_filter_rule_portrange_t* range )
{
	if ( efrm_compare_and_skip( buf, remain, "remote_port=" ) )
		return 0;

	efrm_consume_portrange( buf, remain,
	                        &range->efrp_rmt_min, &range->efrp_rmt_max );
	return 1;
}

static int efrm_read_mac( const char** buf, size_t* remain, int* done,
                          efrm_filter_rule_macaddress_t* mac )
{
	if ( efrm_compare_and_skip( buf, remain, "mac=" ) )
		return 0;

	if ( !efrm_consume_mac( buf, remain,
                                mac->efrm_lcl_mac, mac->efrm_lcl_mask ) ) {
		EFRM_ERR( "%s: Invalid mac= rule.\n", __func__ );
		*done = 1;
		return 0;
	}
	return 1;
}

static int efrm_read_vlan( const char** buf, size_t* remain, int* done,
                           efrm_filter_rule_t* rule )
{
	if ( efrm_compare_and_skip( buf, remain, "vlan=" ) )
		return 0;

	rule->efrm_vlan_id = efrm_atoi(buf,remain);
	return 1;
}

/*
  buf and remain will be altered to point at the next rule
  ifname and rulenumber will output the interface and position for the rule
  buf expects rules of the form:
   if=%s rule=%d protocol=%s local_ip=a.d.b.c/mask \
   remote_ip=a.b.c.d/mask local_port=%d-%d remote_port=%d-%d action=%s
  Or:
   if=%s rule=%d protocol=eth mac=xx:xx:xx:xx:xx:xx/xx:xx:xx:xx:xx:xx action=%s
  Returns a newly allocated rule (or NULL)
*/
static efrm_filter_rule_t*
efrm_interpret_rule( const char** buf, size_t* remain,
                     char* ifname, int* rule_number )
{
	int num_matches = 0;
	int num_controls = 0;
	int act_seen = 0;
	int protocol_seen = 0;
	int if_seen = 0;
	int done = 0;
	efrm_filter_rule_t* rule = 0;

	if ( !buf || !remain || !*buf || !*remain ) return NULL;

	rule = efrm_allocate_blank_rule();
	if ( !rule ) {
		EFRM_ERR("%s: Out of memory allocating new rule.\n", __func__);
		return NULL;
	}

	while ( !done && **buf != '\0' && *remain > 0 ) {
		efrm_skip_whitespace( buf, remain );

		if ( efrm_read_if( buf, remain, &done, ifname, &if_seen ) ||
		     efrm_read_rule( buf, remain, &done, rule_number ) ||
		     efrm_read_action( buf, remain, &done,
		                       &rule->efr_action, &act_seen ) ||
		     efrm_read_protocol( buf, remain, &done,
		                         &rule->efr_protocol,
		                         &rule->eit_ruletype,
		                         &protocol_seen ) )
		{
			num_controls++;
		}
		else if ( efrm_read_lcl_ip( buf, remain, &done,
		                            &rule->efrm_rule.efr_range ) ||
		          efrm_read_rmt_ip( buf, remain, &done,
		                            &rule->efrm_rule.efr_range ) ||
		          efrm_read_lcl_port( buf, remain, &done,
		                              &rule->efrm_rule.efr_range ) ||
		          efrm_read_rmt_port( buf, remain, &done,
		                              &rule->efrm_rule.efr_range ) ||
		          efrm_read_mac( buf, remain, &done,
		                         &rule->efrm_rule.efr_macaddess ) ||
		          efrm_read_vlan( buf, remain, &done, rule ) )
		{
			num_matches++;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "\n" ) ) {
			/* End of rule, check it's valid and return it. */
			if ( if_seen &&
			     protocol_seen &&
			     act_seen &&
			     (num_matches > 0 )
			)
			{
				return rule;
			} else {
				EFRM_ERR("%s: Invalid rule", __func__ );
				break;
			}
		}
		else if ( !done ) {
			/* Only print this if we didnt already error out */
			EFRM_ERR("%s: Unable to understand remainder: %s",
			         __func__, *buf );
			break;
		}
	}

	kfree( rule );
	return NULL;
}

static int efrm_text_to_table_entry( const char ** buf, size_t* remain )
{
	char ifname [IFNAMSIZ];
	int rule_number = -1;
	efrm_filter_table_t* table;
	int rc;
        struct net* netns;

	efrm_filter_rule_t* rule = efrm_interpret_rule( buf, remain, ifname,
	                                                &rule_number );
	if ( !rule )
		return -ENOMEM;

        netns = get_net(current->nsproxy->net_ns);

	/* And actually apply that rule to the table. */
	/* Add the specified rule to the table associated with this
	   interface name, at the given position - negative position means
	   'append'.
	   Returns 0, or a negative error code.
	   May create a new table. */

	if ( !find_table_by_ifname( netns, ifname, &table ) ) {
		EFRM_NOTICE( "%s: Adding rule for unknown interface %s.",
		             __func__, ifname );
		table = efrm_insert_new_table( NULL, netns, ifname );
	}

        put_net(netns);

	if ( !table ) {
                return -ENOMEM;
	}
	rc = add_rule_to_table( table, rule, rule_number );
	if ( rc ) {
		EFRM_ERR( "%s: Unable to add rule %d to %s (%d).",
		          __func__, rule_number, ifname, rc );
		kfree( rule );
	}
	return rc;
}

/* ***************************** */
/* Entry points via file access. */
/* ***************************** */
/* /proc/driver/sfc_resource/ */
/* ************************** */

static int create_kstr_from_ubuf( const char __user *ubuf, size_t size,
				  const char** out_kstr )
{
	/* Creates a buffer in kernel space and copies data into it from
	 * user space buffer. '\0' terminates the output buffer so it
	 * can be safely passed into string handling functions. */
	char* kbuf;
	int rc;
	if( out_kstr == NULL ) {
		EFRM_ERR( "%s: Output buffer pointer is NULL.", __func__ );
		return -EINVAL;
	}
	*out_kstr = NULL;
	kbuf = kmalloc(size + 1, GFP_KERNEL);
	if( kbuf == NULL ) {
		EFRM_ERR( "%s: Failed to allocate kernel buffer.", __func__ );
		return -ENOMEM;
	}
	rc = copy_from_user(kbuf, ubuf, size);
	if( rc != 0 ) {
		EFRM_ERR( "%s: Failed to copy %d bytes from user buffer.",
			__func__, rc );
		kfree(kbuf);
		return -EFAULT;
	}
	kbuf[size] = '\0';
	*out_kstr = kbuf;
	return 0;
}


static ssize_t efrm_add_rule(struct file *file, const char __user *ubuf,
		      size_t count, loff_t *ppos)
{
	/* ENTRYPOINT from firewall_add
	Interpret the provided buffer, and add the rules therein. */
	size_t remain = count;
	const char* buf;
	const char* orig_buf;
	int rc;
	rc = create_kstr_from_ubuf( ubuf, count, &orig_buf );
	if( rc != 0 ) {
		EFRM_ERR( "%s: Failed to create kernel input string, rc=%d.",
			__func__, rc );
		return rc;
	}
	buf = orig_buf;
	mutex_lock( &efrm_ft_mutex );

	while ( *buf != '\0' && remain > 0 ) {
		if ( efrm_text_to_table_entry( &buf, &remain ) )
			break;
	}

	mutex_unlock( &efrm_ft_mutex );
	kfree(orig_buf);
	return count;
}
static const struct proc_ops efrm_fops_add_rule = {
	PROC_OPS_SET_OWNER
	.proc_write		= efrm_add_rule,
};

static ssize_t efrm_del_rule(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	/* ENTRYPOINT from firewall_del.
	   Interpret the buffer and delete the specified rule(s) */
	size_t remain = count;
	char ifname [IFNAMSIZ];
	const char* orig_buf;
	const char* buf;
	int is_all = 0;
	int interface = 0;
	int rule_number = -1;
	int rc = 0;
        struct net* netns;

	rc = create_kstr_from_ubuf(ubuf, count, &orig_buf);
	if( rc != 0 ) {
		EFRM_ERR( "%s: Failed to create kernel input string, rc=%d.",
			__func__, rc );
		return rc;
	}
	buf = orig_buf;
	efrm_skip_whitespace( &buf, &remain );
	/* Either if=ethX or ethX supported */
	efrm_compare_and_skip( &buf, &remain, "if=" );
	efrm_skip_whitespace( &buf, &remain );
	interface = efrm_consume_next_word( &buf, &remain, ifname, IFNAMSIZ );
	if ( interface <= 0 ) {
		EFRM_ERR( "%s: Failed to understand interface.", __func__ );
		kfree(orig_buf);
		return count;
	}

	/* Either rule= or plain, supported */
	efrm_skip_whitespace( &buf, &remain );
	efrm_compare_and_skip( &buf, &remain, "rule=" );
	efrm_skip_whitespace( &buf, &remain );

	is_all = efrm_compare_and_skip( &buf, &remain, "all" ) == 0;
	if ( !is_all ) {
		rule_number = efrm_atoi( &buf, &remain );
	}

	mutex_lock( &efrm_ft_mutex );
        netns = get_net(current->nsproxy->net_ns);

	if ( is_all ) {
		rc = remove_all_rules( netns, ifname );
		if ( rc == -EINVAL && !interface_has_rules( netns, ifname ) ) {
			/* While technically invalid to remove all rules from
			   a nonexistant table, when the result is that table
			   having no rules, count it as a success. */
			rc = 0;
		}
	} else {
		rc = remove_rule( netns, ifname, rule_number );
	}
        put_net(netns);
	mutex_unlock( &efrm_ft_mutex );

	if ( rc ) {
		EFRM_ERR( "%s: Failed to remove rule %d from %s. Code: %d\n",
		          __func__, rule_number, ifname, rc );
	}
	kfree(orig_buf);
	return count;
}
static const struct proc_ops efrm_fops_del_rule = {
	PROC_OPS_SET_OWNER
	.proc_write		= efrm_del_rule,
};

/* ********************************************* */
/* /proc/driver/sfc_resource/ethX/firewall_rules */
/* ********************************************* */

static efrm_filter_rule_t const*
efrm_get_rule_by_number( efrm_filter_table_t const* table, int rule_number ) {
  efrm_filter_rule_t const* rval;
  int curr = 0;

  if ( !table || rule_number < 0 )
    return NULL;

  rval = table->efrm_ft_first_rule;
  while ( curr < rule_number && rval != NULL ) {
    rval = rval->efrm_fr_next;
    curr++;
  }
  return rval;
}

efrm_filter_rule_t const*
efrm_rule_from_iter(struct seq_file* seq, loff_t const* iter_ptr) {
  efrm_filter_table_t const* table;

  if ( !seq || !iter_ptr )
    return NULL;

  table = seq ? (efrm_filter_table_t const*) seq->private : NULL;

  return efrm_get_rule_by_number( table, (int)*iter_ptr );
}

static loff_t efrm_read_rules_iter;

static void* efrm_read_rules_start(struct seq_file* seq, loff_t* pos) {
  void* rval = NULL;

  mutex_lock( &efrm_ft_mutex );

  if ( efrm_rule_from_iter( seq, pos ) ) {
    efrm_read_rules_iter = *pos;
    rval = (void*) &efrm_read_rules_iter;
  } else {
    efrm_read_rules_iter = 0;
    *pos = 0;
  }

  mutex_unlock( &efrm_ft_mutex );

  return rval;
}

static void* efrm_read_rules_next(struct seq_file* seq, void* v, loff_t* pos) {
  loff_t next;
  loff_t* iter_ptr = (loff_t*) v;

  if ( !iter_ptr )
    return NULL;

  next = (*(loff_t*)v) + 1;

  mutex_lock( &efrm_ft_mutex );

  if ( efrm_rule_from_iter(seq, &next) ) {
    *iter_ptr = next;
    *pos = *pos + 1;
  } else {
    *iter_ptr = 0;
    iter_ptr = NULL;
  }

  mutex_unlock( &efrm_ft_mutex );

  return (void*) iter_ptr;
}

int efrm_read_rules_show(struct seq_file* seq, void* v) {
  efrm_filter_rule_t const* rule;
  int rule_number;
  int rc = -EINVAL;
  loff_t const* iter_ptr = (loff_t const*) v;

  if ( !seq || !iter_ptr )
    return rc;

  mutex_lock( &efrm_ft_mutex );

  rule = efrm_rule_from_iter(seq, iter_ptr);
  rule_number = (int) *iter_ptr;
  if ( rule )
    rc = print_rule(seq, rule, rule_number );

  mutex_unlock( &efrm_ft_mutex );

  if ( rc > 0 )
    rc = 0;
  return rc;
}

static void efrm_read_rules_stop(struct seq_file* seq, void* v) {
  /* Nothing to do, the iterator is static */
}

static struct seq_operations efrm_read_rules_seq_ops = {
  .start = efrm_read_rules_start,
  .next = efrm_read_rules_next,
  .stop = efrm_read_rules_stop,
  .show = efrm_read_rules_show
};

static int efrm_read_rules_seq_open(struct inode* inode, struct file* file) {
  int rc = 0;
  efrm_interface_name_t* name = PDE_DATA(inode);
  efrm_filter_table_t* table;
  struct net* netns = get_net(current->nsproxy->net_ns);
  if ( !find_table_by_ifname( netns, name->efrm_in_interface_name, &table ) )
          rc = -ENOENT;
  put_net(netns);
  if ( rc >= 0 )
          rc = seq_open(file, &efrm_read_rules_seq_ops);
  if ( rc >= 0 && file && file->private_data ) {
          ((struct seq_file*)file->private_data)->private = table;
  }
  return rc;
}

static int efrm_read_rules_release(struct inode* inode, struct file* file) {
  /* Careful!  seq_release_private would free the table! */
  return seq_release( inode, file );
}

static const struct proc_ops efrm_fops_rules = {
  PROC_OPS_SET_OWNER
  .proc_open     = efrm_read_rules_seq_open,
  .proc_read     = seq_read,
  .proc_lseek    = seq_lseek,
  .proc_release  = efrm_read_rules_release
};

/* ***************************************** */
/* Initialisation and shutdown entry points. */
/* ***************************************** */

void efrm_filter_shutdown()
{
	/* Complete shutdown */
	int rc = 0;

#ifdef CONFIG_NET_NS
        unregister_pernet_subsys( &filter_net_ops );
#endif

	mutex_lock( &efrm_ft_mutex );

	/* Make sure everything is freed up properly */
	while( !rc && efrm_in_first_interface &&
	       efrm_in_first_interface->efrm_in_root_table ) {
		rc = remove_table(efrm_in_first_interface->efrm_in_root_table);
		if( rc ) {
			EFRM_ERR( "%s:Error %d removing table",
				  __func__, rc );
		}
	}

	if( efrm_in_first_interface != NULL )
		remove_interface_name( efrm_in_first_interface );
	efrm_in_first_interface = NULL;

	mutex_unlock( &efrm_ft_mutex );
}

void efrm_filter_init()
{
	/* First time init */
#ifdef CONFIG_NET_NS
        int rc;

        rc = register_pernet_subsys( &filter_net_ops );
        if( rc < 0 ) {
                EFRM_ERR( "%s: can't register per-namespace ops: %d",
                          __func__, rc );
                return;
        }
#endif

        mutex_lock( &efrm_ft_mutex );
        efrm_in_first_interface = NULL;
	mutex_unlock( &efrm_ft_mutex );
}

void efrm_filter_install_proc_entries()
{
	/* Add the /proc/ files that are not per-interface. */
	efrm_pd_add_rule = efrm_proc_create_file( "firewall_add", 0200,
					NULL, &efrm_fops_add_rule, NULL );
	efrm_pd_del_rule = efrm_proc_create_file( "firewall_del", 0200,
					NULL, &efrm_fops_del_rule, NULL );
}

void efrm_filter_remove_proc_entries()
{
	/* Remove the /proc/ files that are not per-interface. */
	efrm_proc_remove_file( efrm_pd_add_rule );
	efrm_pd_add_rule = NULL;
	efrm_proc_remove_file( efrm_pd_del_rule );
	efrm_pd_del_rule = NULL;
}

int efrm_remove_table_name( char const *pciname )
{
	efrm_filter_table_t* table;
	int found = find_table_by_pcidevice( pciname, &table );
	if ( found ) {
		*table->efrm_ft_pcidev_name = '\0';
		 efrm_remove_files( table );
	}
	return found;
}

void efrm_map_table( struct net* netns, char const* ifname,
                     char const* pciname )
{
	int found;
	efrm_filter_table_t* table = NULL;

	/* We may have:  A previous name for this pci_device
	                 Rules for this name, that don't yet have a device.
	                 No table at all.
	   Tables belong to *interface* names.
	   First: Erase any previous mapping to this device. */
	/* Then: Set the new mapping */
	found = find_table_by_ifname( netns, ifname, &table );
	if ( !found ) {
		table = efrm_insert_new_table( pciname, netns, ifname );
	}
	if ( table ) {
		efrm_add_files( table );
		strlcpy( table->efrm_ft_pcidev_name, pciname,
			 IFNAMSIZ );
	}
}

void efrm_init_resource_filter(const struct device *dev, int ifindex)
{
	/* Per-Interface init */
	char const* pciname;
	char const* ifname;
	struct net_device* ndev;

	if ( !dev )
		return;

	mutex_lock( &efrm_ft_mutex );

	pciname = efrm_get_pciname_from_device( dev );
	ifname = efrm_get_interfacename_from_index( ifindex, &ndev );

	if ( pciname )
		efrm_remove_table_name( pciname );

	if ( ifname ) {
		efrm_map_table( dev_net( ndev ), ifname, pciname );
		dev_put(ndev);
	}

	mutex_unlock( &efrm_ft_mutex );
	return;
}

void efrm_shutdown_resource_filter(const struct device *dev)
{
	/* Per interface shutdown */
	char const* pciname;

	if ( !dev )
		return;

	mutex_lock( &efrm_ft_mutex );

	/* Un-name the table, so its rules won't get used; but don't remove
	   the rules, as the interface can come back later. */

	pciname = efrm_get_pciname_from_device( dev );
	if ( pciname )
		efrm_remove_table_name( pciname );

	mutex_unlock( &efrm_ft_mutex );
}

/* *********************************** */
/* * Entry point for device renaming * */
/* *********************************** */
int efrm_filter_rename( struct efhw_nic *nic, struct net_device *net_dev )
{
	char const* ifname;
	char const* pciname;

	if ( !nic || !net_dev ) {
		EFRM_ERR("%s:Internal error %p %p", __func__, nic, net_dev );
		return -EINVAL;
	}

	/* efhw_nic is the device, which has the real id */
	pciname = efrm_get_pciname_from_device( net_dev->dev.parent );
	if ( !pciname ) {
		EFRM_ERR("%s:Old device has no pciname", __func__ );
	}
	/* net_dev->name should contain the new name */
	ifname = net_dev->name;
	if ( !ifname ) {
		EFRM_ERR("%s:New device has no ifname", __func__ );
	}

	mutex_lock( &efrm_ft_mutex );

	EFRM_TRACE("%s:Renaming device %s, %s", __func__, pciname, ifname );

	if ( pciname )
		efrm_remove_table_name( pciname );
	if ( ifname )
		efrm_map_table( dev_net( net_dev ), ifname, pciname );

	mutex_unlock( &efrm_ft_mutex );

	return 0;
}

ci_inline u32 efrm_rss_mode_to_nic_flags(struct efhw_nic *efhw_nic,
                                         struct efx_dl_device *efx_dev,
					 u32 efrm_rss_mode)
{
	u32 nic_tcp_mode;
	u32 nic_src_mode = (1 << RSS_MODE_HASH_SRC_ADDR_LBN) |
			   (1 << RSS_MODE_HASH_SRC_PORT_LBN);
	u32 nic_dst_mode = (1 << RSS_MODE_HASH_DST_ADDR_LBN) |
			   (1 << RSS_MODE_HASH_DST_PORT_LBN);
	u32 nic_all_mode = nic_src_mode | nic_dst_mode;
	ci_dword_t nic_flags = { {efx_dl_rss_flags_default(efx_dev)} };
	ci_dword_t nic_flags_new;
	ci_dword_t nic_flags_mask;

        /* we need to use default flags in packed stream mode,
         * note in that case TCP hashing will surely be enabled,
         * so nothing to do there anyway */
        if( efhw_nic->flags & NIC_FLAG_RX_RSS_LIMITED )
                return nic_flags.u32[0];

	switch(efrm_rss_mode) {
	case EFRM_RSS_MODE_SRC:
		nic_tcp_mode = nic_src_mode;
		break;
	case EFRM_RSS_MODE_DST:
		nic_tcp_mode = nic_dst_mode;
		break;
	case EFRM_RSS_MODE_DEFAULT:
		nic_tcp_mode = nic_all_mode;
		break;
	default:
		EFHW_ASSERT(!"Unknown rss mode");
		return -EINVAL;
	};

	CI_POPULATE_DWORD_2(nic_flags_mask,
		MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_TCPV4_EN,
                     (1 << MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_IPV4_EN_WIDTH) - 1,
		MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TCP_IPV4_RSS_MODE,
                     ( efhw_nic->flags & NIC_FLAG_ADDITIONAL_RSS_MODES ) ?
                     (1 << MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TCP_IPV4_RSS_MODE_WIDTH) - 1 :
                     0
		);
	CI_POPULATE_DWORD_2(nic_flags_new,
		MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_TCPV4_EN, 1,
		MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TCP_IPV4_RSS_MODE, nic_tcp_mode
		);
        EFHW_ASSERT((nic_flags_new.u32[0] & nic_flags_mask.u32[0]) == nic_flags_new.u32[0]);
	return (nic_flags.u32[0] & ~nic_flags_mask.u32[0]) | nic_flags_new.u32[0];
}

int efrm_rss_context_alloc(struct efrm_client* client, u32 vport_id,
			   int shared,
			   const u32 *indir,
			   const u8 *key, u32 efrm_rss_mode,
			   int num_qs,
			   u32 *rss_context_out)
{
	int rc;
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device *efx_dev;
	u32 nic_rss_flags;

	efx_dev = efhw_nic_acquire_dl_device(efhw_nic);
	/* If [efx_dev] is NULL, the hardware is morally absent. */
	if (efx_dev == NULL)
		return -ENETDOWN;
	nic_rss_flags = efrm_rss_mode_to_nic_flags(efhw_nic, efx_dev, efrm_rss_mode);
	/* Driverlink API takes ef10 MCDI compatible RSS flags */
	rc = efx_dl_rss_context_new(efx_dev, indir, key, nic_rss_flags,
				    num_qs, rss_context_out);
	efhw_nic_release_dl_device(efhw_nic, efx_dev);
	return rc;
}
EXPORT_SYMBOL(efrm_rss_context_alloc);


int efrm_rss_context_update(struct efrm_client* client, u32 rss_context,
			    const u32 *indir, const u8 *key, u32 efrm_rss_mode)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device* efx_dev = efhw_nic_acquire_dl_device(efhw_nic);
	u32 nic_rss_flags;
	int rc;

	/* If [efx_dev] is NULL, the hardware is morally absent. */
	if (efx_dev == NULL)
		return -ENETDOWN;

	nic_rss_flags = efrm_rss_mode_to_nic_flags(efhw_nic, efx_dev, efrm_rss_mode);
	rc = efx_dl_rss_context_set(efx_dev, indir, key, nic_rss_flags,
				    rss_context);

	efhw_nic_release_dl_device(efhw_nic, efx_dev);

	return rc;
}
EXPORT_SYMBOL(efrm_rss_context_update);


int efrm_rss_context_free(struct efrm_client* client, u32 rss_context_id)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
        struct efx_dl_device *efx_dev;
        int rc;
        efx_dev = efhw_nic_acquire_dl_device(efhw_nic);
        /* If [efx_dev] is NULL, the hardware is morally absent. */
        if (efx_dev == NULL)
                return -ENETDOWN;
        rc = efx_dl_rss_context_free(efx_dev, rss_context_id);
        efhw_nic_release_dl_device(efhw_nic, efx_dev);
        return rc;
}
EXPORT_SYMBOL(efrm_rss_context_free);

int efrm_vport_alloc(struct efrm_client* client, u16 vlan_id, u16 *vport_handle_out)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device *efx_dev;
	int rc;
	efx_dev = efhw_nic_acquire_dl_device(efhw_nic);
	/* If [efx_dev] is NULL, the hardware is morally absent. */
	if (efx_dev == NULL)
		return -ENETDOWN;
	rc = efx_dl_vport_new(efx_dev, vlan_id, 0);
	if( rc >= 0 ) {
		*vport_handle_out = rc;
		rc = 0;
	}
	efhw_nic_release_dl_device(efhw_nic, efx_dev);
	return rc;
}
EXPORT_SYMBOL(efrm_vport_alloc);

int efrm_vport_free(struct efrm_client* client, u16 vport_handle)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device *efx_dev;
	int rc;
	efx_dev = efhw_nic_acquire_dl_device(efhw_nic);
	/* If [efx_dev] is NULL, the hardware is morally absent. */
	if (efx_dev == NULL)
		return -ENETDOWN;
	rc = efx_dl_vport_free(efx_dev, vport_handle);
	efhw_nic_release_dl_device(efhw_nic, efx_dev);
	return rc;
}
EXPORT_SYMBOL(efrm_vport_free);

/* ************************************************************* */
/* Entry point: check if a filter is valid, and insert it if so. */
/* ************************************************************* */
#ifdef EFHW_HAS_AF_XDP

#define EFX_IP_FILTER_MATCH_FLAGS \
                (EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_IP_PROTO | \
                 EFX_FILTER_MATCH_LOC_HOST | EFX_FILTER_MATCH_LOC_PORT)

static int efrm_efx_spec_to_ethtool_flow(struct efx_filter_spec* efx_spec,
					 struct ethtool_rx_flow_spec* fs)
{
	/* In order to support different driver capabilities we need to
	 * always install the same filter type. This means that we will
	 * always use a 3-tuple IP filter, even if a 5-tuple was requested.
	 * Although this can in theory match traffic not destined for us, in
	 * practice common usage means that it's sufficiently specific.
	 *
	 * The ethtool interface does not complain if a duplicate filter is
	 * inserted, and does not reference count such filters. That causes
	 * issues for the case where onload tries to replace a wild match
	 * filter with a full match filter, as it will add the new full match
	 * before removing the original wild. However, we treat both of these
	 * as the same 3-tuple and so the net result is that we remove the
	 * filter entirely. This occurs in two circumstances:
	 * - closing a listening socket with accepted sockets still open
	 * - connecting an already bound UDP socket
	 * We can avoid the first by setting oof_shared_keep_thresh=0 when
	 * using AF_XDP.
	 * The second is a rare case, and the failure mode here is to fall
	 * back to traffic via the kernel, so I'm living with it for now.
	 */

	/* Check that this is an IP filter */
	if ((efx_spec->match_flags & EFX_IP_FILTER_MATCH_FLAGS) !=
	    EFX_IP_FILTER_MATCH_FLAGS)
		return -EOPNOTSUPP;

	/* FIXME AF_XDP need to check whether we can install both IPv6 and
	 * IPv4 filters. For now just support IPv4.
	 */
	if (efx_spec->ether_type != ntohs(ETH_P_IP))
		return -EOPNOTSUPP;

	if (efx_spec->ip_proto == IPPROTO_TCP)
		fs->flow_type = TCP_V4_FLOW;
	else if (efx_spec->ip_proto == IPPROTO_UDP)
		fs->flow_type = UDP_V4_FLOW;
	else
		return -EINVAL;

	/* Populate the match fields. For each field we need to set both the
	 * value, and a mask of which bits in that field to match against.
	 */
	fs->h_u.tcp_ip4_spec.ip4dst = efx_spec->loc_host[0];
	fs->m_u.tcp_ip4_spec.ip4dst = 0xffffffff;
	fs->h_u.tcp_ip4_spec.pdst = efx_spec->loc_port;
	fs->m_u.tcp_ip4_spec.pdst = 0xffff;

	/* Give the driver free rein on where to insert the filter. */
	fs->location = RX_CLS_LOC_ANY;

	/* TODO AF_XDP: for now assume dmaq_id matches NIC channel
	 * based on insight into efhw/af_xdp.c */
	fs->ring_cookie = efx_spec->dmaq_id;

	return 0;
}

static int efrm_ethtool_filter_insert(struct net_device* dev,
				      struct efx_filter_spec* spec)
{
	int rc;
	struct ethtool_rxnfc info;
	const struct ethtool_ops *ops = dev->ethtool_ops;
	struct cmd_context ctx;

	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_SRXCLSRLINS;
	rc = efrm_efx_spec_to_ethtool_flow(spec, &info.fs);
	if ( rc < 0 )
		return rc;

	if (!ops->set_rxnfc)
		return -EOPNOTSUPP;

	ctx.netdev = dev;
	rc = rmgr_set_location(&ctx, &info.fs);
	if ( rc < 0 )
		return rc;

	rc = ops->set_rxnfc(dev, &info);
	if ( rc >= 0 )
		rc = info.fs.location;

	return rc;
}

#endif

int efrm_filter_insert(struct efrm_client *client,
		       struct efx_filter_spec *spec,
		       bool replace)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device *efx_dev = efhw_nic_acquire_dl_device(efhw_nic);
	struct net_device* net_dev;
	int rc;

#ifdef EFHW_HAS_AF_XDP
	if ( efhw_nic->devtype.arch == EFHW_ARCH_AF_XDP )
		return efrm_ethtool_filter_insert(efhw_nic->net_dev, spec);
#endif
	/* If [efx_dev] is NULL, the hardware is morally absent. */
	if ( efx_dev == NULL )
		return -ENETDOWN;

#if CI_CFG_IPV6
	/* FIXME: add IPv6 support to firewall rules (bug 85208) */
	if ( (spec->match_flags & EFX_FILTER_MATCH_ETHER_TYPE) &&
	     (spec->ether_type == htons(ETH_P_IPV6)) ) {
		rc = efx_dl_filter_insert( efx_dev, spec, replace );
		efhw_nic_release_dl_device(efhw_nic, efx_dev);
		return rc;
	}
#endif

	/* This should be called every time a driver wishes to insert a
	   filter to the NIC, to check whether the firewall rules want to
	   block it. */
	net_dev = efhw_nic_get_net_dev(efhw_nic);
	if( net_dev ) {
		rc = efrm_filter_check( net_dev->dev.parent, spec );
		dev_put(net_dev);
		if ( rc >= 0 )
			rc = efx_dl_filter_insert( efx_dev, spec, replace );
		efhw_nic_release_dl_device(efhw_nic, efx_dev);
	}
	else {
		rc = -ENODEV;
	}
	return rc;
}
EXPORT_SYMBOL(efrm_filter_insert);


#ifdef EFHW_HAS_AF_XDP
static int efrm_ethtool_filter_remove(struct net_device* dev, int filter_id)
{
	struct ethtool_rxnfc info;
	const struct ethtool_ops *ops = dev->ethtool_ops;

	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_SRXCLSRLDEL;
	info.fs.location = filter_id;

	if (!ops->set_rxnfc)
		return -EOPNOTSUPP;

	return ops->set_rxnfc(dev, &info);
}
#endif

void efrm_filter_remove(struct efrm_client *client, int filter_id)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efrm_nic *rnic = efrm_nic(efhw_nic);
	struct efx_dl_device *efx_dev = efhw_nic_acquire_dl_device(efhw_nic);

#ifdef EFHW_HAS_AF_XDP
	if ( efhw_nic->devtype.arch == EFHW_ARCH_AF_XDP ) {
		efrm_ethtool_filter_remove(efhw_nic->net_dev, filter_id);
		return;
	}
#endif
	if( efx_dev != NULL ) {
		/* If the filter op fails with ENETDOWN, that indicates that
		 * the hardware is inacessible but that the device has not
		 * (yet) been shut down.  It will be recovered by a subsequent
		 * reset.  In the meantime, the net driver's and Onload's
		 * opinions as to the installed filters will diverge.  We
		 * minimise the damage by preventing further driverlink
		 * activity until the reset happens. */
		unsigned generation = efrm_driverlink_generation(rnic);
		if( efx_dl_filter_remove(efx_dev, filter_id) == -ENETDOWN )
			efrm_driverlink_desist(rnic, generation);
		efhw_nic_release_dl_device(efhw_nic, efx_dev);
	}
	/* If [efx_dev] is NULL, the hardware is morally absent and so there's
	 * nothing to do. */
}
EXPORT_SYMBOL(efrm_filter_remove);


int efrm_filter_redirect(struct efrm_client *client, int filter_id,
			 struct efx_filter_spec *spec)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device *efx_dev = efhw_nic_acquire_dl_device(efhw_nic);
	int stack_id = spec->flags & EFX_FILTER_FLAG_STACK_ID ? spec->stack_id : 0;
	int rc;
	/* If [efx_dev] is NULL, the hardware is morally absent and so there's
	 * nothing to do. */
	if (efx_dev == NULL)
		return -ENODEV;
	if (spec->flags & EFX_FILTER_FLAG_RX_RSS )
		rc = efx_dl_filter_redirect_rss(efx_dev, filter_id, spec->dmaq_id,
						spec->rss_context, stack_id);
	else
		rc = efx_dl_filter_redirect(efx_dev, filter_id, spec->dmaq_id,
					    stack_id);
	efhw_nic_release_dl_device(efhw_nic, efx_dev);
	return rc;
}
EXPORT_SYMBOL(efrm_filter_redirect);


int efrm_filter_block_kernel(struct efrm_client *client, int flags, bool block)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device *efx_dev = efhw_nic_acquire_dl_device(efhw_nic);
	int rc = 0;

	/* If [efx_dev] is NULL, the hardware is morally absent and so there's
	 * nothing to do. This counts as success. */
	if ( efx_dev == NULL )
		return 0;

	if ( block ) {
		if ( flags & EFRM_FILTER_BLOCK_UNICAST ) {
			rc = efx_dl_filter_block_kernel(efx_dev,
					EFX_DL_FILTER_BLOCK_KERNEL_UCAST);
		}
		if ( rc < 0 )
			goto out;
		if ( flags & EFRM_FILTER_BLOCK_MULTICAST ) {
			rc = efx_dl_filter_block_kernel(efx_dev,
					EFX_DL_FILTER_BLOCK_KERNEL_MCAST);
		}
		if ( rc < 0 )
			goto unicast_unblock;
	} else {
		if ( flags & EFRM_FILTER_BLOCK_MULTICAST ) {
			efx_dl_filter_unblock_kernel(efx_dev,
					EFX_DL_FILTER_BLOCK_KERNEL_MCAST);
		}
unicast_unblock:
		if ( flags & EFRM_FILTER_BLOCK_UNICAST ) {
			efx_dl_filter_unblock_kernel(efx_dev,
					EFX_DL_FILTER_BLOCK_KERNEL_UCAST);
		}
	}
out:
	efhw_nic_release_dl_device(efhw_nic, efx_dev);
	return rc;
}
EXPORT_SYMBOL(efrm_filter_block_kernel);

ci_inline void build_tests(void) {
	CI_BUILD_ASSERT(EFRM_RSS_KEY_LEN ==
			MC_CMD_RSS_CONTEXT_SET_KEY_IN_TOEPLITZ_KEY_LEN);
	CI_BUILD_ASSERT(EFRM_RSS_INDIRECTION_TABLE_LEN ==
			MC_CMD_RSS_CONTEXT_SET_TABLE_IN_INDIRECTION_TABLE_LEN);
}

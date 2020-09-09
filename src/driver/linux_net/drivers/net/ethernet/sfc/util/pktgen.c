/* SPDX-License-Identifier: BSD-2-Clause */
/* (c) Copyright 2005-2006 Xilinx, Inc. */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <asm/types.h>
typedef __u16 u16;
#include <linux/mii.h>
#include <linux/if.h>

#define eprintf(...) fprintf ( stderr, __VA_ARGS__ )

int sock;
struct ifreq ifr;
struct mii_ioctl_data *mii = ( struct mii_ioctl_data * ) &ifr.ifr_ifru;

void gmiiphy ( void ) {
	if ( ioctl ( sock, SIOCGMIIPHY, &ifr ) < 0 ) {
		eprintf ( "Could not get PHY address: %m\n" );
		exit ( 1 );
	}
	printf ( "PHY address %d\n", mii->phy_id );	
}

void gmiireg ( void ) {
	if ( ioctl ( sock, SIOCGMIIREG, &ifr ) < 0 ) {
		eprintf ( "Could not read GMII register %d: %m\n",
			  mii->reg_num );
		exit ( 1 );
	}
	printf ( "Read MII reg %d = %04x\n",
		 mii->reg_num, mii->val_out );
}

void smiireg ( void ) {
	printf ( "Writing MII reg %d = %04x\n",
		 mii->reg_num, mii->val_in );
	if ( ioctl ( sock, SIOCSMIIREG, &ifr ) < 0 ) {
		eprintf ( "Could not write GMII register %d: %m\n",
			  mii->reg_num );
		exit ( 1 );
	}
}

int main ( int argc, char **argv ) {
	struct mii_ioctl_data *mii =
		( struct mii_ioctl_data * ) &ifr.ifr_ifru;
	unsigned int len;
	int enable;
	int len_bit = 0;

	if ( argc < 3 ) {
		eprintf ( "Syntax: %s ethX [0|64|1518]\n", argv[0] );
		exit ( 1 );
	}

	memset ( &ifr, 0, sizeof ( ifr ) );
	strncpy ( ifr.ifr_name, argv[1], sizeof ( ifr.ifr_name ) );

	len = strtoul ( argv[2], NULL, 10 );
	switch ( len ) {
	case 0:
		enable = 0;
		break;
	case 64:
		enable = 1;
		len_bit = 0;
		break;
	case 1518:
		enable = 1;
		len_bit = 1;
		break;
	default:
		eprintf ( "Invalid length %s (use 0, 64 or 1518)\n", argv[2] );
		exit ( 1 );
	}

	sock = socket ( PF_INET, SOCK_DGRAM, IPPROTO_IP );
	if ( sock < 0 ) {
		eprintf ( "Could not open socket: %m\n" );
		exit ( 1 );
	}

	gmiiphy();

	/* Select page 18 */
	mii->reg_num = 29;
	gmiireg();
	mii->val_in = ( mii->val_out & ~0x1f ) | 18;
	smiireg();

	/* Get packet generator status */
	mii->reg_num = 30;
	gmiireg();
	mii->val_in = ( mii->val_out & ~0x28 ) |
		( enable << 5 ) | ( len_bit << 3 );
	smiireg();

	close ( sock );

	return 0;
}

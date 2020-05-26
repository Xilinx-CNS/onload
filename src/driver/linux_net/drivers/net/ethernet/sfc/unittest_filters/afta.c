#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>

#include "arb_filter_ioctl.h"

enum action {
	ACTION_NONE = 0,
	ACTION_INSERT,
	ACTION_REINSERT,
	ACTION_REMOVE,
	ACTION_REDIRECT,
	ACTION_BLOCK,
	ACTION_UNBLOCK,
	ACTION_VPORT_ADD,
	ACTION_VPORT_DEL,
};

int dev_open(void)
{
	int fd = open("/dev/sfc_aftm", O_RDWR);

	if (fd < 0)
		perror("open");
	return fd;
}

int addr_lookup(const char *host, int portno, struct sockaddr_storage *dest)
{
	struct addrinfo ai_in, *ai_res;
	char port[6];
	int rc;

	if ((portno < 0) || (portno > 0xffff)) {
		fprintf(stderr, "Bad port number %d, not in [0,65535]\n",
			portno);
		return 2;
	}
	snprintf(port, 6, "%d", portno);
	memset(&ai_in, 0, sizeof(ai_in));
	ai_in.ai_family = AF_UNSPEC;
	ai_in.ai_socktype = SOCK_DGRAM;

	rc = getaddrinfo(host, port, &ai_in, &ai_res);
	if (rc) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
		return 1;
	}
	if (!ai_res) {
		fprintf(stderr, "addr_lookup: got no results\n");
		return 1;
	}
	/* just take the first one (slightly bad) */
	memcpy(dest, ai_res->ai_addr, ai_res->ai_addrlen);
	freeaddrinfo(ai_res);
	return 0;
}

int parse_mac(const char *src, char dest[6])
{
	if (sscanf(src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", dest, dest+1, dest+2,
			dest+3, dest+4, dest+5) != 6) {
		fprintf(stderr, "Failed to parse MAC address '%s'\n", src);
		return 2;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct efx_filter_spec filter_spec; /* for [RE]INSERT */
	enum efx_filter_priority priority = EFX_FILTER_PRI_HINT;
	enum efx_encap_type encap = EFX_ENCAP_TYPE_NONE;
	const char *local_mac_addr = NULL;
	const char *local_ip_host = NULL;
	int local_ip_port;
	int ip_proto = IPPROTO_UDP;
	struct protoent *pent;
	int iins = SFC_AFTM_IOCSINSERT;
	int iblk;
	int rxq_id = 0; /* (also for REDIRECT) */
	struct sfc_aftm_redirect redir;
	int filter_id = 0; /* for REMOVE, REDIRECT */
	enum action act = ACTION_NONE;
	enum {DEF_NONE, DEF_UC, DEF_MC} def = DEF_NONE;
	u16 outer_vlan = EFX_FILTER_VID_UNSPEC;
	enum {OVERRIDE_ETHER_TYPE_ANY = -1};
	int override_ether_type = -2;
	enum {OVERRIDE_IP_PROTO_ANY = -1};
	int override_ip_proto = -2;
	int encap_tni = -1;
	const char *outer_mac_addr = NULL;
	int vport_id = 0;
	struct sfc_aftm_vport_add vport = {
		.vlan = EFX_FILTER_VID_UNSPEC,
	};
	int arg;
	int fd;
	int rc;

	for (arg = 1; arg < argc; arg++) {
		if (!strcmp(argv[arg], "ins")) {
			act = ACTION_INSERT;
		} else if (!strcmp(argv[arg], "re")) {
			act = ACTION_REINSERT;
		} else if (!strcmp(argv[arg], "rm")) {
			act = ACTION_REMOVE;
		} else if (!strcmp(argv[arg], "mv")) {
			act = ACTION_REDIRECT;
		} else if (!strcmp(argv[arg], "block")) {
			act = ACTION_BLOCK;
		} else if (!strcmp(argv[arg], "unblock")) {
			act = ACTION_UNBLOCK;
		} else if (!strcmp(argv[arg], "vport_add")) {
			act = ACTION_VPORT_ADD;
		} else if (!strcmp(argv[arg], "vport_del")) {
			act = ACTION_VPORT_DEL;
		} else if (!strncmp(argv[arg], "--id=", 5)) {
			if (sscanf(argv[arg] + 5, "%x", &filter_id) != 1) {
				fprintf(stderr, "Bad --id %s\n", argv[arg] + 5);
				return 2;
			}
		} else if (!strcmp(argv[arg], "--pri=hint")) {
			priority = EFX_FILTER_PRI_HINT;
		} else if (!strcmp(argv[arg], "--pri=manual")) {
			priority = EFX_FILTER_PRI_MANUAL;
		} else if (!strcmp(argv[arg], "--pri=required")) {
			priority = EFX_FILTER_PRI_REQUIRED;
		} else if (!strncmp(argv[arg], "--rxq=", 6)) {
			if (sscanf(argv[arg] + 6, "%d", &rxq_id) != 1) {
				fprintf(stderr, "Bad --rxq %s\n",
					argv[arg] + 6);
				return 2;
			}
		} else if (!strncmp(argv[arg], "--mac=", 6)) {
			local_mac_addr = argv[arg]+6;
		} else if (!strncmp(argv[arg], "--ip=", 5)) {
			char *addr = argv[arg] + 5;
			char *colon = strrchr(addr, ':');
			if (!colon) {
				fprintf(stderr,
					"Bad --ip, should be host:port\n");
				return 2;
			}
			*colon++ = 0;
			local_ip_host = addr;
			if (sscanf(colon, "%d", &local_ip_port) != 1) {
				fprintf(stderr, "Bad --ip port %s\n", colon);
				return 2;
			}
		} else if (!strncmp(argv[arg], "--ipproto=", 10)) {
			pent = getprotobyname(argv[arg] + 10);
			if (!pent) {
				fprintf(stderr, "Bad --ipproto %s\n",
					argv[arg] + 10);
				return 2;
			}
			ip_proto = pent->p_proto;
		} else if (!strcmp(argv[arg], "--def=uc")) {
			def = DEF_UC;
		} else if (!strcmp(argv[arg], "--def=mc")) {
			def = DEF_MC;
		} else if (!strncmp(argv[arg], "--vlan=", 7)) {
			int vid;
			if (sscanf(argv[arg] + 7, "%d", &vid) != 1) {
				fprintf(stderr, "Bad --vlan VID %s\n", argv[arg] + 7);
				return 2;
			}
			vport.vlan = outer_vlan = vid;
		} else if(!strncmp(argv[arg], "--override-ethertype=", 21)) {
			if (!strcmp(argv[arg] + 21, "any")) {
				override_ether_type = OVERRIDE_ETHER_TYPE_ANY;
			} else if (sscanf(argv[arg] + 21, "%d", &override_ether_type) != 1) {
				fprintf(stderr, "Bad --override-ethertype %s\n",
					argv[arg] + 21);
				return 2;
			}
		} else if(!strncmp(argv[arg], "--override-ipproto=", 19)) {
			if (!strcmp(argv[arg] + 19, "any")) {
				override_ip_proto = OVERRIDE_IP_PROTO_ANY;
			} else if (sscanf(argv[arg] + 19, "%d", &override_ip_proto) != 1) {
				fprintf(stderr, "Bad --override-ipproto %s\n",
					argv[arg] + 19);
				return 2;
			}
		} else if(!strncmp(argv[arg], "--encap=", 8)) {
			if (!strcmp(argv[arg] + 8, "vxlan")) {
				encap = EFX_ENCAP_TYPE_VXLAN;
			} else if (!strcmp(argv[arg] + 8, "nvgre")) {
				encap = EFX_ENCAP_TYPE_NVGRE;
			} else {
				fprintf(stderr, "Bad --encap %s\n", argv[arg] + 8);
				return 2;
			}
		} else if(!strcmp(argv[arg], "--encap-ipv6")) {
			encap |= EFX_ENCAP_FLAG_IPV6;
		} else if(!strncmp(argv[arg], "--tni=", 6)) {
			if (sscanf(argv[arg] + 6, "%d", &encap_tni) != 1) {
				fprintf(stderr, "Bad --tni %s\n", argv[arg] + 6);
				return 2;
			}
		} else if (!strncmp(argv[arg], "--outer-mac=", 12)) {
			outer_mac_addr = argv[arg]+12;
		} else if (!strncmp(argv[arg], "--vport=", 8)) {
			if (sscanf(argv[arg] + 8, "%d", &vport_id) != 1) {
				fprintf(stderr, "Bad --vport %s\n", argv[arg] + 8);
				return 2;
			}
		} else if (!strcmp(argv[arg], "--vlan-restrict")) {
			vport.vlan_restrict = true;
		} else {
			fprintf(stderr, "Unrecognised argument %s\n",
				argv[arg]);
			return 2;
		}
	}
	switch (act) {
	case ACTION_REINSERT:
		iins = SFC_AFTM_IOCSREINSERT;
		/* fallthrough */
	case ACTION_INSERT:
		efx_filter_init_rx(&filter_spec, priority, 0, rxq_id);
		if (local_mac_addr) {
			char addr[6];

			rc = parse_mac(local_mac_addr, addr);
			if (rc)
				return rc;
			rc = efx_filter_set_eth_local(&filter_spec,
						      outer_vlan,
						      (const u8 *)addr);
			if (rc) {
				fprintf(stderr, "Failed to set filter local MAC address: %s\n",
					strerror(-rc));
				return 1;
			}
		}
		if (local_ip_host) {
			struct sockaddr_storage dest;
			struct sockaddr_in *in;
			struct sockaddr_in6 *in6;

			rc = addr_lookup(local_ip_host, local_ip_port, &dest);
			if (rc) {
				fprintf(stderr, "Failed to lookup host/ip\n");
				return 1;
			}
			switch (dest.ss_family) {
			case AF_INET:
				in = (struct sockaddr_in *)&dest;
				rc = efx_filter_set_ipv4_local(&filter_spec, ip_proto,
							       in->sin_addr.s_addr,
							       in->sin_port);
				break;
			case AF_INET6:
				in6 = (struct sockaddr_in6 *)&dest;
				rc = efx_filter_set_ipv6_local(&filter_spec, ip_proto,
							       in6->sin6_addr,
							       in6->sin6_port);
				break;
			default: /* can't happen */
				rc = -EPROTONOSUPPORT;
				fprintf(stderr, "Unhandled address family %u\n",
					dest.ss_family);
			}
			if (rc) {
				fprintf(stderr, "Failed to set filter local IP info: %s\n",
					strerror(-rc));
				return 1;
			}
		}
		switch (def) {
		case DEF_NONE:
			break;
		case DEF_UC:
			rc = efx_filter_set_uc_def(&filter_spec);
			if (rc) {
				fprintf(stderr, "Failed to set uc def: %s\n",
					strerror(-rc));
				return 1;
			}
			break;
		case DEF_MC:
			rc = efx_filter_set_mc_def(&filter_spec);
			if (rc) {
				fprintf(stderr, "Failed to set mc def: %s\n",
					strerror(-rc));
				return 1;
			}
			break;
		default: /* can't happen */
			fprintf(stderr, "Unhandled def %d", def);
			return 1;
		}

		if (override_ether_type == OVERRIDE_ETHER_TYPE_ANY) {
			filter_spec.match_flags &= ~EFX_FILTER_MATCH_ETHER_TYPE;
		} else if (override_ether_type >= 0) {
			filter_spec.match_flags |= EFX_FILTER_MATCH_ETHER_TYPE;
			filter_spec.ether_type = htons(override_ether_type);
		}

		if (override_ip_proto == OVERRIDE_IP_PROTO_ANY) {
			filter_spec.match_flags &= ~EFX_FILTER_MATCH_IP_PROTO;
		} else if (override_ip_proto >= 0) {
			filter_spec.match_flags |= EFX_FILTER_MATCH_IP_PROTO;
			filter_spec.ip_proto = override_ip_proto;
		}

		if (encap != EFX_ENCAP_TYPE_NONE)
			efx_filter_set_encap_type(&filter_spec, encap);

		if (encap_tni != -1)
			efx_filter_set_encap_tni(&filter_spec, encap_tni);

		if (outer_mac_addr) {
			char addr[6];

			rc = parse_mac(outer_mac_addr, addr);
			if (rc)
				return rc;

			efx_filter_set_encap_outer_loc_mac(&filter_spec,
						       (const u8 *) addr);
		}

		if (vport_id)
			efx_filter_set_vport_id(&filter_spec, vport_id);

		fd = dev_open();
		if (fd < 0)
			return 1;
		rc = ioctl(fd, iins, &filter_spec);
		if (rc < 0) {
			perror("ioctl");
			return 1;
		}
		fprintf(stderr, "Filter inserted, id=0x%x\n", rc);
		break;
	case ACTION_REMOVE:
		fd = dev_open();
		if (fd < 0)
			return 1;
		rc = ioctl(fd, SFC_AFTM_IOCSREMOVE, filter_id);
		if (rc < 0) {
			perror("ioctl");
			return 1;
		}
		fprintf(stderr, "Filter removed\n");
		break;
	case ACTION_REDIRECT:
		redir.filter_id = filter_id;
		redir.rxq_id = rxq_id;
		fd = dev_open();
		if (fd < 0)
			return 1;
		rc = ioctl(fd, SFC_AFTM_IOCSREDIRECT, &redir);
		if (rc < 0) {
			perror("ioctl");
			return 1;
		}
		fprintf(stderr, "Filter redirected\n");
		break;
	case ACTION_BLOCK:
	case ACTION_UNBLOCK:
		fd = dev_open();
		if (fd < 0)
			return 1;
		switch (def) {
		case DEF_NONE:
			iblk = SFC_AFTM_IOCSBLOCK;
			break;
		case DEF_UC:
			iblk = SFC_AFTM_IOCSUCBLK;
			break;
		case DEF_MC:
			iblk = SFC_AFTM_IOCSMCBLK;
			break;
		default: /* can't happen */
			fprintf(stderr, "Unhandled def %d\n", def);
			return 1;
		}
		rc = ioctl(fd, iblk, act==ACTION_UNBLOCK?
					  SFC_AFTM_BLOCK_RM:
					  SFC_AFTM_BLOCK_ADD);
		if (rc < 0) {
			perror("ioctl");
			return 1;
		}
		break;
	case ACTION_VPORT_ADD:
		fd = dev_open();
		if (fd < 0)
			return 1;
		rc = ioctl(fd, SFC_AFTM_IOCSVPORT_ADD, &vport);
		if (rc < 0) {
			perror("ioctl");
			return 1;
		}
		fprintf(stderr, "V-port created, user_id=%d\n", rc);
		break;
	case ACTION_VPORT_DEL:
		fd = dev_open();
		if (fd < 0)
			return 1;
		rc = ioctl(fd, SFC_AFTM_IOCSVPORT_DEL, vport_id);
		if (rc < 0) {
			perror("ioctl");
			return 1;
		}
		fprintf(stderr, "V-port destroyed\n");
		break;
	case ACTION_NONE:
		fprintf(stderr,
			"No action specified (use 'ins', 're', 'mv', 'rm', 'block', 'unblock',\n\t'vport_add' or 'vport_del')\n");
		return 2;
	default: /* can't happen */
		fprintf(stderr, "Unhandled act %d\n", act);
		return 2;
	}
	return 0;
}

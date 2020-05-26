#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include "asm_types.h"
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include "../linux_mdio.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#define MDIO_DEVAD_C22 32

static const char* mmd_names[] = {
  [MDIO_MMD_PMAPMD] = "PMA",
  [MDIO_MMD_WIS]    = "WIS",
  [MDIO_MMD_PCS]    = "PCS",
  [MDIO_MMD_PHYXS]  = "PHYXS",
  [MDIO_MMD_DTEXS]  = "DTEXS",
  [MDIO_MMD_TC]     = "TC",
  [MDIO_MMD_AN]     = "AN",
  [MDIO_MMD_C22EXT] = "c22ext",
  /* dummy for clause 22 addressing */
  [MDIO_DEVAD_C22]  = "c22",
};

union ifreq_mii {
  struct ifreq req;
  struct {
    uint8_t pad[offsetof(struct ifreq, ifr_ifru)];
    struct mii_ioctl_data ioc;
  } mii;
};

static int get_mmd(const char* mmd_name) {
  int mmd;
  char* end;

  mmd = strtol(mmd_name, &end, 10);
  if( *end == 0 && mmd > 0 && mmd < 32 )
    return mmd;

  for( mmd = 0; mmd < (sizeof(mmd_names) / sizeof(mmd_names[0])); mmd++) {
    if( mmd_names[mmd] && strcasecmp(mmd_names[mmd], mmd_name) == 0 )
      return mmd;
  }

  eprintf("Invalid MMD id \"%s\"\n", mmd_name);
  exit(1);
}

int main(int argc, char** argv) {
  int fd;
  union ifreq_mii if_req;
  char* colon;
  int read, prt, dev, addr, value = 0;

  if( argc < 4 || argc > 5 ) {
    eprintf("Syntax: %s ethX [<prt>:]<mmd> <address> [value]\n", argv[0]);
    exit(1);
  }

  /* Get options */
  read = (argc == 4);

  colon = strchr(argv[2], ':');
  if( colon ) {
    prt = strtol(argv[2], NULL, 0);
    if( prt < 0 || prt >= 32 ) {
      eprintf("Invalid port \"%s\"\n", argv[2]);
      exit(1);
    }
    dev = get_mmd(colon + 1);
  } else {
    prt = -1; /* auto */
    dev = get_mmd(argv[2]);
  }

  addr = strtol(argv[3], (char**)NULL, 0);

  if( !read )
    value = strtol(argv[4], (char**)NULL, 0);

  fd = socket(AF_INET, SOCK_STREAM, 0); /* arbitrary socket */
  if( fd < 0 ) {
    eprintf("Could not create socket: %m\n");
    exit(1);
  }

  memset(&if_req, 0, sizeof(if_req));
  strncpy(if_req.req.ifr_name, argv[1], IFNAMSIZ);

  if( prt == -1 ) {
    struct ethtool_cmd ecmd = { ETHTOOL_GSET };

    if_req.req.ifr_data = (caddr_t)&ecmd;
    if( ioctl(fd, SIOCETHTOOL, &if_req) < 0 ) {
      eprintf("Failed to get PHY id for \"%s\": %m\n", argv[1]);
      exit(1);
    }
    prt = ecmd.phy_address;
  }

  if_req.mii.ioc.phy_id =
    (dev == MDIO_DEVAD_C22) ? prt : mdio_phy_id_c45(prt, dev);
  if_req.mii.ioc.reg_num = addr;
  if_req.mii.ioc.val_in = value;

  /* Perform the ioctl */
  if( ioctl(fd, read ? SIOCGMIIREG : SIOCSMIIREG, &if_req) < 0 ) {
    eprintf("MDIO failed: %m\n");
    exit(1);
  }

  if( read )
    printf("returned %d 0x%x\n", if_req.mii.ioc.val_out,
           if_req.mii.ioc.val_out );

  close(fd);

  return 0;
}

/* Filter race test app
 *
 * Inserts or removes SECTION_SIZE (or '-l<count>') consecutive MAC filters
 * Outputs the filter ID for those which succeeded, '-' for those which failed.
 * When several copies are run simultaneously, for each filter precisely one
 * process should succeed, and the others should fail
 *
 * In remove mode (--rm), reads in a list of filter IDs, in the output format,
 * from stdin
 *
 * When we succeed in inserting or removing a filter, we sleep for 10ns.  This
 * is to prevent one process getting ahead of the others, and thereby maximise
 * the probability of hitting any race conditions
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>

#include "arb_filter_ioctl.h"

#define SECTION_SIZE	512 /* size of Siena MAC filter table */

struct config {
	bool *succ; /* whether each filter op succeeded */
	int *f_id; /* ID of each inserted filter (-1 means no filter) */
	enum {MODE_INS, MODE_RM} mode;
	enum {TYPE_MAC, TYPE_IPMC} type; /* type of filters to use */
	enum efx_filter_priority prio;
	int fd;
};

void wait_for_top_of_second(void);
int do_insert(struct config *cfg, int i);
void do_remove(struct config *cfg, int i);

int main(int argc, char *argv[])
{
	struct config cfg = {.mode = MODE_INS, .type = TYPE_MAC,
			     .prio = EFX_FILTER_PRI_HINT};
	unsigned int i, l = SECTION_SIZE;
	int arg;

	/* parse arguments */
	for (arg = 1; arg < argc; arg++) {
		if (!strcmp(argv[arg], "--ins")) {
			cfg.mode = MODE_INS;
		} else if (!strcmp(argv[arg], "--rm")) {
			cfg.mode = MODE_RM;
		} else if (!strcmp(argv[arg], "--mac")) {
			cfg.type = TYPE_MAC;
		} else if (!strcmp(argv[arg], "--ipmc")) {
			cfg.type = TYPE_IPMC;
		} else if (!strncmp(argv[arg], "-l", 2)) {
			if (sscanf(argv[arg]+2, "%u", &l) != 1) {
				fprintf(stderr, "Bad -l%s\n", argv[arg]+2);
				return 2;
			}
		} else if (!strcmp(argv[arg], "--prio=hint")) {
			cfg.prio = EFX_FILTER_PRI_HINT;
		} else if (!strcmp(argv[arg], "--prio=manual")) {
			cfg.prio = EFX_FILTER_PRI_MANUAL;
		} else if (!strcmp(argv[arg], "--prio=required")) {
			cfg.prio = EFX_FILTER_PRI_REQUIRED;
		} else {
			fprintf(stderr, "Unrecognised argument '%s'\n", argv[arg]);
			return 2;
		}
	}

	/* allocate memory in cfg */
	cfg.succ = calloc(l, sizeof(bool));
	if (!cfg.succ) {
		perror("calloc");
		return 1;
	}
	cfg.f_id = calloc(l, sizeof(int));
	if(!cfg.f_id) {
		perror("calloc");
		return 1;
	}

	if(cfg.mode == MODE_RM) { /* read in filter IDs */
		char buf[80];

		for (i = 0; i < l; i++) {
			if (!fgets(buf, 80, stdin)) {
				perror("fgets");
				fprintf(stderr, "i == %u\n", i);
				return 1;
			}
			if(buf[0] == '-') {
				cfg.f_id[i] = -1;
			} else if (sscanf(buf, "%d", cfg.f_id+i) != 1) {
				fprintf(stderr, "Bad input line '%s'\n", buf);
				return 1;
			}
		}
	}

	/* open the filter device */
	cfg.fd = open("/dev/sfc_aftm", O_RDWR);
	if (cfg.fd < 0) {
		perror("open");
		return 1;
	}

	wait_for_top_of_second();

	/* perform the specified filter ops */
	if (cfg.mode == MODE_INS) {
		for (i = 0; i < l; i++)
			if (do_insert(&cfg, i))
				return 1;
	} else if (cfg.mode == MODE_RM) {
		for (i = 0; i < l; i++)
			do_remove(&cfg, i);
	}

	/* output results */
	for (i = 0; i < l; i++)
		if (cfg.succ[i])
			printf("%d\n", cfg.f_id[i]);
		else
			printf("-\n");
	close(cfg.fd);
	return 0;
}

void wait_for_top_of_second(void)
{
	struct timeval tv;
	time_t nexts;
	long nanos;

	gettimeofday(&tv, NULL);
	nexts = tv.tv_sec+1;
	while (true) {
		gettimeofday(&tv, NULL);
		if (tv.tv_sec >= nexts)
			return;
		nanos = (1000000 - tv.tv_usec) * 500;
		nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = nanos}, NULL);
	}
}

int do_insert(struct config *cfg, int i)
{
	struct efx_filter_spec filter_spec;
	u8 mac[6] = {2, 0, 0, 0, 0, 0};
	u32 ip;
	int rc;

	efx_filter_init_rx(&filter_spec, cfg->prio, 0, 0);
	switch (cfg->type) {
	case TYPE_MAC:
		/* make the MAC unique */
		mac[3] = i >> 16;
		mac[4] = (i >> 8) & 0xff;
		mac[5] = i & 0xff;
		rc = efx_filter_set_eth_local(&filter_spec, EFX_FILTER_VID_UNSPEC, mac);
		if (rc) {
			fprintf(stderr, "Failed to set filter MAC address: %s\n",
					strerror(-rc));
			return rc;
		}
		break;
	case TYPE_IPMC:
		/* make the IP unique & mcast */
		ip = 0xe0000000 + i;
		rc = efx_filter_set_ipv4_local(&filter_spec, IPPROTO_UDP,
					       htonl(ip), htons(42042));
		if (rc) {
			fprintf(stderr, "Failed to set filter IP address: %s\n",
					strerror(-rc));
			return rc;
		}
		break;
	}
	rc = ioctl(cfg->fd, SFC_AFTM_IOCSINSERT, &filter_spec);
	if (rc < 0) {
		cfg->f_id[i] = -1;
		cfg->succ[i] = false;
	} else {
		cfg->f_id[i] = rc;
		cfg->succ[i] = true;
		/* we won, so sleep 10ns */
		nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 10}, NULL);
	}
	return 0;
}

void do_remove(struct config *cfg, int i)
{
	int rc;

	if (cfg->f_id[i] >= 0) { /* remove the filter */
		rc = ioctl(cfg->fd, SFC_AFTM_IOCSREMOVE, cfg->f_id[i]);
		cfg->succ[i] = (rc == 0);
		if (rc == 0) {
			/* we won, so sleep 10ns */
			nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 10}, NULL);
		}
	} else { /* nothing to remove */
		cfg->succ[i] = false;
	}
}

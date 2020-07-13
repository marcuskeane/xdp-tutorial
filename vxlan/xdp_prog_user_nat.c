/* SPDX-License-Identifier: GPL-2.0 */

static const char *__doc__ = "XDP NAT helper\n"
	" Populates NAT maps\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#include "../common/xdp_stats_kern_user.h"

struct vtep_info {
	__be32 vtep_ip;
	__be32 vx_vni;
	__u8 dest_rmac[ETH_ALEN];
	__u8 src_rmac[ETH_ALEN];
};

struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"nat-laddr", required_argument, NULL, 'l' },
	 "NAT inside local address", "<ipaddr>", true },

	{{"nat-gaddr", required_argument, NULL, 'g' },
	 "NAT inside global address", "<ipaddr>", true },

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};


static int write_nat_entry(int map_fd, unsigned int  *key, unsigned int *value)
{
	if (bpf_map_update_elem(map_fd, key, value, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

/*	printf("forward: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			src[0], src[1], src[2], src[3], src[4], src[5],
			dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]
	      );
*/
	return 0;
}

static int parse_ipstr(const char *ipstr, unsigned int *addr)
{
	if (inet_pton(AF_INET, ipstr, addr) == 1) {
		return AF_INET;
	}

	fprintf(stderr, "%s is an invalid IP\n", ipstr);
	return AF_UNSPEC;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int len;
	int nat_io_map_fd;
	int nat_oi_map_fd;
	char pin_dir[PATH_MAX];
	__u32 nat_laddr;
	__u32 nat_gaddr;

	struct config cfg = {
		.ifindex   = -1,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	if (parse_ipstr(cfg.local_addr, &nat_laddr) != AF_INET) {
		return EXIT_FAIL_OPTION;
	}

	if (parse_ipstr(cfg.global_addr, &nat_gaddr) != AF_INET) {
		return EXIT_FAIL_OPTION;
	}


	/* Open the nat maps corresponding to the cfg.ifname interface */
	nat_io_map_fd = open_bpf_map_file(pin_dir, "nat_inside_out", NULL);
	if (nat_io_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	nat_oi_map_fd = open_bpf_map_file(pin_dir, "nat_outside_in", NULL);
	if (nat_oi_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	printf("map dir: %s\n", pin_dir);

	/* Setup the mapping for nat */
	if (write_nat_entry(nat_io_map_fd, &nat_laddr, &nat_gaddr) < 0) {
		fprintf(stderr, "can't write nat entry\n");
		return 1;
	}

	if (write_nat_entry(nat_oi_map_fd, &nat_gaddr, &nat_laddr) < 0) {
		fprintf(stderr, "can't write nat entry\n");
		return 1;
	}
	return EXIT_OK;
}

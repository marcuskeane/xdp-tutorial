/* SPDX-License-Identifier: GPL-2.0 */

static const char *__doc__ = "XDP vtep helper\n"
	" - Populates vtep  maps\n";

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

	{{"vlan", required_argument, NULL, 't' },
	 "VLAN to lookup", "<vlan>", true },

	{{"lookup-ifindex", required_argument, NULL, 'I' },
	 "Ifindex to use for fib lookup", "<ifindex>", true },

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int parse_u8(char *str, unsigned char *x)
{
	unsigned long z;

	z = strtoul(str, 0, 16);
	if (z > 0xff)
		return -1;

	if (x)
		*x = z;

	return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	if (parse_u8(str, &mac[0]) < 0)
		return -1;
	if (parse_u8(str + 3, &mac[1]) < 0)
		return -1;
	if (parse_u8(str + 6, &mac[2]) < 0)
		return -1;
	if (parse_u8(str + 9, &mac[3]) < 0)
		return -1;
	if (parse_u8(str + 12, &mac[4]) < 0)
		return -1;
	if (parse_u8(str + 15, &mac[5]) < 0)
		return -1;

	return 0;
}

static int write_vlan_map(int map_fd, int vlan, int lookup_ifindex)
{
	if (bpf_map_update_elem(map_fd, vlan, lookup_ifindex, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	printf("new mapping: %d -> %d\n",
			vlan, lookup_ifindex 
	      );

	return 0;
}


#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int len;
	int map_fd;
	char pin_dir[PATH_MAX];

	struct config cfg = {
		.ifindex   = -1,
		.vlan = -1,
		.lookup_ifindex = -1
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	if (cfg.vlan == -1) {
		fprintf(stderr, "ERR: required option --vlan missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	if (cfg.lookup_ifindex == -1) {
		fprintf(stderr, "ERR: required option --lookup-ifindex missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}


	/* Open the tx_port map corresponding to the cfg.ifname interface */
	map_fd = open_bpf_map_file(pin_dir, "vlan_lookup", NULL);
	if (map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	printf("map dir: %s\n", pin_dir);

	/* Setup the mapping of vlan to lookup ifindex */
	if (write_vlan_map(map_fd, src, dest) < 0) {
		fprintf(stderr, "can't write iface params\n");
		return 1;
	}

	return EXIT_OK;
}

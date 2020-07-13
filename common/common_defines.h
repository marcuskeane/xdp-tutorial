#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <net/if.h>
#include <linux/types.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define IP4_SIZE 15

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	char redirect_ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	char src_mac[18];
	char dest_mac[18];
	char *local_addr;
	char local_addr_buf[INET_ADDRSTRLEN];
	char *global_addr;
	char global_addr_buf[INET_ADDRSTRLEN];
	char *vtep_ip;
	char vtep_ip_buf[INET_ADDRSTRLEN];
	int vni;
	int vlan;
	int lookup_ifindex;
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_poll_mode;
};

/* Defined in common_params.o */
extern int verbose;

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#endif /* __COMMON_DEFINES_H */

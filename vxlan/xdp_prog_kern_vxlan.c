/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
//#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>
#include <stdlib.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif


struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") mac_lookup = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = ETH_ALEN,
	.value_size = ETH_ALEN,
	.max_entries = 1,
};


/*static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	return ~((csum & 0xffff) + (csum >> 16));
}
*/

/*
 * The icmp_checksum_diff function takes pointers to old and new structures and
 * the old checksum and returns the new checksum.  It uses the bpf_csum_diff
 * helper to compute the checksum difference. Note that the sizes passed to the
 * bpf_csum_diff helper should be multiples of 4, as it operates on 32-bit
 * words.
 */
/*static __always_inline __u16 icmp_checksum_diff(
		__u16 seed,
		struct icmphdr_common *icmphdr_new,
		struct icmphdr_common *icmphdr_old)
{
	__u32 csum, size = sizeof(struct icmphdr_common);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}
*/

//#define AF_INET 2
//#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}


#define IANA_VXLAN_UDP_PORT     4789
#define MY_VNI 100
#define DEST "10.254.12.2"

#define IP4(a, b, c, d) ((strtol((a), NULL, 10) << 24) | (strtol((b), NULL, 10) << 16) | (strtol((c), NULL, 10) << 8) | strtol((d), NULL, 10))

struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

/*
 * parse_vxlanhdr: parse the vxlan header and return the VNI
 */
static __always_inline int parse_vxlanhdr(struct hdr_cursor *nh,
					void *data_end,
					struct vxlanhdr **vxlanhdr)
{
	int vni;
	struct vxlanhdr *vxh = nh->pos;

	if (vxh + 1 > data_end)
		return -1;

	nh->pos  = vxh + 1;
	*vxlanhdr = vxh;

	vni = (int)vxh->vx_vni;
	return vni;
}


/* Solution to packet03/assignment-4 */
SEC("xdp_sb")
int xdp_sb_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct udphdr *udphdr;
	struct vxlanhdr *vxhdr;
	int rc;
	int action = XDP_PASS;
	int eth_type, ip_type;
	int vni;
	//struct sockaddr_in sa_param;
	//struct in_addr inaddr;
	//char *ip_param = DEST;
	__u32 csum = 0;
	int i;
	__u16 *next_iph_u16;

	int vxlan_offset;

	struct hdr_cursor nh;

	nh.pos = data;
	unsigned char *dst_mac;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		if ((ip_type = parse_iphdr(&nh, data_end, &iphdr)) < 0)
			goto out;
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		if (udphdr->dest != bpf_htons(IANA_VXLAN_UDP_PORT)){
			goto out;
		}
		if (parse_vxlanhdr(&nh, data_end, &vxhdr) < 0){
			goto out;
		}
		vni = bpf_ntohl(vxhdr->vx_vni) >> 8;
		bpf_debug("Debug:vni :0x%x\n", vni);
		bpf_debug("Debug:vni(nbo)  :0x%x\n", vxhdr->vx_vni);
		bpf_debug("Debug:my vni :0x%x\n", MY_VNI);

		if (vni != MY_VNI) {
			goto out;
		}
		eth_type = parse_ethhdr(&nh, data_end, &eth);
		if (eth_type < 0) {
			action = XDP_ABORTED;
			goto out;
		}

		if (eth_type == bpf_htons(ETH_P_IP)) {
			ip_type = parse_iphdr(&nh, data_end, &iphdr);
		} else {
			goto out;
		}
		__be32 ip = bpf_htonl(IP4("10", "254", "12", "2"));
		//if ((rval = inet_pton(AF_INET, "10.254.12.2", &inaddr)) == 0) {
			//
			//goto out;
		//}
		iphdr->daddr = ip;
		bpf_debug("Debug:reset ip\n");
		iphdr->check = 0;

		next_iph_u16 = (__u16 *)iphdr;
		#pragma clang loop unroll(full)
		for (i = 0; i < sizeof(*iphdr) >> 1; i++)
			csum += *next_iph_u16++;

		iphdr->check = ~((csum & 0xffff) + (csum >> 16));

		// pop vxlan header
		vxlan_offset = (int)(sizeof(*eth) + sizeof(*iphdr) + sizeof(*udphdr) + sizeof(*vxhdr));
		if (bpf_xdp_adjust_head(ctx, vxlan_offset)) {
			bpf_debug("Debug:did not adjust\n");
		       goto out;
		}
 		data_end = (void *)(long)ctx->data_end;
		eth = (void *)(long)ctx->data;
		if (eth + 1 > data_end) {
			action = XDP_ABORTED;
			goto out;
		}

		nh.pos = eth;
		
		eth_type = parse_ethhdr(&nh, data_end, &eth);
		bpf_debug("Debug:parsing eth\n");
		if (eth_type < 0) {
			bpf_debug("Debug:parsing eth failed\n");
			action = XDP_ABORTED;
			goto out;
		}
		bpf_debug("Debug:looking up mac\n");
			bpf_debug("Debug: eth->h_dest(1): %x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
			bpf_debug("Debug: eth->h_dest(2): %x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
		dst_mac = bpf_map_lookup_elem(&mac_lookup, eth->h_dest);
		bpf_debug("Debug:looked up mac\n");
		if (!dst_mac)
			goto out;

		if (dst_mac)
			bpf_debug("Debug:found mac\n");
			memcpy(eth->h_dest, dst_mac, ETH_ALEN);
		
		/*if (eth_type == bpf_htons(ETH_P_IP)) {
			ip_type = parse_iphdr(&nh, data_end, &iphdr);
			if (ip_type < 0)
				goto out;
		} else {
			goto out;
		}
		
		if (iphdr->ttl <= 1)
			goto out;
		*/	
		goto out;
		bpf_debug("Debug: iphdr->daddr:0x%x\n", iphdr->daddr);
		bpf_debug("Debug: iphdr->saddr:0x%x\n", iphdr->saddr);

		fib_params.family	= AF_INET;
		fib_params.tos		= iphdr->tos;
		fib_params.l4_protocol	= iphdr->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iphdr->tot_len);
		fib_params.ipv4_src	= iphdr->saddr;
		fib_params.ipv4_dst	= iphdr->daddr;
		
		//bpf_debug("Debug: ctx->ingress_ifindex: 0x%x\n", ctx->ingress_ifindex);
		fib_params.ifindex = ctx->ingress_ifindex;

		rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		switch (rc) {
		case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
			if (eth_type == bpf_htons(ETH_P_IP))
				ip_decrease_ttl(iphdr);


			bpf_debug("Debug: fib_params.ifindex: 0x%x\n", fib_params.ifindex);

			bpf_debug("Debug: eth->h_dest(1): %x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
			bpf_debug("Debug: eth->h_dest(2): %x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

			bpf_debug("Debug: eth->h_source(1): %x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
			bpf_debug("Debug: eth->h_source(2): %x:%x:%x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);


			bpf_debug("Debug: h_vlan_proto: %x\n", fib_params.h_vlan_proto);
			bpf_debug("Debug: h_vlan_TCI: %x\n", fib_params.h_vlan_TCI);

			//action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);

			//if (vlan_tag_push(ctx, eth, 10) < 0) {
			//	goto out;
			//}
			
			break;

		case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
		case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
		case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
			action = XDP_DROP;
			break;
		case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
		case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
		case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
			/* PASS */
			break;
		}
		
		
	} else {
		goto out;
	}



out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

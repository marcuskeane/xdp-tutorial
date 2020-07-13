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

#define IANA_VXLAN_UDP_PORT     4789
#define MY_VNI 200
#define DEST "10.254.12.2"

#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#define VLAN_MAX_DEPTH 4


#define IP4(a, b, c, d) (bpf_htonl((strtol((a), NULL, 10) << 24) | (strtol((b), NULL, 10) << 16) | (strtol((c), NULL, 10) << 8) | strtol((d), NULL, 10)))

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

struct bpf_map_def SEC("maps") nat_inside_out = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 5,
};

struct bpf_map_def SEC("maps") nat_outside_in = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 5,
};

struct bpf_map_def SEC("maps") vtep_lookup = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct vtep_info),
	.max_entries = 1,
};

/* Based on parse_ethhdr() 
 * returns vlan id.
 * 0 for no vlan
 * -1 on failue
 */




/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}


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


/* SB */
SEC("xdp_sb")
int xdp_sb_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	//struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct udphdr *udphdr;
	struct vxlanhdr *vxhdr;
	//int rc;
	int action = XDP_PASS;
	int eth_type, ip_type;
	int vni;
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

	if (eth_type != bpf_htons(ETH_P_IP)) 
		goto out;
	if ((ip_type = parse_iphdr(&nh, data_end, &iphdr)) < 0)
		goto out;

	if (ip_type != IPPROTO_UDP) 
		goto out;

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
		bpf_debug("Debug: not my vni\n");
		goto out;
	}
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	bpf_debug("Debug: eth_type :0x%x\n", eth_type);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type != bpf_htons(ETH_P_IP)) 
		goto out;
	ip_type = parse_iphdr(&nh, data_end, &iphdr);
		
	__be32 ip = IP4("10", "254", "12", "2");
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
		



out:
	return xdp_stats_record_action(ctx, action);
}


#define MY_VLAN 10
#define REMOTE_VNI 200

/* NB */
SEC("xdp_nb")
int xdp_nb_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth;
	//struct vlan_hdr *vlh;
	struct iphdr *iphdr;
	struct udphdr *udphdr;
	struct vxlanhdr *vxhdr;
	//int rc;
	int action = XDP_PASS;
	int eth_type, ip_type;
	//
	//__u16 vlan;
	__u16 payload_len;
	struct ethhdr eth_cpy;


	__be32 inside_addr = IP4("10", "254", "12", "2");
	__be32 outside_addr = IP4("10", "20", "20", "2");
	__be32 remote_vtep = IP4("192", "168", "90", "3");
	__be32 save_source;
	//__be32 local_vtep  = IP4("10", "200", "23", "2");
	__be32 remote_ip = IP4("10", "254", "34", "3");
	__u16 vni = 200;
	char local_rmac[] = {0x52, 0x30, 0x94, 0x00, 0xaa, 0x3e};
	//char remote_rmac[] = {0x82, 0x74, 0x9e, 0xbc, 0x73, 0x8f};
	char remote_rmac[] = {0x82, 0x5d, 0xdf, 0xe5, 0x43, 0xbf};


	__u32 csum = 0;;
	int i;
	int rc;
	__u64 nh_off;

	__u16 *next_iph_u16;

	struct hdr_cursor nh;

	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	bpf_debug("Debug: %0x\n", eth_type);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}
	if (eth + 1 > data_end)
		goto out;

	/* First copy the original Ethernet header */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	iphdr = nh.pos;
	if (iphdr + 1 > data_end)
		goto out;

	if (eth_type != bpf_htons(ETH_P_IP))
		goto out;

	if ((ip_type = parse_iphdr(&nh, data_end, &iphdr)) < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (iphdr->saddr != inside_addr || iphdr->daddr != remote_ip)
		goto out;


	bpf_debug("Debug: resetting ip\n");
	save_source = iphdr->saddr;
	iphdr->saddr = outside_addr;
	payload_len = ntohs(iphdr->tot_len);
	iphdr->check = 0;

	next_iph_u16 = (__u16 *)iphdr;
	#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(*iphdr) >> 1; i++)
		csum += *next_iph_u16++;
	iphdr->check = ~((csum & 0xffff) + (csum >> 16));

	fib_params.family	= AF_INET;
	fib_params.tos		= iphdr->tos;
	fib_params.l4_protocol	= iphdr->protocol;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.tot_len	= bpf_ntohs(iphdr->tot_len);
	fib_params.ipv4_src	= iphdr->saddr;
	fib_params.ipv4_dst	= remote_vtep;
	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	bpf_debug("Debug: rc: 0x%x\n", rc);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		if (eth_type == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iphdr);

		if (bpf_xdp_adjust_head(ctx, 0 - ((int)sizeof(*eth) + (int)sizeof(*iphdr) + (int)sizeof(*udphdr) + (int)sizeof(*vxhdr))))
			return -1;
		data_end = (void *)(long)ctx->data_end;
		eth = (void *)(long)ctx->data;
		nh.pos = eth;

		if (eth + 1 > data_end)
			return -1;

		__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

		nh_off = sizeof(*eth);
		nh.pos += nh_off;

		iphdr = nh.pos;
		if (iphdr + 1 > data_end)
			goto out;

		iphdr->version = 4;
		iphdr->ihl = sizeof(*iphdr) >> 2;
		iphdr->frag_off =	0;
		iphdr->protocol = IPPROTO_UDP;
		iphdr->check = 0;
		csum = 0;
		iphdr->tos = 0;
		iphdr->tot_len = htons(payload_len + sizeof(*iphdr) + sizeof(*udphdr) + sizeof(*vxhdr) + sizeof(*eth));
		iphdr->daddr = remote_vtep;
		iphdr->saddr = save_source;
		iphdr->ttl = 8;

		next_iph_u16 = (__u16 *)iphdr;
		#pragma clang loop unroll(full)
		for (i = 0; i < sizeof(*iphdr) >> 1; i++)
			csum += *next_iph_u16++;
		iphdr->check = ~((csum & 0xffff) + (csum >> 16));

		nh_off = sizeof(*iphdr);
		nh.pos += nh_off;

		udphdr = nh.pos;
		if (udphdr + 1 > data_end)
			goto out;

		udphdr->source = bpf_htons(5555);
		udphdr->dest = bpf_htons(IANA_VXLAN_UDP_PORT);
		udphdr->check = 0;
		udphdr->len = bpf_htons(sizeof(*udphdr) +sizeof(*vxhdr) + sizeof(*eth) + payload_len) ;

		nh_off = sizeof(*udphdr);
		nh.pos += nh_off;
		vxhdr = nh.pos;
		if (vxhdr + 1 > data_end)
			goto out;
		
		vxhdr->vx_flags = bpf_htonl(0x8 << 24);
		vxhdr->vx_vni = bpf_htonl(vni << 8);
		
		nh_off = sizeof(*vxhdr);
		nh.pos += nh_off;
		eth = nh.pos;
		if (eth + 1 > data_end)
			goto out;


		memcpy(eth->h_dest, remote_rmac, ETH_ALEN);
		memcpy(eth->h_source, local_rmac, ETH_ALEN);
		bpf_debug("Debug: fib_params.dmac(1): %x:%x:%x\n", fib_params.dmac[0], fib_params.dmac[1], fib_params.dmac[2]);
		bpf_debug("Debug: fib_params.dmac(2): %x:%x:%x\n", fib_params.dmac[3], fib_params.dmac[4], fib_params.dmac[5]);
		bpf_debug("Debug: fib_params.smac(1): %x:%x:%x\n", fib_params.smac[0], fib_params.smac[1], fib_params.smac[2]);
		bpf_debug("Debug: fib_params.smac(2): %x:%x:%x\n", fib_params.smac[3], fib_params.smac[4], fib_params.smac[5]);
		bpf_debug("Debug: fib_params.ipv4_dst: 0x%x\n", bpf_ntohl(fib_params.ipv4_dst));
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
		bpf_debug("Debug: not forwarded\n");
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
		bpf_debug("Debug: forwarding disabled\n");
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
		bpf_debug("Debug: no neigh\n");
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		/* PASS */
		break;
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

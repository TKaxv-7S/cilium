/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "lib/common.h"
#include "lib/eps.h"
#include "lib/ipv4.h"
#include "lib/identity.h"

static __always_inline void
set_decrypt_mark(struct __ctx_buff *ctx, __u16 node_id)
{
	/* Decrypt "key" is determined by SPI and originating node */
	ctx->mark = MARK_MAGIC_DECRYPT | node_id << 16;
}

#ifdef ENCRYPTION_STRICT_MODE_EGRESS
/* strict_allow checks whether the packet is allowed to pass through the strict mode. */
static __always_inline bool
strict_allow(struct __ctx_buff *ctx, __be16 proto) {
	const struct remote_endpoint_info __maybe_unused *dest_info;
	bool __maybe_unused in_strict_cidr = false;
	struct iphdr __maybe_unused *ip4;
	void *data, *data_end;

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return true;

		/* Allow traffic that is sent from the node:
		 * (1) When encapsulation is used and the destination is a remote pod.
		 * (2) When the destination is a remote-node.
		 */
		if (ip4->saddr == IPV4_GATEWAY || ip4->saddr == IPV4_ENCRYPT_IFACE)
			return true;

		in_strict_cidr = ipv4_is_in_subnet(ip4->daddr,
						   STRICT_IPV4_NET,
						   STRICT_IPV4_NET_SIZE);
		in_strict_cidr &= ipv4_is_in_subnet(ip4->saddr,
						    STRICT_IPV4_NET,
						    STRICT_IPV4_NET_SIZE);

#if defined(TUNNEL_MODE) || defined(STRICT_IPV4_OVERLAPPING_CIDR)
		/* Allow pod to remote-node communication */
		dest_info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (dest_info && identity_is_remote_node(dest_info->sec_identity))
			return true;
#endif /* TUNNEL_MODE || STRICT_IPV4_OVERLAPPING_CIDR */
		return !in_strict_cidr;
#endif /* ENABLE_IPV4 */
	default:
		return true;
	}
}
#endif /* ENCRYPTION_STRICT_MODE_EGRESS */

/* strict_ingress_drop checks whether a packet must be dropped by strict
 * ingress encryption enforcement. It returns true for cluster-internal pod
 * traffic that reached a local pod without going through the WireGuard decrypt
 * path. Legitimate decrypted traffic is delivered directly from
 * bpf_wireguard.c (BPF host routing) or returns to the stack with
 * MARK_MAGIC_DECRYPT set, neither of which re-enters bpf_host from a netdev.
 *
 * Callers are responsible for gating this on ENABLE_WIREGUARD and the
 * encryption_strict_ingress / enable_identity_mark configuration.
 */
static __always_inline bool
strict_ingress_drop(struct __ctx_buff *ctx, __u32 secctx, bool from_host,
		    const struct endpoint_info *ep)
{
	/* Traffic that entered from the local host stack is fine. */
	if (from_host)
		return false;

	/* Already-decrypted traffic is fine. */
	if (ctx_is_decrypt(ctx))
		return false;

	/* Only enforce on cluster-internal traffic. */
	if (!identity_is_cluster(secctx))
		return false;

	/* Traffic from a remote node is not pod traffic. */
	if (identity_is_remote_node(secctx))
		return false;

	/* Traffic with a host source identity is not pod traffic. Unlike the
	 * from_host check above, this matches on the source identity regardless
	 * of which path the packet entered through.
	 */
	if (identity_is_host(secctx))
		return false;

	/* Only enforce on delivery to a local pod: skip traffic not destined for
	 * a local endpoint, or destined for the local host.
	 */
	if (!ep || (ep->flags & ENDPOINT_MASK_HOST_DELIVERY))
		return false;

	return true;
}

/* checks whether the source endpoint matches the encryption policy */
static __always_inline bool
encrypt_src_matches_policy(__u32 src_sec_identity) {
#ifndef ENABLE_NODE_ENCRYPTION
	/* Unless node encryption is enabled, we don't want to encrypt
	 * traffic from the hostns.
	 *
	 * NB: if iptables has SNAT-ed the packet, its sec id is HOST_ID.
	 * This means that the packet won't be encrypted. This is fine,
	 * as with --encrypt-node=false we encrypt only pod-to-pod packets.
	 */
	if (src_sec_identity == HOST_ID)
		return false;
#endif /* !ENABLE_NODE_ENCRYPTION */

	/* We don't want to encrypt any traffic that originates from outside
	 * the cluster. This check excludes DSR traffic from the LB node to a remote backend.
	 */
	if (!identity_is_cluster(src_sec_identity))
		return false;

	/* If source is remote node we should treat it like outside traffic.
	 * This is possible when connection is done from pod to load balancer with DSR enabled.
	 */
	if (identity_is_remote_node(src_sec_identity))
		return false;

	return true;
}

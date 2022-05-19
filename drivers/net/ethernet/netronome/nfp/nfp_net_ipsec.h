/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2018 Netronome Systems, Inc */
/* Copyright (C) 2021 Corigine, Inc */

#ifndef __NFP_NET_IPSEC_H__
#define __NFP_NET_IPSEC_H__
#include <net/xfrm.h>

struct nfp_ipsec_offload {
	u32 seq_hi;
	u32 seq_low;
	u32 handle;
};

#ifndef CONFIG_NFP_APP_IPSEC
static inline int nfp_net_ipsec_init(struct nfp_net *nn)
{
	return 0;
}

static inline void nfp_net_ipsec_free(struct nfp_net *nn)
{
}

static inline bool nfp_net_ipsec_tx_prep(struct sk_buff *skb,
					 struct xfrm_offload *xo,
					 struct xfrm_state *x)
{
	return false;
}

static inline int nfp_net_ipsec_rx(struct nfp_net_rx_desc *rxd,
				   struct nfp_meta_parsed *meta,
				   struct sk_buff *skb)
{
	return 0;
}
#else
int nfp_net_ipsec_init(struct nfp_net *nn);
void nfp_net_ipsec_free(struct nfp_net *nn);
bool nfp_net_ipsec_tx_prep(struct sk_buff *skb, struct nfp_ipsec_offload *offload_info);
int nfp_net_ipsec_rx(struct nfp_net_rx_desc *rxd,
		     struct nfp_meta_parsed *meta,
		     struct sk_buff *skb);
#endif

#endif /* __NFP_NET_IPSEC_H__ */

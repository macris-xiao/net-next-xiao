// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2018 Netronome Systems, Inc */
/* Copyright (C) 2021 Corigine, Inc */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <asm/unaligned.h>
#include <linux/ktime.h>
#include <net/xfrm.h>

#include "nfp_net_ctrl.h"
#include "nfp_net.h"
#include "nfp_net_ipsec.h"

#define NFP_NET_IPSEC_MAX_SA_CNT (16 * 1024)
#define OFFLOAD_HANDLE_ERROR 0xffffffff

/* IPSEC_CFG_MSSG_ADD_SA */
struct nfp_ipsec_cfg_add_sa {
	u32 ciph_key[8];    /* Cipher Key */
	union {
		u32 auth_key[16];   /* Authentication Key */
		struct nfp_ipsec_aesgcm {  /* AES-GCM-ESP fields */
			u32 salt;     /* initialized with sa */
			u32 iv[2];    /* firmware use only */
			u32 cntr;
			u32 zeros[4]; /* init to 0 with sa */
			u32 len_a[2]; /* firmware use only */
			u32 len_c[2];
			u32 spare0[4];
		} aesgcm_fields;
	};
	struct sa_ctrl_word {
		uint32_t hash   :4;  /* From nfp_ipsec_sa_hash_type */
		uint32_t cimode :4;  /* From nfp_ipsec_sa_cipher_mode */
		uint32_t cipher :4;  /* From nfp_ipsec_sa_cipher */
		uint32_t mode   :2;  /* From nfp_ipsec_sa_mode */
		uint32_t proto  :2;  /* From nfp_ipsec_sa_prot */
		uint32_t dir :1;     /* Sa direction */
		uint32_t ena_arw:1;  /* Anti-Replay Window */
		uint32_t ext_seq:1;  /* 64-bit Sequence Num */
		uint32_t ext_arw:1;  /* 64b Anti-Replay Window */
		uint32_t spare2 :9;  /* Must be set to 0 */
		uint32_t encap_dsbl:1;/* Encap/decap disable */
		uint32_t gen_seq:1;  /* Firmware Generate Seq */
		uint32_t spare8 :1;  /* Must be set to 0 */
	} ctrl_word;
	u32 spi; /* SPI Value */
	uint32_t pmtu_limit :16;  /* PMTU Limit */
	uint32_t spare3     :1;
	uint32_t frag_check :1;  /* Stateful fragment checking flag */
	uint32_t bypass_DSCP:1;  /* Bypass DSCP Flag */
	uint32_t df_ctrl    :2;  /* DF Control bits */
	uint32_t ipv6       :1;  /* Outbound IPv6 addr format */
	uint32_t udp_enable :1;  /* Add/Remove UDP header for NAT */
	uint32_t tfc_enable :1;  /* Traffic Flow Confidentiality */
	uint32_t spare4	 :8;
	u32 soft_lifetime_byte_count;
	u32 hard_lifetime_byte_count;
	u32 src_ip[4]; /* Src IP addr */
	u32 dst_ip[4]; /* Dst IP addr */
	uint32_t natt_dst_port :16; /* NAT-T UDP Header dst port */
	uint32_t natt_src_port :16; /* NAT-T UDP Header src port */
	u32 soft_lifetime_time_limit;
	u32 hard_lifetime_time_limit;
	u32 sa_creation_time_lo_32; /* ucode fills this in */
	u32 sa_creation_time_hi_32; /* ucode fills this in */
	uint32_t reserved0   :16;
	uint32_t tfc_padding :16; /* Traffic Flow Confidential Pad */
};

struct nfp_net_ipsec_sa_data {
	struct nfp_ipsec_cfg_add_sa nfp_sa;
	struct xfrm_state *x;
	int invalidated;
};

struct nfp_net_ipsec_data {
	struct nfp_net_ipsec_sa_data sa_entries[NFP_NET_IPSEC_MAX_SA_CNT];
	unsigned int sa_free_stack[NFP_NET_IPSEC_MAX_SA_CNT];
	unsigned int sa_free_cnt;
	struct mutex lock;	/* protects nfp_net_ipsec_data struct */
};

static int nfp_net_xfrm_add_state(struct xfrm_state *x)
{
	return -EOPNOTSUPP;
}

static void nfp_net_xfrm_del_state(struct xfrm_state *x)
{
}

static void nfp_net_xfrm_free_state(struct xfrm_state *x)
{
}

static bool nfp_net_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	/* TBD test for unsupport offloads */
	return true;
}

static const struct xfrmdev_ops nfp_net_ipsec_xfrmdev_ops = {
	.xdo_dev_state_add = nfp_net_xfrm_add_state,
	.xdo_dev_state_delete = nfp_net_xfrm_del_state,
	.xdo_dev_state_free = nfp_net_xfrm_free_state,
	.xdo_dev_offload_ok = nfp_net_ipsec_offload_ok,
};

int nfp_net_ipsec_init(struct nfp_net *nn)
{
	if (nn->dp.netdev) {
		struct nfp_net_ipsec_data *ipd;
		int i;

		nn->dp.netdev->xfrmdev_ops = &nfp_net_ipsec_xfrmdev_ops;
		ipd = kzalloc(sizeof(*ipd), GFP_KERNEL);
		if (!ipd)
			return -ENOMEM;

		for (i = 0; i < NFP_NET_IPSEC_MAX_SA_CNT; i++)
			ipd->sa_free_stack[i] = NFP_NET_IPSEC_MAX_SA_CNT - i - 1;

		ipd->sa_free_cnt = NFP_NET_IPSEC_MAX_SA_CNT;
		mutex_init(&ipd->lock);
		nn->ipsec_data = ipd;
	}

	return 0;
}

void nfp_net_ipsec_free(struct nfp_net *nn)
{
	if (!nn->ipsec_data)
		return;

	mutex_destroy(&nn->ipsec_data->lock);
	kfree(nn->ipsec_data);
	nn->ipsec_data = NULL;
}

bool nfp_net_ipsec_tx_prep(struct sk_buff *skb, struct nfp_ipsec_offload *offload_info)
{
	struct xfrm_offload *_xo = xfrm_offload(skb);
	struct xfrm_state *_x;

	if (!_xo)
		return false;

	_x = xfrm_input_state(skb);
	if (!_x)
		return false;

	if (_x->xso.offload_handle == OFFLOAD_HANDLE_ERROR) {
		pr_warn_ratelimited("Invalid xfrm offload handle\n");
		return false;
	}
	offload_info->seq_hi = _xo->seq.hi;
	offload_info->seq_low = _xo->seq.low;
	offload_info->handle = _x->xso.offload_handle;
	return true;
}

int nfp_net_ipsec_rx(struct nfp_net_rx_desc *rxd,
		     struct nfp_meta_parsed *meta,
		     struct sk_buff *skb)
{
	struct nfp_net_ipsec_sa_data *sa_data;
	struct net_device *netdev = skb->dev;
	struct nfp_net_ipsec_data *ipd;
	struct xfrm_offload *xo;
	struct xfrm_state *x;
	struct sec_path *sp;
	struct nfp_net *nn;
	int saidx;

	nn = netdev_priv(netdev);
	ipd = nn->ipsec_data;

	if (meta->ipsec_saidx == 0)
		return 0; /* no offload took place */

	saidx = meta->ipsec_saidx - 1;
	if (saidx > NFP_NET_IPSEC_MAX_SA_CNT || saidx < 0) {
		pr_warn_ratelimited("Invalid SAIDX from NIC (%d)\n", saidx);
		return -1;
	}

	sa_data = &ipd->sa_entries[saidx];
	if (!sa_data->x) {
		pr_warn_ratelimited("Unused SAIDX from NIC (%d)\n", saidx);
		return -1;
	}

	x = sa_data->x;
	xfrm_state_hold(x);
	sp = secpath_set(skb);
	if (unlikely(!sp)) {
		pr_warn_ratelimited("Failed to alloc secpath for RX offload\n");
		return -1;
	}

	sp->xvec[sp->len++] = x;
	sp->olen++;
	xo = xfrm_offload(skb);
	xo->flags = CRYPTO_DONE;
	xo->status = CRYPTO_SUCCESS;
	return 0;
}

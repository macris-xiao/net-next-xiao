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

/* IPsec config message cmd codes */
enum nfp_ipsec_cfg_mssg_cmd_codes {
	NFP_IPSEC_CFG_MSSG_ADD_SA,	 /* add a new SA */
	NFP_IPSEC_CFG_MSSG_INV_SA,	 /* invalidate an existing SA */
	NFP_IPSEC_CFG_MSSG_MODIFY_SA,	 /* modify an existing SA */
	NFP_IPSEC_CFG_MSSG_GET_SA_STATS, /* report SA counters, flags, etc. */
	NFP_IPSEC_CFG_MSSG_GET_SEQ_NUMS, /* allocate sequence numbers */
	NFP_IPSEC_CFG_MSSG_LAST
};

/* IPsec config message response codes */
enum nfp_ipsec_cfg_mssg_rsp_codes {
	NFP_IPSEC_CFG_MSSG_OK,
	NFP_IPSEC_CFG_MSSG_FAILED,
	NFP_IPSEC_CFG_MSSG_SA_VALID,
	NFP_IPSEC_CFG_MSSG_SA_HASH_ADD_FAILED,
	NFP_IPSEC_CFG_MSSG_SA_HASH_DEL_FAILED,
	NFP_IPSEC_CFG_MSSG_SA_INVALID_CMD
};

/* Protocol */
enum nfp_ipsec_sa_prot {
	NFP_IPSEC_PROTOCOL_AH = 0,
	NFP_IPSEC_PROTOCOL_ESP = 1
};

/* Mode */
enum nfp_ipsec_sa_mode {
	NFP_IPSEC_PROTMODE_TRANSPORT = 0,
	NFP_IPSEC_PROTMODE_TUNNEL = 1
};

/* Cipher types */
enum nfp_ipsec_sa_cipher {
	NFP_IPSEC_CIPHER_NULL,
	NFP_IPSEC_CIPHER_3DES,
	NFP_IPSEC_CIPHER_AES128,
	NFP_IPSEC_CIPHER_AES192,
	NFP_IPSEC_CIPHER_AES256,
	NFP_IPSEC_CIPHER_AES128_NULL,
	NFP_IPSEC_CIPHER_AES192_NULL,
	NFP_IPSEC_CIPHER_AES256_NULL,
	NFP_IPSEC_CIPHER_CHACHA20
};

/* Cipher modes */
enum nfp_ipsec_sa_cipher_mode {
	NFP_IPSEC_CIMODE_ECB,
	NFP_IPSEC_CIMODE_CBC,
	NFP_IPSEC_CIMODE_CFB,
	NFP_IPSEC_CIMODE_OFB,
	NFP_IPSEC_CIMODE_CTR
};

/* Hash types */
enum nfp_ipsec_sa_hash_type {
	NFP_IPSEC_HASH_NONE,
	NFP_IPSEC_HASH_MD5_96,
	NFP_IPSEC_HASH_SHA1_96,
	NFP_IPSEC_HASH_SHA256_96,
	NFP_IPSEC_HASH_SHA384_96,
	NFP_IPSEC_HASH_SHA512_96,
	NFP_IPSEC_HASH_MD5_128,
	NFP_IPSEC_HASH_SHA1_80,
	NFP_IPSEC_HASH_SHA256_128,
	NFP_IPSEC_HASH_SHA384_192,
	NFP_IPSEC_HASH_SHA512_256,
	NFP_IPSEC_HASH_GF128_128,
	NFP_IPSEC_HASH_POLY1305_128
};

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

/* IPSEC_CFG_MSSG_INV_SA */
struct nfp_ipsec_cfg_inv_sa {
	u32 spare6;
};

/* IPSEC_CFG_MSSG_GET_SA_STATS */
struct nfp_ipsec_cfg_get_sa_stats {
	u32 seq_lo; /* Sequence Number (low 32bits) */
	u32 seq_high; /* Sequence Number (high 32bits)*/
	u32 arw_counter_lo;  /* Anti-replay wndw cntr */
	u32 arw_counter_high;/* Anti-replay wndw cntr */
	u32 arw_bitmap_lo;   /* Anti-replay wndw bitmap */
	u32 arw_bitmap_high; /* Anti-replay wndw bitmap */
	uint32_t reserved1:1;
	uint32_t soft_lifetime_byte_cnt_exceeded :1; /* Soft cnt_exceeded */
	uint32_t hard_lifetime_byte_cnt_exceeded :1; /* Hard cnt_exceeded */
	uint32_t soft_lifetime_time_limit_exceeded :1; /* Soft cnt_exceeded */
	uint32_t hard_lifetime_time_limit_exceeded :1; /* Hard cnt_exceeded */
	uint32_t spare7:27;
	u32 lifetime_byte_count;
	u32 pkt_count;
	u32 discards_auth; /* Auth failures */
	u32 discards_unsupported; /* Unsupported crypto mode */
	u32 discards_alignment; /* Alignment error */
	u32 discards_hard_bytelimit; /* Byte Count limit */
	u32 discards_seq_num_wrap; /* Sequ Number wrap */
	u32 discards_pmtu_limit_exceeded; /* PMTU Limit */
	u32 discards_arw_old_seq; /* Anti-Replay seq small */
	u32 discards_arw_replay; /* Anti-Replay seq rcvd */
	u32 discards_ctrl_word; /* Bad SA Control word */
	u32 discards_ip_hdr_len; /* Hdr offset from too high */
	u32 discards_eop_buf; /* No EOP buffer */
	u32 ipv4_id_counter; /* IPv4 ID field counter */
	u32 discards_isl_fail; /* Inbound SPD Lookup failure */
	u32 discards_ext_not_found; /* Ext header end */
	u32 discards_max_ext_hdrs; /* Max ext header */
	u32 discards_non_ext_hdrs; /* Non-extension headers */
	u32 discards_ext_hdr_too_big; /* Ext header chain */
	u32 discards_hard_timelimit; /* Time Limit */
};

/* IPSEC_CFG_MSSG_GET_SEQ_NUMS */
struct ipsec_cfg_get_seq_nums {
	u32 seq_nums; /* # sequence numbers to allocate */
	u32 seq_num_low; /* rtrn start seq num 31:00 */
	u32 seq_num_hi;  /* rtrn start seq num 63:32 */
};

/* IPSEC_CFG_MSSG */
struct nfp_ipsec_cfg_mssg {
	union {
		struct{
			uint32_t cmd:16;     /* One of nfp_ipsec_cfg_mssg_cmd_codes */
			uint32_t rsp:16;     /* One of nfp_ipsec_cfg_mssg_rsp_codes */
			uint32_t sa_idx:16;  /* SA table index */
			uint32_t spare0:16;
			union {
				struct nfp_ipsec_cfg_add_sa cfg_add_sa;
				struct nfp_ipsec_cfg_inv_sa cfg_inv_sa;
				struct nfp_ipsec_cfg_get_sa_stats cfg_get_stats;
				struct ipsec_cfg_get_seq_nums cfg_get_seq_nums;
			};
		};
		u32 raw[64];
	};
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

static int nfp_ipsec_cfg_cmd_issue(struct nfp_net *nn, int type, int saidx,
				   struct nfp_ipsec_cfg_mssg *msg)
{
	int i, msg_size, ret;

	msg->cmd = type;
	msg->sa_idx = saidx;
	msg->rsp = 0;
	msg_size = ARRAY_SIZE(msg->raw);

	for (i = 0; i < msg_size; i++)
		nn_writel(nn, NFP_NET_CFG_MBOX_VAL + 4 * i, msg->raw[i]);

	ret = nfp_net_mbox_reconfig(nn, NFP_NET_CFG_MBOX_CMD_IPSEC);
	if (ret < 0)
		return ret;

	/* for now we always read the whole message response back */
	for (i = 0; i < msg_size; i++)
		msg->raw[i] = nn_readl(nn, NFP_NET_CFG_MBOX_VAL + 4 * i);

	switch (msg->rsp) {
	case NFP_IPSEC_CFG_MSSG_OK:
		return 0;
	case NFP_IPSEC_CFG_MSSG_SA_INVALID_CMD:
		return -EINVAL;
	case NFP_IPSEC_CFG_MSSG_SA_VALID:
		return -EEXIST;
	case NFP_IPSEC_CFG_MSSG_FAILED:
	case NFP_IPSEC_CFG_MSSG_SA_HASH_ADD_FAILED:
	case NFP_IPSEC_CFG_MSSG_SA_HASH_DEL_FAILED:
		return -EIO;
	default:
		return -EDOM;
	}
}

static int set_aes_keylen(struct nfp_ipsec_cfg_add_sa *cfg, int alg, int keylen)
{
	if (alg == SADB_X_EALG_NULL_AES_GMAC) {
		if (keylen == 128)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES128_NULL;
		else if (keylen == 192)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES192_NULL;
		else if (keylen == 256)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES256_NULL;
		else
			return -1;
	} else {
		if (keylen == 128)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES128;
		else if (keylen == 192)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES192;
		else if (keylen == 256)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES256;
		else
			return -1;
	}

	return 0;
}

static int nfp_net_xfrm_add_state(struct xfrm_state *x)
{
	int i, key_len, trunc_len, err = 0, saidx = -1;
	struct net_device *netdev = x->xso.dev;
	struct nfp_net_ipsec_sa_data *sa_data;
	struct nfp_ipsec_cfg_add_sa *cfg;
	struct nfp_net_ipsec_data *ipd;
	struct nfp_ipsec_cfg_mssg msg;
	struct nfp_net *nn;
	__be32 *p;

	nn = netdev_priv(netdev);
	ipd = nn->ipsec_data;
	cfg = &msg.cfg_add_sa;

	nn_dbg(nn, "XFRM add state!\n");
	mutex_lock(&ipd->lock);

	if (ipd->sa_free_cnt == 0) {
		dev_info(&netdev->dev, "No space for xfrm offload\n");
		err =  -ENOSPC;
		goto error;
	}

	saidx = ipd->sa_free_stack[ipd->sa_free_cnt - 1];
	sa_data = &ipd->sa_entries[saidx];
	memset(&msg, 0, sizeof(msg));

	/* General */
	switch (x->props.mode) {
	case XFRM_MODE_TUNNEL:
		cfg->ctrl_word.mode = NFP_IPSEC_PROTMODE_TUNNEL;
		break;
	case XFRM_MODE_TRANSPORT:
		cfg->ctrl_word.mode = NFP_IPSEC_PROTMODE_TRANSPORT;
		break;
	default:
		dev_info(&netdev->dev, "Unsupported mode for xfrm offload\n");
		err = -EOPNOTSUPP;
		goto error;
	}

	switch (x->id.proto) {
	case IPPROTO_ESP:
		cfg->ctrl_word.proto = NFP_IPSEC_PROTOCOL_ESP;
		break;
	case IPPROTO_AH:
		cfg->ctrl_word.proto = NFP_IPSEC_PROTOCOL_AH;
		break;
	default:
		dev_info(&netdev->dev, "Unsupported protocol for xfrm offload\n");
		err = -EOPNOTSUPP;
		goto error;
	}

	if (x->props.flags & XFRM_STATE_ESN)
		cfg->ctrl_word.ext_seq = 1;
	else
		cfg->ctrl_word.ext_seq = 0;

	cfg->ctrl_word.ena_arw = 0;
	cfg->ctrl_word.ext_arw = 0;
	cfg->spi = ntohl(x->id.spi);

	/* Hash/Authentication*/
	if (x->aalg)
		trunc_len = x->aalg->alg_trunc_len;
	else
		trunc_len = 0;

	switch (x->props.aalgo) {
	case SADB_AALG_NONE:
		cfg->ctrl_word.hash = NFP_IPSEC_HASH_NONE;
		trunc_len = -1;
		break;
	case SADB_AALG_MD5HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_MD5_96;
		else if (trunc_len == 128)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_MD5_128;
		else
			trunc_len = 0;
		break;
	case SADB_AALG_SHA1HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA1_96;
		else if (trunc_len == 80)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA1_80;
		else
			trunc_len = 0;
		break;
	case SADB_X_AALG_SHA2_256HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA256_96;
		else if (trunc_len == 128)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA256_128;
		else
			trunc_len = 0;
		break;
	case SADB_X_AALG_SHA2_384HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA384_96;
		else if (trunc_len == 192)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA384_192;
		else
			trunc_len = 0;
		break;
	case SADB_X_AALG_SHA2_512HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA512_96;
		else if (trunc_len == 256)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA512_256;
		else
			trunc_len = 0;
		break;
	default:
		dev_info(&netdev->dev, "Unsupported authentication algorithm\n");
		err = -EOPNOTSUPP;
		goto error;
	}

	if (!trunc_len) {
		dev_info(&netdev->dev, "Unsupported authentication algorithm trunc length\n");
		err = -EOPNOTSUPP;
		goto error;
	}

	if (x->aalg) {
		p = (__be32 *)x->aalg->alg_key;
		key_len = (x->aalg->alg_key_len + 7) / 8;
		if (key_len > sizeof(cfg->auth_key)) {
			dev_info(&netdev->dev, "Insufficient space for offloaded auth key\n");
			err = -EINVAL;
			goto error;
		}
		for (i = 0; i < key_len / 4; i++)
			cfg->auth_key[i] = ntohl(*p++);
	}
	/* Encryption */
	switch (x->props.ealgo) {
	case SADB_EALG_NONE:
	case SADB_EALG_NULL:
		cfg->ctrl_word.cimode = NFP_IPSEC_CIMODE_CBC;
		cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_NULL;
		break;
	case SADB_EALG_3DESCBC:
		cfg->ctrl_word.cimode = NFP_IPSEC_CIMODE_CBC;
		cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_3DES;
		break;
	case SADB_X_EALG_AES_GCM_ICV16:
	case SADB_X_EALG_NULL_AES_GMAC:
		if (!x->aead) {
			dev_info(&netdev->dev, "Invalid AES key data\n");
			err = -EINVAL;
			goto error;
		}

		if (x->aead->alg_icv_len != 128) {
			dev_info(&netdev->dev,
				 "ICV must be 128bit with SADB_X_EALG_AES_GCM_ICV16\n");
			err = -EINVAL;
			goto error;
		}
		cfg->ctrl_word.cimode = NFP_IPSEC_CIMODE_CTR;
		cfg->ctrl_word.hash = NFP_IPSEC_HASH_GF128_128;

		/* aead->alg_key_len includes 32-bit salt */
		if (set_aes_keylen(cfg, x->props.ealgo, x->aead->alg_key_len - 32)) {
			dev_info(&netdev->dev, "Unsupported AES key length %d\n",
				 x->aead->alg_key_len);
			err = -EOPNOTSUPP;
			goto error;
		}
		break;
	case SADB_X_EALG_AESCBC:
		cfg->ctrl_word.cimode = NFP_IPSEC_CIMODE_CBC;
		if (!x->ealg) {
			dev_info(&netdev->dev, "Invalid AES key data\n");
			err = -EINVAL;
			goto error;
		}
		if (set_aes_keylen(cfg, x->props.ealgo, x->ealg->alg_key_len) < 0) {
			dev_info(&netdev->dev, "Unsupported AES key length %d\n",
				 x->ealg->alg_key_len);
			err = -EOPNOTSUPP;
			goto error;
		}
		break;
	default:
		dev_info(&netdev->dev, "Unsupported encryption algorithm for offload\n");
		err = -EOPNOTSUPP;
		goto error;
	}

	if (x->aead) {
		int salt_len = 4;

		p = (__be32 *)x->aead->alg_key;
		key_len = (x->aead->alg_key_len + 7) / 8;
		key_len -= salt_len;

		if (key_len > sizeof(cfg->ciph_key)) {
			dev_info(&netdev->dev, "Insufficient space for offloaded key\n");
			err = -EINVAL;
			goto error;
		}

		for (i = 0; i < key_len / 4; i++)
			cfg->ciph_key[i] = ntohl(*p++);

		/* load up the salt */
		for (i = 0; i < salt_len; i++)
			cfg->auth_key[i] = ntohl(*p++);
	}

	if (x->ealg) {
		p = (__be32 *)x->ealg->alg_key;
		key_len = (x->ealg->alg_key_len + 7) / 8;
		if (key_len > sizeof(cfg->ciph_key)) {
			dev_info(&netdev->dev, "Insufficient space for offloaded key\n");
			err = -EINVAL;
			goto error;
		}
		for (i = 0; i < key_len / 4; i++)
			cfg->ciph_key[i] = ntohl(*p++);
	}
	/* IP related info */
	switch (x->props.family) {
	case AF_INET:
		cfg->ipv6 = 0;
		cfg->src_ip[0] = ntohl(x->props.saddr.a4);
		cfg->dst_ip[0] = ntohl(x->id.daddr.a4);
		break;
	case AF_INET6:
		cfg->ipv6 = 1;
		for (i = 0; i < 4; i++) {
			cfg->src_ip[i] = ntohl(x->props.saddr.a6[i]);
			cfg->dst_ip[i] = ntohl(x->id.daddr.a6[i]);
		}
		break;
	default:
		dev_info(&netdev->dev, "Unsupported address family\n");
		err = -EOPNOTSUPP;
		goto error;
	}

	/* Maximum nic IPsec code could handle. Other limits may apply. */
	cfg->pmtu_limit = 0xffff;

	/* host will generate the sequence numbers so that
	 * if packets get fragmented in host, sequence
	 * numbers will stay in sync
	 */
	cfg->ctrl_word.gen_seq = 0;

	/* SA dirction*/
	cfg->ctrl_word.dir = x->xso.dir;

	/* allocate saidx and commit the SA */
	ipd->sa_free_cnt -= 1;
	sa_data->invalidated = 0;
	sa_data->x = x;
	x->xso.offload_handle = saidx + 1;
	err = nfp_ipsec_cfg_cmd_issue(nn, NFP_IPSEC_CFG_MSSG_ADD_SA, saidx, &msg);
	if (err) {
		dev_info(&netdev->dev, "Failed to issue ipsec command err ret=%d\n", err);
		goto error;
	}

	mutex_unlock(&ipd->lock);

	nn_dbg(nn, "Successfully offload saidx %d\n", saidx);
	return 0;
error:
	if (saidx < 0) {
		ipd->sa_free_stack[ipd->sa_free_cnt] = saidx;
		ipd->sa_free_cnt++;
	}
	mutex_unlock(&ipd->lock);
	x->xso.offload_handle = OFFLOAD_HANDLE_ERROR;
	return err;
}

static void xfrm_invalidate(struct nfp_net *nn, unsigned int saidx, int is_del)
{
	struct nfp_net_ipsec_data *ipd = nn->ipsec_data;
	struct nfp_net_ipsec_sa_data *sa_data;
	struct nfp_ipsec_cfg_mssg msg;
	int err;

	sa_data = &ipd->sa_entries[saidx];
	if (!sa_data->invalidated) {
		err = nfp_ipsec_cfg_cmd_issue(nn, NFP_IPSEC_CFG_MSSG_INV_SA, saidx, &msg);
		if (err)
			nn_warn(nn, "Failed to invalidate SA in hardware\n");
		sa_data->invalidated = 1;
	} else if (is_del) {
		nn_warn(nn, "Unexpected invalidate state for offloaded saidx %d\n", saidx);
	}
}

static void nfp_net_xfrm_del_state(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct nfp_net_ipsec_data *ipd;
	struct nfp_net *nn;

	nn = netdev_priv(netdev);
	ipd = nn->ipsec_data;

	nn_dbg(nn, "XFRM del state!\n");

	if (x->xso.offload_handle == OFFLOAD_HANDLE_ERROR)
		return;

	mutex_lock(&ipd->lock);
	xfrm_invalidate(nn, x->xso.offload_handle - 1, 1);
	mutex_unlock(&ipd->lock);
}

static void nfp_net_xfrm_free_state(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct nfp_net_ipsec_data *ipd;
	struct nfp_net *nn;
	int saidx;

	nn = netdev_priv(netdev);
	ipd = nn->ipsec_data;

	nn_dbg(nn, "XFRM free state!\n");

	if (x->xso.offload_handle == OFFLOAD_HANDLE_ERROR)
		return;

	mutex_lock(&ipd->lock);
	saidx = x->xso.offload_handle - 1;
	xfrm_invalidate(nn, saidx, 0);
	ipd->sa_entries[saidx].x = NULL;
	/* return saidx to free list */
	ipd->sa_free_stack[ipd->sa_free_cnt] = saidx;
	ipd->sa_free_cnt++;

	mutex_unlock(&ipd->lock);
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

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2018 Netronome Systems, Inc */
/* Copyright (C) 2021 Corigine, Inc */

#include "../nfpcore/nfp_cpp.h"
#include "../nfpcore/nfp_nsp.h"
#include "../nfp_app.h"
#include "../nfp_main.h"

static int nfp_ipsec_sriov_enable(struct nfp_app *app, int num_vfs)
{
	return 0;
}

static void nfp_ipsec_sriov_disable(struct nfp_app *app)
{
}

static netdev_features_t nfp_ipsec_get_features(struct nfp_app *app, struct nfp_net *nn)
{
	return 0;
}

const struct nfp_app_type app_ipsec = {
	.id		= NFP_APP_IPSEC_NIC,
	.name		= "ipsec-nic",
	.vnic_alloc	= nfp_app_nic_vnic_alloc,
	.sriov_enable	= nfp_ipsec_sriov_enable,
	.sriov_disable	= nfp_ipsec_sriov_disable,
	.get_features   = nfp_ipsec_get_features,
};

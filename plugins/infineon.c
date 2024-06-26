/*
 * oFono - Open Source Telephony
 * Copyright (C) 2014  Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define OFONO_API_SUBJECT_TO_CHANGE

#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/modem.h>

#include "ofono.h"

#include "drivers/rilmodem/vendor.h"
#include "ril.h"

static int inf_probe(struct ofono_modem *modem)
{
	return ril_create(modem, OFONO_RIL_VENDOR_INFINEON);
}

static struct ofono_modem_driver infineon_driver = {
	.probe = inf_probe,
	.remove = ril_remove,
	.enable = ril_enable,
	.disable = ril_disable,
	.pre_sim = ril_pre_sim,
	.post_sim = ril_post_sim,
	.post_online = ril_post_online,
	.set_online = ril_set_online,
};

OFONO_MODEM_DRIVER_BUILTIN(infineon, &infineon_driver)

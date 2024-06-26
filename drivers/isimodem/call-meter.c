/*
 * oFono - Open Source Telephony
 * Copyright (C) 2009-2010  Nokia Corporation and/or its subsidiary(-ies)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <gisi/client.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/call-meter.h>

#include "isiutil.h"
#include "ss.h"

struct call_meter_data {
	GIsiClient *client;
};

static void isi_call_meter_query(struct ofono_call_meter *cm,
					ofono_call_meter_query_cb_t cb,
					void *data)
{
}

static void isi_acm_query(struct ofono_call_meter *cm,
				ofono_call_meter_query_cb_t cb,
				void *data)
{
}

static void isi_acm_reset(struct ofono_call_meter *cm, const char *sim_pin2,
				ofono_call_meter_set_cb_t cb, void *data)
{
}

static void isi_acm_max_query(struct ofono_call_meter *cm,
				ofono_call_meter_query_cb_t cb, void *data)
{
}

static void isi_acm_max_set(struct ofono_call_meter *cm, int new_value,
				const char *sim_pin2,
				ofono_call_meter_set_cb_t cb, void *data)
{
}

static void isi_puct_query(struct ofono_call_meter *cm,
				ofono_call_meter_puct_query_cb_t cb, void *data)
{
}

static void isi_puct_set(struct ofono_call_meter *cm, const char *currency,
				double ppu, const char *sim_pin2,
				ofono_call_meter_set_cb_t cb, void *data)
{
}

static int isi_call_meter_probe(struct ofono_call_meter *cm,
				unsigned int vendor, void *user)
{
	GIsiModem *modem = user;
	struct call_meter_data *cmd;

	cmd = g_try_new0(struct call_meter_data, 1);
	if (cmd == NULL)
		return -ENOMEM;

	cmd->client = g_isi_client_create(modem, PN_SS);
	if (cmd->client == NULL) {
		g_free(cmd);
		return -ENOMEM;
	}

	ofono_call_meter_set_data(cm, cmd);

	return 0;
}

static void isi_call_meter_remove(struct ofono_call_meter *cm)
{
	struct call_meter_data *data = ofono_call_meter_get_data(cm);

	ofono_call_meter_set_data(cm, NULL);

	if (data == NULL)
		return;

	g_isi_client_destroy(data->client);
	g_free(data);
}

static const struct ofono_call_meter_driver driver = {
	.probe			= isi_call_meter_probe,
	.remove			= isi_call_meter_remove,
	.call_meter_query	= isi_call_meter_query,
	.acm_query		= isi_acm_query,
	.acm_reset		= isi_acm_reset,
	.acm_max_query		= isi_acm_max_query,
	.acm_max_set		= isi_acm_max_set,
	.puct_query		= isi_puct_query,
	.puct_set		= isi_puct_set
};

OFONO_ATOM_DRIVER_BUILTIN(call_meter, isimodem, &driver)

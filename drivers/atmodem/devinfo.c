/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>

#include <drivers/atmodem/atutil.h>

#include "gatchat.h"
#include "gatresult.h"

static const char *gcap_prefix[] = { "+GCAP:", NULL };

static void attr_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_devinfo_query_cb_t cb = cbd->cb;
	const char *prefix = cbd->user;
	struct ofono_error error;
	const char *attr;

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, NULL, cbd->data);
		return;
	}

	if (at_util_parse_attr(result, prefix, &attr) == FALSE) {
		CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
		return;
	}

	cb(&error, attr, cbd->data);
}

static void at_query_manufacturer(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	GAtChat *chat = ofono_devinfo_get_data(info);

	cbd->user = "+CGMI:";

	if (g_at_chat_send(chat, "AT+CGMI", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void at_query_model(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	GAtChat *chat = ofono_devinfo_get_data(info);

	cbd->user = "+CGMM:";

	if (g_at_chat_send(chat, "AT+CGMM", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void at_query_revision(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	GAtChat *chat = ofono_devinfo_get_data(info);

	cbd->user = "+CGMR:";

	if (g_at_chat_send(chat, "AT+CGMR", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void at_query_serial(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	GAtChat *chat = ofono_devinfo_get_data(info);

	cbd->user = "+CGSN:";

	if (g_at_chat_send(chat, "AT+CGSN", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void capability_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_devinfo *info = user_data;

	ofono_devinfo_register(info);
}

static int at_devinfo_probe(struct ofono_devinfo *info, unsigned int vendor,
				void *data)
{
	GAtChat *chat = g_at_chat_clone(data);

	ofono_devinfo_set_data(info, chat);

	g_at_chat_send(chat, "AT+GCAP", gcap_prefix,
				capability_cb, info, NULL);

	return 0;
}

static void at_devinfo_remove(struct ofono_devinfo *info)
{
	GAtChat *chat = ofono_devinfo_get_data(info);

	ofono_devinfo_set_data(info, NULL);

	g_at_chat_unref(chat);
}

static const struct ofono_devinfo_driver driver = {
	.probe			= at_devinfo_probe,
	.remove			= at_devinfo_remove,
	.query_manufacturer	= at_query_manufacturer,
	.query_model		= at_query_model,
	.query_revision		= at_query_revision,
	.query_serial		= at_query_serial,
};

OFONO_ATOM_DRIVER_BUILTIN(devinfo, atmodem, &driver)

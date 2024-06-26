/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/radio-settings.h>

#include <drivers/atmodem/atutil.h>

#include "gatchat.h"
#include "gatresult.h"

static const char *none_prefix[] = { NULL };
static const char *zsnt_prefix[] = { "+ZSNT:", NULL };

struct radio_settings_data {
	GAtChat *chat;
};

static void zsnt_query_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_radio_settings_rat_mode_query_cb_t cb = cbd->cb;
	unsigned int mode;
	struct ofono_error error;
	GAtResultIter iter;
	int value;

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+ZSNT:") == FALSE)
		goto error;

	if (g_at_result_iter_next_number(&iter, &value) == FALSE)
		goto error;

	switch (value) {
	case 0:
		mode = OFONO_RADIO_ACCESS_MODE_ANY;
		break;
	case 1:
		mode = OFONO_RADIO_ACCESS_MODE_GSM;
		break;
	case 2:
		mode = OFONO_RADIO_ACCESS_MODE_UMTS;
		break;
	default:
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	cb(&error, mode, cbd->data);

	return;

error:
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
}

static void zte_query_rat_mode(struct ofono_radio_settings *rs,
				ofono_radio_settings_rat_mode_query_cb_t cb,
				void *data)
{
	struct radio_settings_data *rsd = ofono_radio_settings_get_data(rs);
	struct cb_data *cbd = cb_data_new(cb, data);

	if (g_at_chat_send(rsd->chat, "AT+ZSNT?", zsnt_prefix,
					zsnt_query_cb, cbd, g_free) == 0) {
		CALLBACK_WITH_FAILURE(cb, -1, data);
		g_free(cbd);
	}
}

static void zsnt_modify_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_radio_settings_rat_mode_set_cb_t cb = cbd->cb;
	struct ofono_error error;

	decode_at_error(&error, g_at_result_final_response(result));
	cb(&error, cbd->data);
}

static void zte_set_rat_mode(struct ofono_radio_settings *rs, unsigned int mode,
				ofono_radio_settings_rat_mode_set_cb_t cb,
				void *data)
{
	struct radio_settings_data *rsd = ofono_radio_settings_get_data(rs);
	struct cb_data *cbd = cb_data_new(cb, data);
	char buf[20];
	int value = 0;

	switch (mode) {
	case OFONO_RADIO_ACCESS_MODE_ANY:
		value = 0;
		break;
	case OFONO_RADIO_ACCESS_MODE_GSM:
		value = 1;
		break;
	case OFONO_RADIO_ACCESS_MODE_UMTS:
		value = 2;
		break;
	case OFONO_RADIO_ACCESS_MODE_LTE:
		goto error;
	}

	snprintf(buf, sizeof(buf), "AT+ZSNT=%u,0,0", value);

	if (g_at_chat_send(rsd->chat, buf, none_prefix,
					zsnt_modify_cb, cbd, g_free) > 0)
		return;

error:
	CALLBACK_WITH_FAILURE(cb, data);
	g_free(cbd);
}

static void zsnt_support_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_radio_settings *rs = user_data;

	if (!ok) {
		ofono_radio_settings_remove(rs);
		return;
	}

	ofono_radio_settings_register(rs);
}

static int zte_radio_settings_probe(struct ofono_radio_settings *rs,
					unsigned int vendor, void *data)
{
	GAtChat *chat = data;
	struct radio_settings_data *rsd;

	rsd = g_try_new0(struct radio_settings_data, 1);
	if (rsd == NULL)
		return -ENOMEM;

	rsd->chat = g_at_chat_clone(chat);

	ofono_radio_settings_set_data(rs, rsd);

	g_at_chat_send(rsd->chat, "AT+ZSNT=?", none_prefix,
					zsnt_support_cb, rs, NULL);

	return 0;
}

static void zte_radio_settings_remove(struct ofono_radio_settings *rs)
{
	struct radio_settings_data *rsd = ofono_radio_settings_get_data(rs);

	ofono_radio_settings_set_data(rs, NULL);

	g_at_chat_unref(rsd->chat);
	g_free(rsd);
}

static const struct ofono_radio_settings_driver driver = {
	.probe			= zte_radio_settings_probe,
	.remove			= zte_radio_settings_remove,
	.query_rat_mode		= zte_query_rat_mode,
	.set_rat_mode		= zte_set_rat_mode
};

OFONO_ATOM_DRIVER_BUILTIN(radio_settings, ztemodem, &driver)

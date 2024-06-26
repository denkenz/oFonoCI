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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/audio-settings.h>

#include "gatchat.h"
#include "gatresult.h"

static const char *cvoice_prefix[] = { "^CVOICE:", NULL };

struct audio_settings_data {
	GAtChat *chat;
};

static void cring_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_audio_settings *as = user_data;

	ofono_audio_settings_active_notify(as, TRUE);
}

static void orig_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_audio_settings *as = user_data;

	ofono_audio_settings_active_notify(as, TRUE);
}

static void cend_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_audio_settings *as = user_data;

	ofono_audio_settings_active_notify(as, FALSE);
}

static void cvoice_support_cb(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct ofono_audio_settings *as = user_data;
	struct audio_settings_data *asd = ofono_audio_settings_get_data(as);

	if (!ok)
		return;

	g_at_chat_register(asd->chat, "+CRING:", cring_notify, FALSE, as, NULL);
	g_at_chat_register(asd->chat, "^ORIG:", orig_notify, FALSE, as, NULL);
	g_at_chat_register(asd->chat, "^CEND:", cend_notify, FALSE, as, NULL);

	ofono_audio_settings_register(as);
}

static int huawei_audio_settings_probe(struct ofono_audio_settings *as,
					unsigned int vendor, void *data)
{
	GAtChat *chat = data;
	struct audio_settings_data *asd;

	asd = g_try_new0(struct audio_settings_data, 1);
	if (asd == NULL)
		return -ENOMEM;

	asd->chat = g_at_chat_clone(chat);

	ofono_audio_settings_set_data(as, asd);

	g_at_chat_send(asd->chat, "AT^CVOICE=?", cvoice_prefix,
					cvoice_support_cb, as, NULL);

	return 0;
}

static void huawei_audio_settings_remove(struct ofono_audio_settings *as)
{
	struct audio_settings_data *asd = ofono_audio_settings_get_data(as);

	ofono_audio_settings_set_data(as, NULL);

	g_at_chat_unref(asd->chat);
	g_free(asd);
}

static const struct ofono_audio_settings_driver driver = {
	.probe		= huawei_audio_settings_probe,
	.remove		= huawei_audio_settings_remove,
};

OFONO_ATOM_DRIVER_BUILTIN(audio_settings, huaweimodem, &driver)

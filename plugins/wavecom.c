/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <gatchat.h>
#include <gattty.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/call-barring.h>
#include <ofono/call-forwarding.h>
#include <ofono/call-meter.h>
#include <ofono/call-settings.h>
#include <ofono/devinfo.h>
#include <ofono/message-waiting.h>
#include <ofono/netreg.h>
#include <ofono/phonebook.h>
#include <ofono/sim.h>
#include <ofono/sms.h>
#include <ofono/ussd.h>
#include <ofono/voicecall.h>

#include <drivers/atmodem/atutil.h>
#include <drivers/atmodem/vendor.h>


static int wavecom_probe(struct ofono_modem *modem)
{
	return 0;
}

static void wavecom_remove(struct ofono_modem *modem)
{
}

static void wavecom_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

static int wavecom_enable(struct ofono_modem *modem)
{
	GAtChat *chat;

	DBG("%p", modem);

	chat = at_util_open_device(modem, "Device", wavecom_debug, "",
					"Baud", "115200",
					"Parity", "none",
					"StopBits", "1",
					"DataBits", "8",
					NULL);
	if (!chat)
		return -EINVAL;

	g_at_chat_add_terminator(chat, "+CPIN:", 6, TRUE);
	ofono_modem_set_data(modem, chat);

	return 0;
}

static int wavecom_disable(struct ofono_modem *modem)
{
	GAtChat *chat = ofono_modem_get_data(modem);

	DBG("%p", modem);

	ofono_modem_set_data(modem, NULL);

	g_at_chat_unref(chat);

	return 0;
}

static void wavecom_pre_sim(struct ofono_modem *modem)
{
	GAtChat *chat = ofono_modem_get_data(modem);
	const char *model;
	enum ofono_vendor vendor = 0;
	struct ofono_sim *sim;

	DBG("%p", modem);

	model = ofono_modem_get_string(modem, "Model");
	if (model && strcmp(model, "Q2XXX") == 0)
		vendor = OFONO_VENDOR_WAVECOM_Q2XXX;

	ofono_devinfo_create(modem, 0, "atmodem", chat);
	sim = ofono_sim_create(modem, vendor, "atmodem", chat);
	ofono_voicecall_create(modem, 0, "atmodem", chat);

	if (vendor == OFONO_VENDOR_WAVECOM_Q2XXX)
		ofono_sim_inserted_notify(sim, TRUE);
}

static void wavecom_post_sim(struct ofono_modem *modem)
{
	GAtChat *chat = ofono_modem_get_data(modem);
	struct ofono_message_waiting *mw;
	const char *model;
	enum ofono_vendor vendor = 0;

	DBG("%p", modem);

	model = ofono_modem_get_string(modem, "Model");
	if (model && strcmp(model, "Q2XXX") == 0)
		vendor = OFONO_VENDOR_WAVECOM_Q2XXX;

	ofono_ussd_create(modem, 0, "atmodem", chat);
	ofono_call_forwarding_create(modem, 0, "atmodem", chat);
	ofono_call_settings_create(modem, 0, "atmodem", chat);
	ofono_netreg_create(modem, 0, "atmodem", chat);
	ofono_call_meter_create(modem, 0, "atmodem", chat);
	ofono_call_barring_create(modem, 0, "atmodem", chat);
	ofono_sms_create(modem, vendor, "atmodem", chat);
	ofono_phonebook_create(modem, 0, "atmodem", chat);

	mw = ofono_message_waiting_create(modem);
	if (mw)
		ofono_message_waiting_register(mw);
}

static struct ofono_modem_driver wavecom_driver = {
	.probe		= wavecom_probe,
	.remove		= wavecom_remove,
	.enable		= wavecom_enable,
	.disable	= wavecom_disable,
	.pre_sim	= wavecom_pre_sim,
	.post_sim	= wavecom_post_sim,
};

OFONO_MODEM_DRIVER_BUILTIN(wavecom, &wavecom_driver)

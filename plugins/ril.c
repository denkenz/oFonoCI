/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 * Copyright (C) 2012-2014 Canonical Ltd
 * Copyright (C) 2013 Jolla Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <glib.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>
#include <ofono/phonebook.h>
#include <ofono/netreg.h>
#include <ofono/voicecall.h>
#include <ofono/sms.h>
#include <ofono/cbs.h>
#include <ofono/sim.h>
#include <ofono/ussd.h>
#include <ofono/call-forwarding.h>
#include <ofono/call-settings.h>
#include <ofono/call-barring.h>
#include <ofono/call-meter.h>
#include <ofono/call-volume.h>
#include <ofono/radio-settings.h>
#include <ofono/gprs.h>
#include <ofono/gprs-context.h>
#include <ofono/audio-settings.h>
#include <ofono/types.h>

#include <gril/gril.h>

#include "ofono.h"

#include "ril.h"
#include "drivers/rilmodem/rilutil.h"
#include "drivers/rilmodem/vendor.h"

#define RILMODEM "rilmodem"

#define	RADIO_GID 1001
#define	RADIO_UID 1001

#define MAX_SIM_STATUS_RETRIES 15

/* this gives 30s for rild to initialize */
#define RILD_MAX_CONNECT_RETRIES 5
#define RILD_CONNECT_RETRY_TIME_S 5

char *RILD_CMD_SOCKET[] = {"/dev/socket/rild", "/dev/socket/rild1"};
char *GRIL_HEX_PREFIX[] = {"Device 0: ", "Device 1: "};

struct ril_data {
	GRil *ril;
	enum ofono_ril_vendor vendor;
	int sim_status_retries;
	ofono_bool_t connected;
	ofono_bool_t ofono_online;
	int radio_state;
	struct ofono_sim *sim;
	struct ofono_radio_settings *radio_settings;
	int rild_connect_retries;
};

static void ril_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

static void ril_radio_state_changed(struct ril_msg *message, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct ril_data *rd = ofono_modem_get_data(modem);
	struct parcel rilp;
	int radio_state;

	g_ril_init_parcel(message, &rilp);

	radio_state = parcel_r_int32(&rilp);

	if (rilp.malformed) {
		ofono_error("%s: malformed parcel received", __func__);
		ofono_modem_set_powered(modem, FALSE);
		return;
	}

	g_ril_append_print_buf(rd->ril, "(state: %s)",
				ril_radio_state_to_string(radio_state));
	g_ril_print_unsol(rd->ril, message);

	if (radio_state != rd->radio_state) {
		ofono_info("%s: state: %s rd->ofono_online: %d",
				__func__,
				ril_radio_state_to_string(radio_state),
				rd->ofono_online);

		rd->radio_state = radio_state;

		switch (radio_state) {
		case RADIO_STATE_ON:
			if (rd->radio_settings == NULL)
				rd->radio_settings =
					ofono_radio_settings_create(modem,
							rd->vendor, RILMODEM,
							rd->ril);

			break;

		case RADIO_STATE_UNAVAILABLE:
		case RADIO_STATE_OFF:
			/*
			 * Unexpected radio state change, as we are supposed to
			 * be online. UNAVAILABLE has been seen occassionally
			 * when powering off the phone. We wait 5 secs to avoid
			 * too fast re-spawns, then exit with error to make
			 * upstart re-start ofono.
			 */
			if (rd->ofono_online)
				ofono_error("%s: radio self-powered off!",
						__func__);

			break;
		}
	}
}

int ril_create(struct ofono_modem *modem, enum ofono_ril_vendor vendor)
{
	ofono_bool_t lte_cap;
	struct ril_data *rd = g_try_new0(struct ril_data, 1);
	if (rd == NULL) {
		errno = ENOMEM;
		goto error;
	}

	DBG("");

	rd->vendor = vendor;
	rd->ofono_online = FALSE;
	rd->radio_state = RADIO_STATE_OFF;

	lte_cap = getenv("OFONO_RIL_RAT_LTE") ? TRUE : FALSE;
	ofono_modem_set_boolean(modem, MODEM_PROP_LTE_CAPABLE, lte_cap);

	ofono_modem_set_data(modem, rd);

	return 0;

error:
	g_free(rd);

	return -errno;
}

static int ril_probe(struct ofono_modem *modem)
{
	return ril_create(modem, OFONO_RIL_VENDOR_AOSP);
}

void ril_remove(struct ofono_modem *modem)
{
	struct ril_data *rd = ofono_modem_get_data(modem);

	ofono_modem_set_data(modem, NULL);

	if (!rd)
		return;

	g_ril_unref(rd->ril);

	g_free(rd);
}

void ril_pre_sim(struct ofono_modem *modem)
{
	struct ril_data *rd = ofono_modem_get_data(modem);

	DBG("");

	ofono_devinfo_create(modem, rd->vendor, RILMODEM, rd->ril);
	ofono_voicecall_create(modem, rd->vendor, RILMODEM, rd->ril);
	ofono_call_volume_create(modem, rd->vendor, RILMODEM, rd->ril);

	rd->sim = ofono_sim_create(modem, rd->vendor, RILMODEM, rd->ril);
}

void ril_post_sim(struct ofono_modem *modem)
{
	struct ril_data *rd = ofono_modem_get_data(modem);
	struct ofono_message_waiting *mw;

	/* TODO: this function should setup:
	 *  - phonebook
	 *  - stk ( SIM toolkit )
	 *  - radio_settings
	 */
	ofono_sms_create(modem, rd->vendor, RILMODEM, rd->ril);

	mw = ofono_message_waiting_create(modem);
	if (mw)
		ofono_message_waiting_register(mw);

	ofono_call_forwarding_create(modem, rd->vendor, RILMODEM, rd->ril);
	ofono_stk_create(modem, rd->vendor, RILMODEM, rd->ril);
	ofono_phonebook_create(modem, rd->vendor, RILMODEM, modem);
}

void ril_post_online(struct ofono_modem *modem)
{
	struct ril_data *rd = ofono_modem_get_data(modem);
	struct ofono_gprs *gprs;
	struct ofono_gprs_context *gc;

	ofono_cbs_create(modem, rd->vendor, RILMODEM, rd->ril);
	ofono_netreg_create(modem, rd->vendor, RILMODEM, rd->ril);
	ofono_ussd_create(modem, rd->vendor, RILMODEM, rd->ril);
	ofono_call_settings_create(modem, rd->vendor, RILMODEM, rd->ril);
	ofono_call_barring_create(modem, rd->vendor, RILMODEM, rd->ril);
	gprs = ofono_gprs_create(modem, rd->vendor, RILMODEM, rd->ril);
	gc = ofono_gprs_context_create(modem, rd->vendor, RILMODEM, rd->ril);

	if (gc) {
		ofono_gprs_context_set_type(gc,
					OFONO_GPRS_CONTEXT_TYPE_INTERNET);
		ofono_gprs_add_context(gprs, gc);
	}

	gc = ofono_gprs_context_create(modem, rd->vendor, RILMODEM, rd->ril);

	if (gc) {
		ofono_gprs_context_set_type(gc, OFONO_GPRS_CONTEXT_TYPE_MMS);
		ofono_gprs_add_context(gprs, gc);
	}
}

static void ril_set_online_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ril_data *rd = cbd->user;
	ofono_modem_online_cb_t cb = cbd->cb;

	if (message->error == RIL_E_SUCCESS) {
		DBG("%s: set_online OK: rd->ofono_online: %d", __func__,
			rd->ofono_online);
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	} else {
		ofono_error("%s: set_online: %d failed", __func__,
				rd->ofono_online);
		CALLBACK_WITH_FAILURE(cb, cbd->data);
	}
}

static void ril_send_power(struct ril_data *rd, ofono_bool_t online,
				GRilResponseFunc func,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_modem_online_cb_t cb;
	GDestroyNotify notify = NULL;
	struct parcel rilp;

	if (cbd != NULL) {
		notify = g_free;
		cb = cbd->cb;
	}

	DBG("(online = 1, offline = 0)): %i", online);

	parcel_init(&rilp);
	parcel_w_int32(&rilp, 1);
	parcel_w_int32(&rilp, online);

	g_ril_append_print_buf(rd->ril, "(%d)", online);

	if (g_ril_send(rd->ril, RIL_REQUEST_RADIO_POWER, &rilp,
			func, cbd, notify) == 0 && cbd != NULL) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		g_free(cbd);
	}
}

void ril_set_online(struct ofono_modem *modem, ofono_bool_t online,
			ofono_modem_online_cb_t callback, void *data)
{
	struct ril_data *rd = ofono_modem_get_data(modem);
	struct cb_data *cbd = cb_data_new(callback, data, rd);

	rd->ofono_online = online;

	DBG("setting rd->ofono_online to: %d", online);

	ril_send_power(rd, online, ril_set_online_cb, cbd);
}

static void ril_connected(struct ril_msg *message, gpointer user_data)
{
	struct ofono_modem *modem = (struct ofono_modem *) user_data;
	struct ril_data *rd = ofono_modem_get_data(modem);

	ofono_info("[%d,UNSOL]< %s", g_ril_get_slot(rd->ril),
		g_ril_unsol_request_to_string(rd->ril, message->req));

	/* TODO: need a disconnect function to restart things! */
	rd->connected = TRUE;

	DBG("calling set_powered(TRUE)");

	ofono_modem_set_powered(modem, TRUE);
}

static int create_gril(struct ofono_modem *modem)
{
	struct ril_data *rd = ofono_modem_get_data(modem);
	int slot_id = ofono_modem_get_integer(modem, "Slot");

	ofono_info("Using %s as socket for slot %d.",
					RILD_CMD_SOCKET[slot_id], slot_id);

	/* RIL expects user radio to connect to the socket */
	rd->ril = g_ril_new_with_ucred(RILD_CMD_SOCKET[slot_id],
						OFONO_RIL_VENDOR_AOSP,
						RADIO_UID, RADIO_GID);

	/* NOTE: Since AT modems open a tty, and then call
	 * g_at_chat_new(), they're able to return -EIO if
	 * the first fails, and -ENOMEM if the second fails.
	 * in our case, we already return -EIO if the ril_new
	 * fails.  If this is important, we can create a ril_socket
	 * abstraction... ( probaby not a bad idea ).
	 */

	if (rd->ril == NULL) {
		ofono_error("g_ril_new() failed to create modem!");
		return -EIO;
	}
	g_ril_set_slot(rd->ril, slot_id);

	if (getenv("OFONO_RIL_TRACE"))
		g_ril_set_trace(rd->ril, TRUE);

	if (getenv("OFONO_RIL_HEX_TRACE"))
		g_ril_set_debugf(rd->ril, ril_debug, GRIL_HEX_PREFIX[slot_id]);

	g_ril_register(rd->ril, RIL_UNSOL_RIL_CONNECTED,
			ril_connected, modem);

	g_ril_register(rd->ril, RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED,
			ril_radio_state_changed, modem);

	return 0;
}

static gboolean connect_rild(gpointer user_data)
{
	struct ofono_modem *modem = (struct ofono_modem *) user_data;
	struct ril_data *rd = ofono_modem_get_data(modem);

	ofono_info("Trying to reconnect to rild...");

	if (rd->rild_connect_retries++ < RILD_MAX_CONNECT_RETRIES) {
		if (create_gril(modem) < 0)
			return TRUE;
	} else {
		ofono_error("Failed to connect to rild.");
		return TRUE;
	}

	return FALSE;
}

int ril_enable(struct ofono_modem *modem)
{
	int ret;

	DBG("");

	ret = create_gril(modem);
	if (ret < 0)
		g_timeout_add_seconds(RILD_CONNECT_RETRY_TIME_S,
					connect_rild, modem);

	return -EINPROGRESS;
}

static void power_off_cb(struct ril_msg *message, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ril_data *rd = cbd->user;
	struct ofono_modem *modem = cbd->data;

	if (rd) {
		g_ril_unref(rd->ril);
		rd->ril = NULL;
	}

	ofono_modem_set_powered(modem, FALSE);
}

int ril_disable(struct ofono_modem *modem)
{
	struct ril_data *rd = ofono_modem_get_data(modem);
	struct cb_data *cbd = cb_data_new(NULL, modem, rd);

	DBG("%p", modem);

	ril_send_power(rd, FALSE, power_off_cb, cbd);

	return -EINPROGRESS;
}

static struct ofono_modem_driver ril_driver = {
	.probe = ril_probe,
	.remove = ril_remove,
	.enable = ril_enable,
	.disable = ril_disable,
	.pre_sim = ril_pre_sim,
	.post_sim = ril_post_sim,
	.post_online = ril_post_online,
	.set_online = ril_set_online,
};

OFONO_MODEM_DRIVER_BUILTIN(ril, &ril_driver)

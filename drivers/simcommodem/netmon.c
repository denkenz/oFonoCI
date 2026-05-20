/*
 * oFono - Open Source Telephony
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/netreg.h>
#include <ofono/netmon.h>

#include <drivers/atmodem/atutil.h>

#include "gatchat.h"
#include "gatresult.h"

#include "common.h"

#include "drivers/atmodem/vendor.h"

static const char *cpsi_prefix[] = { "+CPSI:", NULL };

struct netmon_driver_data {
	GAtChat *chat;
};

struct req_cb_data {
	gint ref_count; /* Ref count */

	struct ofono_netmon *netmon;
	ofono_netmon_cb_t cb;
	void *data;

	struct ofono_network_operator op;

	int rssi;	/* CSQ: received signal strength indicator (RSSI) */

	struct {
		int tac;	/* CPSI: Tracing Area Code */
		int pcell;	/* CPSI: Physical Cell ID */
		int earfcn;	/* CPSI: E-UTRA Absolute Radio Frequency Channel Number */
		int rsrp;	/* CPSI: Reference Signal Received Power */
		int rsrq;	/* CPSI: Reference Signal Received Quality */
	} lte;
};

static inline struct req_cb_data *req_cb_data_new0(void *cb, void *data,
							void *user)
{
	struct req_cb_data *ret = g_new0(struct req_cb_data, 1);

	ret->ref_count = 1;
	ret->netmon = user;
	ret->data = data;
	ret->cb = cb;

	return ret;
}

static inline struct req_cb_data *req_cb_data_ref(struct req_cb_data *cbd)
{
	if (cbd == NULL)
		return NULL;

	g_atomic_int_inc(&cbd->ref_count);

	return cbd;
}

static void req_cb_data_unref(gpointer user_data)
{
	struct req_cb_data *cbd = user_data;
	gboolean is_zero;

	if (cbd == NULL)
		return;

	is_zero = g_atomic_int_dec_and_test(&cbd->ref_count);

	if (is_zero == TRUE)
		g_free(cbd);
}

static int simcom_parse_cpsi_lte(GAtResultIter *iter, struct req_cb_data *cbd) {
	/*
	 * +CPSI: <System Mode>,<Operation Mode>[,<MCC>-<MNC>,<TAC>,<SCellID>,<PCellID>,<Frequency Band>,<earfcn>,<dlbw>,<ulbw>,<RSRQ>,<RSRP>,<RSSI>,<RSSNR>]
	 * +CPSI: LTE,Online,460-01,0x230A,175499523,318,EUTRAN-BAND3,1650,5,0,21,67,255,19
	 */

	struct ofono_netmon *nm = cbd->netmon;
	int number;
	const char *field = NULL;
	char *mcc = NULL;
	char *mnc = NULL;

	cbd->lte.earfcn = -1;
	cbd->lte.rsrp = -1;
	cbd->lte.rsrq = -1;

	g_at_result_iter_skip_next(iter);

	if (g_at_result_iter_next_unquoted_string(iter, &field)) {
		mcc = strdup(field);
		mnc = strchr(mcc, '-');
		if(mnc != NULL) {
			*mnc++ = 0;
			snprintf(cbd->op.mcc, 4, "%s", mcc);
			snprintf(cbd->op.mnc, 4, "%s", mnc);
		}
		free(mcc);
	}

	if (g_at_result_iter_next_unquoted_string(iter, &field))
		cbd->lte.tac = strtol(field, NULL, 16);

	g_at_result_iter_skip_next(iter);

	if (g_at_result_iter_next_number(iter, &number))
		cbd->lte.pcell = number;

	g_at_result_iter_skip_next(iter);

	if (g_at_result_iter_next_number(iter, &number))
		cbd->lte.earfcn = number;

	g_at_result_iter_skip_next(iter);
	g_at_result_iter_skip_next(iter);

	if (g_at_result_iter_next_number(iter, &number))
		cbd->lte.rsrq = number;

	if (g_at_result_iter_next_number(iter, &number))
		cbd->lte.rsrp = number;

	if (g_at_result_iter_next_number(iter, &number))
		cbd->rssi = number;

	DBG(" %-15s %s", "LTE.MCC", cbd->op.mcc);
	DBG(" %-15s %s", "LTE.MNC", cbd->op.mnc);
	DBG(" %-15s %d", "LTE.TAC", cbd->lte.tac);
	DBG(" %-15s %d", "LTE.PCI", cbd->lte.pcell);
	DBG(" %-15s %d", "LTE.EUARFCN", cbd->lte.earfcn);
	DBG(" %-15s %d", "LTE.RSRP", cbd->lte.rsrp);
	DBG(" %-15s %d", "LTE.RSRQ", cbd->lte.rsrq);

	ofono_netmon_serving_cell_notify(nm, cbd->op.tech,
		OFONO_NETMON_INFO_MCC, cbd->op.mcc,
		OFONO_NETMON_INFO_MNC, cbd->op.mnc,
		OFONO_NETMON_INFO_TAC, cbd->lte.tac,
		OFONO_NETMON_INFO_PCI, cbd->lte.pcell,
		OFONO_NETMON_INFO_RSSI, cbd->rssi,
		OFONO_NETMON_INFO_EARFCN, cbd->lte.earfcn,
		OFONO_NETMON_INFO_RSRP, cbd->lte.rsrp,
		OFONO_NETMON_INFO_RSRQ, cbd->lte.rsrq,
		OFONO_NETMON_INFO_INVALID);
}

static void cpsi_cb(gboolean ok, GAtResult *result, gpointer user_data) {
	struct req_cb_data *cbd = user_data;
	struct ofono_error error;
	const char *technology;
	GAtResultIter iter;

	DBG("ok %d", ok);

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		CALLBACK_WITH_FAILURE(cbd->cb, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if(!g_at_result_iter_next(&iter, "+CPSI: ")) {
		ofono_warn("Failed to find iterate +CPSI response");
		CALLBACK_WITH_SUCCESS(cbd->cb, cbd->data);
		return;
	}

	if (!g_at_result_iter_next_unquoted_string(&iter, &technology)) {
		ofono_warn("+CPSI: failed to parse technology");
		CALLBACK_WITH_SUCCESS(cbd->cb, cbd->data);
		return;
	}

	if (strcmp(technology, "LTE") == 0) {
		cbd->op.tech = OFONO_NETMON_CELL_TYPE_LTE;
		simcom_parse_cpsi_lte(&iter, cbd);
	} else if (strcmp(technology, "NO SERVICE") == 0 ) {
		cbd->op.tech = -1;
	} else {
		ofono_warn("Unknown technology in +CPSI response: %s", technology);
		cbd->op.tech = -1;
	}

	CALLBACK_WITH_SUCCESS(cbd->cb, cbd->data);
}

static void simcom_netmon_request_update(struct ofono_netmon *netmon,
						ofono_netmon_cb_t cb,
						void *data)
{
	struct netmon_driver_data *nmd = ofono_netmon_get_data(netmon);
	struct req_cb_data *cbd;

	DBG("simcom netmon request update");

	cbd = req_cb_data_new0(cb, data, netmon);

	if (g_at_chat_send(nmd->chat, "AT+CPSI?", cpsi_prefix, cpsi_cb, cbd,
				req_cb_data_unref))
		return;

	req_cb_data_unref(cbd);
	CALLBACK_WITH_FAILURE(cbd->cb, cbd->data);
}

static int simcom_netmon_probe(struct ofono_netmon *netmon,
					unsigned int vendor, void *user)
{
	struct netmon_driver_data *nmd = g_new0(struct netmon_driver_data, 1);
	GAtChat *chat = user;

	DBG("simcom netmon probe");

	nmd->chat = g_at_chat_clone(chat);

	ofono_netmon_set_data(netmon, nmd);
	ofono_netmon_register(netmon);

	return 0;
}

static void simcom_netmon_remove(struct ofono_netmon *netmon)
{
	struct netmon_driver_data *nmd = ofono_netmon_get_data(netmon);

	DBG("simcom netmon remove");

	g_at_chat_unref(nmd->chat);

	ofono_netmon_set_data(netmon, NULL);

	g_free(nmd);
}

static const struct ofono_netmon_driver driver = {
	.probe			= simcom_netmon_probe,
	.remove			= simcom_netmon_remove,
	.request_update		= simcom_netmon_request_update,
};

OFONO_ATOM_DRIVER_BUILTIN(netmon, simcommodem, &driver);

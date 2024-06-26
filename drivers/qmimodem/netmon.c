/*
 * oFono - Open Source Telephony
 * Copyright (C) 2017  Jonas Bonn
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

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/netmon.h>

#include "src/common.h"

#include "qmi.h"
#include "nas.h"
#include "util.h"

struct netmon_data {
	struct qmi_service *nas;
};

static void get_rssi_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_netmon *netmon = cbd->user;
	ofono_netmon_cb_t cb = cbd->cb;
	struct {
		enum ofono_netmon_cell_type type;
		int rssi;
		int ber;
		int rsrq;
		int rsrp;
	} props;
	uint16_t len;
	int16_t rsrp;
	const struct {
		int8_t value;
		int8_t rat;
	} __attribute__((__packed__)) *rsrq;
	const struct {
		uint16_t count;
		struct {
			uint8_t rssi;
			int8_t rat;
		} __attribute__((__packed__)) info[0];
	} __attribute__((__packed__)) *rssi;
	const struct {
		uint16_t count;
		struct {
			uint16_t rate;
			int8_t rat;
		} __attribute__((__packed__)) info[0];
	} __attribute__((__packed__)) *ber;
	int i;
	uint16_t num;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		return;
	}

	/* RSSI */
	rssi = qmi_result_get(result, 0x11, &len);
	if (rssi) {
		num = L_LE16_TO_CPU(rssi->count);
		for (i = 0; i < num; i++) {
			DBG("RSSI: %hhu on RAT %hhd",
				rssi->info[i].rssi,
				rssi->info[i].rat);
		}

		/* Get cell type from RSSI info... it will be the same
		 * for all the other entries
		 */
		props.type = qmi_nas_rat_to_tech(rssi->info[0].rat);
		switch (rssi->info[0].rat) {
		case QMI_NAS_NETWORK_RAT_GSM:
			props.type = OFONO_NETMON_CELL_TYPE_GSM;
			break;
		case QMI_NAS_NETWORK_RAT_UMTS:
			props.type = OFONO_NETMON_CELL_TYPE_UMTS;
			break;
		case QMI_NAS_NETWORK_RAT_LTE:
			props.type = OFONO_NETMON_CELL_TYPE_LTE;
			break;
		default:
			props.type = OFONO_NETMON_CELL_TYPE_GSM;
			break;
		}

		props.rssi = (rssi->info[0].rssi + 113) / 2;
		if (props.rssi > 31) props.rssi = 31;
		if (props.rssi < 0) props.rssi = 0;
	} else {
		props.type = QMI_NAS_NETWORK_RAT_GSM;
		props.rssi = -1;
	}

	/* Bit error rate */
	ber = qmi_result_get(result, 0x15, &len);
	if (ber) {
		num = L_LE16_TO_CPU(ber->count);
		for (i = 0; i < ber->count; i++) {
			DBG("Bit error rate: %hu on RAT %hhd",
				L_LE16_TO_CPU(ber->info[i].rate),
				ber->info[i].rat);
		}

		props.ber = L_LE16_TO_CPU(ber->info[0].rate);
		if (props.ber > 7)
			props.ber = -1;
	} else {
		props.ber = -1;
	}

	/* LTE RSRQ */
	rsrq = qmi_result_get(result, 0x16, &len);
	if (rsrq) {
		DBG("RSRQ: %hhd on RAT %hhd",
			rsrq->value,
			rsrq->rat);

		if (rsrq->value == 0) {
			props.rsrq = -1;
		} else {
			props.rsrq = (rsrq->value + 19) * 2;
			if (props.rsrq > 34) props.rsrq = 34;
			if (props.rsrq < 0) props.rsrq = 0;
		}
	} else {
		props.rsrq = -1;
	}

	/* LTE RSRP */
	if (qmi_result_get_int16(result, 0x18, &rsrp)) {
		DBG("Got LTE RSRP: %hd", rsrp);

		if (rsrp == 0) {
			props.rsrp = -1;
		} else {
			props.rsrp = rsrp + 140;
			if (props.rsrp > 97) props.rsrp = 97;
			if (props.rsrp < 0) props.rsrp = 0;
		}
	} else {
		props.rsrp = -1;
	}

	ofono_netmon_serving_cell_notify(netmon,
				props.type,
				OFONO_NETMON_INFO_RSSI, props.rssi,
				OFONO_NETMON_INFO_BER, props.ber,
				OFONO_NETMON_INFO_RSRQ, props.rsrq,
				OFONO_NETMON_INFO_RSRP, props.rsrp,
				OFONO_NETMON_INFO_INVALID);

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void qmi_netmon_request_update(struct ofono_netmon *netmon,
					ofono_netmon_cb_t cb,
					void *user_data)
{
	struct netmon_data *data = ofono_netmon_get_data(netmon);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_param *param;

	DBG("");

	cbd->user = netmon;

	param = qmi_param_new();

	/* Request all signal strength items: mask=0xff */
	qmi_param_append_uint16(param, 0x10, 255);

	if (qmi_service_send(data->nas, QMI_NAS_GET_SIGNAL_STRENGTH, param,
					get_rssi_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
	CALLBACK_WITH_FAILURE(cb, cbd->data);
	l_free(cbd);
}

static int qmi_netmon_probe(struct ofono_netmon *netmon,
					unsigned int vendor, void *user_data)
{
	struct qmi_service *nas = user_data;
	struct netmon_data *nmd;

	DBG("");

	nmd = l_new(struct netmon_data, 1);
	nmd->nas = nas;

	ofono_netmon_set_data(netmon, nmd);

	return 0;
}

static void qmi_netmon_remove(struct ofono_netmon *netmon)
{
	struct netmon_data *nmd = ofono_netmon_get_data(netmon);

	DBG("");

	ofono_netmon_set_data(netmon, NULL);

	qmi_service_free(nmd->nas);
	l_free(nmd);
}

static const struct ofono_netmon_driver driver = {
	.flags			= OFONO_ATOM_DRIVER_FLAG_REGISTER_ON_PROBE,
	.probe			= qmi_netmon_probe,
	.remove			= qmi_netmon_remove,
	.request_update		= qmi_netmon_request_update,
};

OFONO_ATOM_DRIVER_BUILTIN(netmon, qmimodem, &driver)

/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 * Copyright (C) 2017  sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
#include <ofono/ussd.h>
#include <smsutil.h>
#include "qmi.h"
#include "util.h"
#include "voice.h"

struct ussd_data {
	struct qmi_service *voice;
};

static int validate_ussd_data(const struct qmi_ussd_data *data, uint16_t size)
{
	if (data == NULL)
		return 1;

	if (size < sizeof(*data))
		return 1;

	if (size < sizeof(*data) + data->length)
		return 1;

	if (data->dcs < QMI_USSD_DCS_ASCII || data->dcs > QMI_USSD_DCS_UCS2)
		return 1;

	return 0;
}

static int convert_qmi_dcs_gsm_dcs(int qmi_dcs, int *gsm_dcs)
{
	switch (qmi_dcs) {
	case QMI_USSD_DCS_ASCII:
		*gsm_dcs = USSD_DCS_8BIT;
		break;
	case QMI_USSD_DCS_8BIT:
		*gsm_dcs = USSD_DCS_8BIT;
		break;
	case QMI_USSD_DCS_UCS2:
		*gsm_dcs = USSD_DCS_UCS2;
		break;
	default:
		return 1;
	}

	return 0;
}

static void async_ind(struct qmi_result *result, void *user_data)
{
	struct ofono_ussd *ussd = user_data;
	const struct qmi_ussd_data *qmi_ussd;
	uint8_t user_action_required = 0;
	int notify_status = OFONO_USSD_STATUS_NOTIFY;
	uint16_t len;
	int gsm_dcs;

	DBG("");

	qmi_ussd = qmi_result_get(result, QMI_VOICE_PARAM_USSD_IND_DATA, &len);
	if (qmi_ussd == NULL)
		return;

	if (validate_ussd_data(qmi_ussd, len))
		goto error;

	if (convert_qmi_dcs_gsm_dcs(qmi_ussd->dcs, &gsm_dcs))
		goto error;

	if (qmi_result_get_uint8(result, QMI_VOICE_PARAM_USSD_IND_USER_ACTION,
					&user_action_required)) {
		if (user_action_required == QMI_USSD_USER_ACTION_REQUIRED)
			notify_status = OFONO_USSD_STATUS_ACTION_REQUIRED;
	}

	ofono_ussd_notify(ussd, notify_status, gsm_dcs,
				qmi_ussd->data, qmi_ussd->length);
	return;

error:
	ofono_ussd_notify(ussd, OFONO_USSD_STATUS_TERMINATED, 0, NULL, 0);
}

static void async_orig_ind(struct qmi_result *result, void *user_data)
{
	struct ofono_ussd *ussd = user_data;
	const struct qmi_ussd_data *qmi_ussd;
	uint16_t error = 0;
	uint16_t len;
	int gsm_dcs;

	DBG("");

	qmi_result_get_uint16(result, QMI_VOICE_PARAM_ASYNC_USSD_ERROR, &error);

	switch (error) {
	case 0:
		/* no error */
		break;
	case 92:
		qmi_result_get_uint16(result,
					QMI_VOICE_PARAM_ASYNC_USSD_FAILURE_CASE,
					&error);
		DBG("Failure Cause: 0x%04x", error);
		goto error;
	default:
		DBG("USSD Error 0x%04x", error);
		goto error;
	}

	qmi_ussd = qmi_result_get(result, QMI_VOICE_PARAM_ASYNC_USSD_DATA,
					&len);
	if (qmi_ussd == NULL)
		return;

	if (validate_ussd_data(qmi_ussd, len))
		goto error;

	if (convert_qmi_dcs_gsm_dcs(qmi_ussd->dcs, &gsm_dcs))
		goto error;

	ofono_ussd_notify(ussd, OFONO_USSD_STATUS_NOTIFY, gsm_dcs,
				qmi_ussd->data, qmi_ussd->length);
	return;

error:
	ofono_ussd_notify(ussd, OFONO_USSD_STATUS_TERMINATED, 0, NULL, 0);
}

static int qmi_ussd_probe(struct ofono_ussd *ussd,
				unsigned int vendor, void *user_data)
{
	struct qmi_service *voice = user_data;
	struct ussd_data *data;

	DBG("");

	data = l_new(struct ussd_data, 1);
	data->voice = voice;

	qmi_service_register(data->voice, QMI_VOICE_USSD_IND,
					async_ind, ussd, NULL);
	qmi_service_register(data->voice, QMI_VOICE_ASYNC_ORIG_USSD,
					async_orig_ind, ussd, NULL);


	ofono_ussd_set_data(ussd, data);

	return 0;
}

static void qmi_ussd_remove(struct ofono_ussd *ussd)
{
	struct ussd_data *data = ofono_ussd_get_data(ussd);

	DBG("");

	ofono_ussd_set_data(ussd, NULL);

	qmi_service_free(data->voice);
	l_free(data);
}

static void qmi_ussd_cancel(struct ofono_ussd *ussd,
				ofono_ussd_cb_t cb, void *user_data)
{
	struct ussd_data *ud = ofono_ussd_get_data(ussd);

	DBG("");

	if (qmi_service_send(ud->voice, QMI_VOICE_CANCEL_USSD, NULL,
					NULL, NULL, NULL) > 0)
		CALLBACK_WITH_SUCCESS(cb, user_data);
	else
		CALLBACK_WITH_FAILURE(cb, user_data);
}

/*
 * The cb is called when the request (on modem layer) reports success or
 * failure. It doesn't contain a network result. We get the network answer
 * via VOICE_IND.
 */
static void qmi_ussd_request_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_ussd_cb_t cb = cbd->cb;

	DBG("");

	qmi_result_print_tlvs(result);

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		return;
	}

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void qmi_ussd_request(struct ofono_ussd *ussd, int dcs,
			const unsigned char *pdu, int len,
			ofono_ussd_cb_t cb, void *data)
{
	struct ussd_data *ud = ofono_ussd_get_data(ussd);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct qmi_ussd_data *qmi_ussd;
	struct qmi_param *param;
	char *utf8 = NULL;
	long utf8_len = 0;

	DBG("");

	switch (dcs) {
	case 0xf: /* 7bit GSM unspecific */
		utf8 = ussd_decode(dcs, len, pdu);
		if (!utf8)
			goto error;

		utf8_len = strlen(utf8);
		break;
	default:
		DBG("Unsupported USSD Data Coding Scheme 0x%x", dcs);
		goto error;
	}

	/*
	 * So far only DCS_ASCII works.
	 * DCS_8BIT and DCS_UCS2 is broken, because the modem firmware
	 * (least on a EC20) encodes those in-correctly onto the air interface,
	 * resulting in wrong decoded USSD data.
	 */
	qmi_ussd = alloca(sizeof(struct qmi_ussd_data) + utf8_len);
	qmi_ussd->dcs = QMI_USSD_DCS_ASCII;
	qmi_ussd->length = len;
	memcpy(qmi_ussd->data, utf8, utf8_len);
	l_free(utf8);

	param = qmi_param_new();
	if (param == NULL)
		goto error;

	qmi_param_append(param, QMI_VOICE_PARAM_USS_DATA,
			sizeof(struct qmi_ussd_data) + utf8_len, qmi_ussd);

	if (qmi_service_send(ud->voice, QMI_VOICE_ASYNC_ORIG_USSD, param,
					qmi_ussd_request_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
error:
	l_free(cbd);
	CALLBACK_WITH_FAILURE(cb, data);
}

static const struct ofono_ussd_driver driver = {
	.flags		= OFONO_ATOM_DRIVER_FLAG_REGISTER_ON_PROBE,
	.probe		= qmi_ussd_probe,
	.remove		= qmi_ussd_remove,
	.request	= qmi_ussd_request,
	.cancel		= qmi_ussd_cancel
};

OFONO_ATOM_DRIVER_BUILTIN(ussd, qmimodem, &driver)

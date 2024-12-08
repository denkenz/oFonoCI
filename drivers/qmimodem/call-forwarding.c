/*
 * oFono - Open Source Telephony
 * Copyright (C) 2024 Ivaylo Dimitrov <ivo.g.dimitrov.75@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/call-forwarding.h>

#include "qmi.h"
#include "voice.h"
#include "util.h"

struct call_forwarding_data {
	struct qmi_service *voice;
};

struct call_forwarding_info {
	struct {
		int8_t active;
		uint8_t cls;
		uint8_t len;
		uint8_t number[];
	} i;
	uint8_t time;
} __attribute__((__packed__));

struct call_forwarding_info_ext {
	uint8_t active;
	uint8_t cls;
	uint8_t time;
	uint8_t pind;
	uint8_t sind;
	uint8_t type;
	uint8_t plan;
	uint8_t len;
	uint8_t number[];
} __attribute__((__packed__));

static int forw_type_to_reason(int type)
{
	switch (type) {
	case 0:
		return QMI_VOICE_SS_RSN_FWD_UNCONDITIONAL;
	case 1:
		return QMI_VOICE_SS_RSN_FWD_MOBILE_BUSY;
	case 2:
		return QMI_VOICE_SS_RSN_FWD_NO_REPLY;
	case 3:
		return QMI_VOICE_SS_RSN_FWD_UNREACHABLE;
	case 4:
		return QMI_VOICE_SS_RSN_FWD_ALL;
	case 5:
		return QMI_VOICE_SS_RSN_FWD_ALL_CONDITIONAL;
	default:
		DBG("Unknown forwarding type %d", type);
		return 0;
	}
}

static void set_fwd_cond(struct ofono_call_forwarding_condition *cond,
				int status, int cls, int time, int type,
				uint8_t *number, uint8_t nlen)
{
	uint8_t maxlen = OFONO_MAX_PHONE_NUMBER_LENGTH;

	cond->status = status;
	cond->cls = cls;
	cond->time = time;
	cond->phone_number.type = type;

	if (nlen < maxlen)
		maxlen = nlen;

	memcpy(&cond->phone_number.number, number, maxlen);
	cond->phone_number.number[maxlen] = 0;
}

static void query_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_call_forwarding_query_cb_t cb = cbd->cb;
	const uint8_t *p;
	uint8_t num;
	const uint8_t *end;
	uint16_t length;
	struct ofono_call_forwarding_condition *list = NULL;
	int i;
	bool extended = false;
	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto error;

	/*
	 * we want extended info if any, because of the number type.
	 */
	p = qmi_result_get(result, 0x16, &length);
	if (p && length)
		extended = true;
	else
		p = qmi_result_get(result, 0x10, &length);

	if (p && length)
		extended = false;
	else
		goto error;

	end = p + length;
	num = *p++;
	list = l_new(struct ofono_call_forwarding_condition, num);

	for (i = 0; i < num; i++) {
		if (extended) {
			struct call_forwarding_info_ext *fi = (void *)p;
			const uint8_t *iend = p + sizeof(*fi);
			int type;

			if (iend > end || iend + fi->len > end)
				goto error;

			type = fi->type == 1 ?
					OFONO_NUMBER_TYPE_INTERNATIONAL :
					OFONO_NUMBER_TYPE_UNKNOWN;
			set_fwd_cond(&list[i], fi->active, fi->cls,
					fi->time, type, fi->number, fi->len);

			p += sizeof(*fi) + fi->len;
		} else {
			struct call_forwarding_info *fi = (void *)p;
			const uint8_t *iend = p + sizeof(*fi);

			if (iend > end || iend + fi->i.len > end)
				goto error;

			set_fwd_cond(&list[i], fi->i.active, fi->i.cls,
					fi->time, OFONO_NUMBER_TYPE_UNKNOWN,
					fi->i.number, fi->i.len);
			p += sizeof(*fi) + fi->i.len;
		}
	}

	CALLBACK_WITH_SUCCESS(cb, num, list, cbd->data);
	l_free(list);
	return;

error:
	l_free(list);
	CALLBACK_WITH_FAILURE(cb, 0, NULL, cbd->data);
}

static void qmi_query(struct ofono_call_forwarding *cf, int type, int cls,
			ofono_call_forwarding_query_cb_t cb, void *data)
{
	struct call_forwarding_data *cfd = ofono_call_forwarding_get_data(cf);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct qmi_param *param;
	uint8_t reason = forw_type_to_reason(type);

	DBG("");

	if (!cfd || !reason)
		goto error;

	param = qmi_param_new();
	qmi_param_append_uint8(param, 0x01, reason);

	if (cls != 7 /* BEARER_CLASS_DEFAULT */)
		qmi_param_append_uint8(param, 0x10, cls);

	if (qmi_service_send(cfd->voice, QMI_VOICE_GET_CALL_FWDING, param,
				query_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
error:
	l_free(cbd);
	CALLBACK_WITH_FAILURE(cb, 0, NULL, data);
}

static void set_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_call_forwarding_set_cb_t cb = cbd->cb;

	DBG("");

	if (!qmi_result_set_error(result, NULL))
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	else
		CALLBACK_WITH_FAILURE(cb, cbd->data);
}

static void qmi_register(struct ofono_call_forwarding *cf, int type, int cls,
				const struct ofono_phone_number *ph, int time,
				ofono_call_forwarding_set_cb_t cb, void *data)
{
	struct call_forwarding_data *cfd = ofono_call_forwarding_get_data(cf);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct qmi_param *param;
	struct __attribute__((__packed__)) {
		uint8_t service;
		uint8_t reason;
	} ssd;
	struct __attribute__((__packed__)) {
		uint8_t type;
		uint8_t plan;
	} tpd;

	DBG("");

	ssd.reason = forw_type_to_reason(type);

	if (!cfd || !ssd.reason)
		goto error;

	ssd.service = QMI_VOICE_SS_ACTION_REGISTER;

	param = qmi_param_new();
	qmi_param_append(param, 0x01, sizeof(ssd), &ssd);

	if (cls != 7 /* BEARER_CLASS_DEFAULT */)
		qmi_param_append_uint8(param, 0x10, cls);

	qmi_param_append(param, 0x12, strlen(ph->number), ph->number);
	qmi_param_append_uint8(param, 0x13, time);

	tpd.type = ph->type == OFONO_NUMBER_TYPE_INTERNATIONAL ? 1 : 0;
	tpd.plan = tpd.type;
	qmi_param_append(param, 0x14, sizeof(tpd), &tpd);

	if (qmi_service_send(cfd->voice, QMI_VOICE_SET_SUPS_SERVICE, param,
				set_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
error:
	l_free(cbd);
	CALLBACK_WITH_FAILURE(cb, data);
}

static void qmi_set(struct ofono_call_forwarding *cf, int type, int cls,
			int service, ofono_call_forwarding_set_cb_t cb,
			void *data)
{
	struct call_forwarding_data *cfd = ofono_call_forwarding_get_data(cf);
	struct cb_data *cbd = cb_data_new(cb, data);
	struct qmi_param *param;
	struct __attribute__((__packed__)) {
		uint8_t service;
		uint8_t reason;
	} ssd;

	DBG("");

	ssd.reason = forw_type_to_reason(type);

	if (!cfd || !ssd.reason)
		goto error;

	ssd.service = service;

	param = qmi_param_new();
	qmi_param_append(param, 0x01, sizeof(ssd), &ssd);

	if (cls != 7 /* BEARER_CLASS_DEFAULT */)
		qmi_param_append_uint8(param, 0x10, cls);

	if (qmi_service_send(cfd->voice, QMI_VOICE_SET_SUPS_SERVICE, param,
				set_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);

error:
	l_free(cbd);
	CALLBACK_WITH_FAILURE(cb, data);
}

static void qmi_activate(struct ofono_call_forwarding *cf, int type, int cls,
				ofono_call_forwarding_set_cb_t cb, void *data)
{
	qmi_set(cf, type, cls, QMI_VOICE_SS_ACTION_ACTIVATE, cb, data);
}

static void qmi_deactivate(struct ofono_call_forwarding *cf, int type, int cls,
				ofono_call_forwarding_set_cb_t cb, void *data)
{
	qmi_set(cf, type, cls, QMI_VOICE_SS_ACTION_DEACTIVATE, cb, data);
}

static void qmi_erase(struct ofono_call_forwarding *cf, int type, int cls,
			ofono_call_forwarding_set_cb_t cb, void *data)
{
	qmi_set(cf, type, cls, QMI_VOICE_SS_ACTION_ERASE, cb, data);
}

static int qmi_call_forwarding_probe(struct ofono_call_forwarding *cf,
					unsigned int vendor, void *user_data)
{
	struct qmi_service *voice = user_data;
	struct call_forwarding_data *cfd;

	DBG("");

	cfd = l_new(struct call_forwarding_data, 1);
	cfd->voice = voice;

	ofono_call_forwarding_set_data(cf, cfd);

	return 0;
}

static void qmi_call_forwarding_remove(struct ofono_call_forwarding *cf)
{
	struct call_forwarding_data *cfd = ofono_call_forwarding_get_data(cf);

	DBG("");

	ofono_call_forwarding_set_data(cf, NULL);

	qmi_service_free(cfd->voice);
	l_free(cfd);
}

static const struct ofono_call_forwarding_driver driver = {
	.flags			= OFONO_ATOM_DRIVER_FLAG_REGISTER_ON_PROBE,
	.probe			= qmi_call_forwarding_probe,
	.remove			= qmi_call_forwarding_remove,
	.registration		= qmi_register,
	.activation		= qmi_activate,
	.query			= qmi_query,
	.deactivation		= qmi_deactivate,
	.erasure		= qmi_erase
};

OFONO_ATOM_DRIVER_BUILTIN(call_forwarding, qmimodem, &driver)

/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/sms.h>

#include "qmi.h"
#include "wms.h"
#include "util.h"

struct sms_data {
	struct qmi_service *wms;
	struct qmi_wms_read_msg_id rd_msg_id;
	struct qmi_wms_result_msg_list *msg_list;
	uint32_t rd_msg_num;
	uint8_t msg_mode;
	bool msg_mode_all;
	bool msg_list_chk;
};

static void get_msg_list(struct ofono_sms *sms);
static void raw_read(struct ofono_sms *sms, uint8_t type, uint32_t ndx);

static void get_smsc_addr_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_sca_query_cb_t cb = cbd->cb;
	struct ofono_phone_number sca;
	const struct qmi_wms_result_smsc_addr *smsc;
	uint16_t len;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
		return;
	}

	smsc = qmi_result_get(result, QMI_WMS_RESULT_SMSC_ADDR, &len);
	if (!smsc) {
		CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
		return;
	}

	if (!smsc->addr_len) {
		CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
		return;
	}

	if (smsc->addr[0] == '+') {
		strncpy(sca.number, smsc->addr + 1, smsc->addr_len - 1);
		sca.number[smsc->addr_len - 1] = '\0';
		sca.type = 145;
	} else {
		strncpy(sca.number, smsc->addr, smsc->addr_len);
		sca.number[smsc->addr_len] = '\0';
		sca.type = 129;
	}

	CALLBACK_WITH_SUCCESS(cb, &sca, cbd->data);
}

static void qmi_sca_query(struct ofono_sms *sms,
				ofono_sms_sca_query_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("");

	if (qmi_service_send(data->wms, QMI_WMS_GET_SMSC_ADDR, NULL,
					get_smsc_addr_cb, cbd, l_free) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);

	l_free(cbd);
}

static void set_smsc_addr_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_sca_set_cb_t cb = cbd->cb;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		return;
	}

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void qmi_sca_set(struct ofono_sms *sms,
				const struct ofono_phone_number *sca,
				ofono_sms_sca_set_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char type[4], number[OFONO_MAX_PHONE_NUMBER_LENGTH + 2];
	struct qmi_param *param;

	DBG("type %d name %s", sca->type, sca->number);

	switch (sca->type) {
	case 129:
		snprintf(number, sizeof(number), "%s", sca->number);
		break;
	case 145:
		snprintf(number, sizeof(number), "+%s", sca->number);
		break;
	default:
		goto error;
	}

	snprintf(type, sizeof(type), "%d", sca->type);

	param = qmi_param_new();

	qmi_param_append(param, QMI_WMS_PARAM_SMSC_ADDR,
						strlen(number), number);
	qmi_param_append(param, QMI_WMS_PARAM_SMSC_ADDR_TYPE,
						strlen(type), type);

	if (qmi_service_send(data->wms, QMI_WMS_SET_SMSC_ADDR, param,
					set_smsc_addr_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);

error:
	CALLBACK_WITH_FAILURE(cb, cbd->data);
	l_free(cbd);
}

static void raw_send_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_submit_cb_t cb = cbd->cb;
	uint16_t msgid;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	if (!qmi_result_get_uint16(result, QMI_WMS_RESULT_MESSAGE_ID, &msgid)) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	CALLBACK_WITH_SUCCESS(cb, msgid, cbd->data);
}

static void qmi_submit(struct ofono_sms *sms,
			const unsigned char *pdu, int pdu_len, int tpdu_len,
			int mms, ofono_sms_submit_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_wms_param_message *message;
	struct qmi_param *param;

	DBG("pdu_len %d tpdu_len %d mms %d", pdu_len, tpdu_len, mms);

	message = alloca(3 + pdu_len);

	message->msg_format = 0x06;
	message->msg_length = L_CPU_TO_LE16(pdu_len);
	memcpy(message->msg_data, pdu, pdu_len);

	param = qmi_param_new();

	qmi_param_append(param, QMI_WMS_PARAM_MESSAGE, 3 + pdu_len, message);

	if (qmi_service_send(data->wms, QMI_WMS_RAW_SEND, param,
					raw_send_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
	l_free(cbd);
}

static int domain_to_bearer(uint8_t domain)
{
	switch (domain) {
	case QMI_WMS_DOMAIN_CS_PREFERRED:
		return 3;
	case QMI_WMS_DOMAIN_PS_PREFERRED:
		return 2;
	case QMI_WMS_DOMAIN_CS_ONLY:
		return 1;
	case QMI_WMS_DOMAIN_PS_ONLY:
		return 0;
	}

	return -1;
}

static uint8_t bearer_to_domain(int bearer)
{
	switch (bearer) {
	case 0:
		return QMI_WMS_DOMAIN_PS_ONLY;
	case 1:
		return QMI_WMS_DOMAIN_CS_ONLY;
	case 2:
		return QMI_WMS_DOMAIN_PS_PREFERRED;
	case 3:
		return QMI_WMS_DOMAIN_CS_PREFERRED;
	}

	return QMI_WMS_DOMAIN_CS_PREFERRED;
}

static void get_domain_pref_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_bearer_query_cb_t cb = cbd->cb;
	uint8_t domain;
	int bearer;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	if (!qmi_result_get_uint8(result, QMI_WMS_RESULT_DOMAIN, &domain)) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	bearer = domain_to_bearer(domain);

	CALLBACK_WITH_SUCCESS(cb, bearer, cbd->data);
}

static void qmi_bearer_query(struct ofono_sms *sms,
				ofono_sms_bearer_query_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("");

	if (qmi_service_send(data->wms, QMI_WMS_GET_DOMAIN_PREF, NULL,
					get_domain_pref_cb, cbd, l_free) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
	l_free(cbd);
}

static void set_domain_pref_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_bearer_set_cb_t cb = cbd->cb;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		return;
	}

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void qmi_bearer_set(struct ofono_sms *sms, int bearer,
				ofono_sms_bearer_set_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_param *param;
	uint8_t domain;

	DBG("bearer %d", bearer);

	domain = bearer_to_domain(bearer);

	param = qmi_param_new_uint8(QMI_WMS_PARAM_DOMAIN, domain);

	if (qmi_service_send(data->wms, QMI_WMS_SET_DOMAIN_PREF, param,
					set_domain_pref_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);

	CALLBACK_WITH_FAILURE(cb, cbd->data);
	l_free(cbd);
}

static void delete_msg_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	uint16_t err;

	DBG("");

	if (qmi_result_set_error(result, &err))
		DBG("Err: delete %d - %s", err, qmi_result_get_error(result));

	/*
	 * Continue processing msg list. If error occurred, something
	 * serious happened, then don't bother.
	 */
	if (data->msg_list && data->msg_list_chk) {
		uint32_t msg = ++data->rd_msg_num;

		/*
		 * Get another msg. If list is empty check for more. Once query
		 * returns empty, rely on event indication to get new msgs.
		 */
		if (msg < data->msg_list->cnt)
			raw_read(sms, data->msg_list->msg[msg].type,
				L_LE32_TO_CPU(data->msg_list->msg[msg].ndx));
		else
			get_msg_list(sms);
	}
}

static void delete_msg(struct ofono_sms *sms, uint8_t tag)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct qmi_param *param;
	qmi_service_result_func_t func = NULL;

	DBG("");

	param = qmi_param_new();

	qmi_param_append_uint8(param, QMI_WMS_PARAM_DEL_STORE,
				QMI_WMS_STORAGE_TYPE_UIM);

	if (tag == QMI_WMS_MT_UNDEFINE) {
		DBG("delete read msg type %d ndx %d", data->rd_msg_id.type,
			data->rd_msg_id.ndx);

		/* delete 1 msg */
		qmi_param_append_uint32(param, QMI_WMS_PARAM_DEL_NDX,
					data->rd_msg_id.ndx);
		func = delete_msg_cb;
	} else {
		DBG("delete msg tag %d mode %d", tag, data->msg_mode);

		/* delete all msgs from 1 tag type */
		qmi_param_append_uint8(param, QMI_WMS_PARAM_DEL_TYPE, tag);
	}

	qmi_param_append_uint8(param, QMI_WMS_PARAM_DEL_MODE, data->msg_mode);

	if (qmi_service_send(data->wms, QMI_WMS_DELETE, param,
				func, sms, NULL) > 0)
		return;

	qmi_param_free(param);
	data->msg_list_chk = false;
}

static void raw_read_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	const struct qmi_wms_raw_message *msg;
	uint16_t err;

	DBG("");

	if (qmi_result_set_error(result, &err)) {
		DBG("Err: read %d - %s", err, qmi_result_get_error(result));
		data->msg_list_chk = false;
		return;
	}

	/* Raw message data */
	msg = qmi_result_get(result, QMI_WMS_RESULT_READ_MSG, NULL);
	if (msg) {
		uint16_t plen;
		uint16_t tpdu_len;

		plen = L_LE16_TO_CPU(msg->msg_length);
		tpdu_len = plen - msg->msg_data[0] - 1;

		ofono_sms_deliver_notify(sms, msg->msg_data, plen, tpdu_len);
	} else
		DBG("Err: no data in type %d ndx %d", data->rd_msg_id.type,
			data->rd_msg_id.ndx);

	/* delete read msg */
	delete_msg(sms, QMI_WMS_MT_UNDEFINE);
}

static void raw_read(struct ofono_sms *sms, uint8_t type, uint32_t ndx)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct qmi_param *param;

	DBG("");

	param = qmi_param_new();

	data->rd_msg_id.type = type;
	data->rd_msg_id.ndx = ndx;

	DBG("read type %d ndx %d", data->rd_msg_id.type, data->rd_msg_id.ndx);

	qmi_param_append(param, QMI_WMS_PARAM_READ_MSG,
				sizeof(data->rd_msg_id), &data->rd_msg_id);
	qmi_param_append_uint8(param, QMI_WMS_PARAM_READ_MODE, data->msg_mode);

	if (qmi_service_send(data->wms, QMI_WMS_RAW_READ, param,
				raw_read_cb, sms, NULL) > 0)
		return;

	qmi_param_free(param);
	data->msg_list_chk = false;
}

static void get_msg_list_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	const struct qmi_wms_result_msg_list *list;
	uint32_t cnt = 0;
	uint16_t tmp;
	uint16_t length;
	size_t msg_size;

	DBG("");

	if (qmi_result_set_error(result, &tmp)) {
		DBG("Err: get msg list mode=%d %d=%s", data->msg_mode, tmp,
			qmi_result_get_error(result));
		goto done;
	}

	list = qmi_result_get(result, QMI_WMS_RESULT_MSG_LIST, &length);
	if (list == NULL) {
		DBG("Err: get msg list empty");
		goto done;
	}

	cnt = L_LE32_TO_CPU(list->cnt);
	DBG("msgs found %d", cnt);

	msg_size = cnt * sizeof(list->msg[0]);

	if (length != sizeof(list->cnt) + msg_size) {
		DBG("Err: invalid msg list count");
		goto done;
	}

	for (tmp = 0; tmp < cnt; tmp++) {
		DBG("unread type %d ndx %d", list->msg[tmp].type,
			L_LE32_TO_CPU(list->msg[tmp].ndx));
	}

	/* free list from last time */
	if (data->msg_list) {
		l_free(data->msg_list);
		data->msg_list = NULL;
	}

	/* save list and get 1st msg */
	if (cnt) {
		data->msg_list = l_malloc(sizeof(list->cnt) + msg_size);
		data->msg_list->cnt = cnt;
		memcpy(data->msg_list->msg, list->msg, msg_size);

		data->rd_msg_num = 0;
		raw_read(sms, data->msg_list->msg[0].type,
				L_LE32_TO_CPU(data->msg_list->msg[0].ndx));
		return;
	}

done:
	data->msg_list_chk = false;

	/* if both protocols supported, check the other */
	if (data->msg_mode_all) {
		data->msg_mode_all = false;
		data->msg_mode = QMI_WMS_MESSAGE_MODE_GSMWCDMA;
		get_msg_list(sms);
	}
}

static void get_msg_list(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct qmi_param *param;

	DBG("");

	param = qmi_param_new();

	data->msg_list_chk = true;

	/* query NOT_READ msg list */
	qmi_param_append_uint8(param, QMI_WMS_PARAM_STORAGE_TYPE,
				QMI_WMS_STORAGE_TYPE_UIM);
	qmi_param_append_uint8(param, QMI_WMS_PARAM_TAG_TYPE,
				QMI_WMS_MT_NOT_READ);
	qmi_param_append_uint8(param, QMI_WMS_PARAM_MESSAGE_MODE,
				data->msg_mode);

	if (qmi_service_send(data->wms, QMI_WMS_GET_MSG_LIST, param,
				get_msg_list_cb, sms, NULL) > 0)
		return;

	data->msg_list_chk = false;
	qmi_param_free(param);
}

static void get_msg_protocol_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	uint16_t err;

	DBG("");

	if (qmi_result_set_error(result, &err)) {
		if (err != QMI_ERR_OP_DEVICE_UNSUPPORTED) {
			DBG("Err: protocol %d - %s",
					err, qmi_result_get_error(result));
			return;
		}

		/* Get Message Protocol operation is not supported */
		DBG("query both CDMA and WCDMA");
		data->msg_mode_all = true;
		data->msg_mode = QMI_WMS_MESSAGE_MODE_CDMA;
	} else {
		/* Query of current protocol succeeded, use that */
		qmi_result_get_uint8(result, QMI_WMS_PARAM_PROTOCOL,
					&data->msg_mode);

		DBG("msg_mode: %s", data->msg_mode ? "WCDMA" : "CDMA");
	}

	/* check for messages */
	get_msg_list(sms);
}

static void get_msg_protocol(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	DBG("");

	qmi_service_send(data->wms, QMI_WMS_GET_MSG_PROTOCOL, NULL,
				get_msg_protocol_cb, sms, NULL);
}

static void send_ack_cb(struct qmi_result *result, void *user_data)
{
	uint16_t err;

	DBG("");

	if (!qmi_result_set_error(result, &err))
		return;

	DBG("Err: protocol %d - %s",
			err, qmi_result_get_error(result));
}

static void send_ack(struct sms_data *data,
				const struct qmi_wms_result_message *message)
{
	struct __attribute__((__packed__)) {
		uint32_t transaction_id;
		uint8_t mode;
		uint8_t success;
	} ack;
	struct qmi_param *param;

	ack.transaction_id = message->transaction_id;
	ack.success = 1;

	if (message->msg_format == 0)
		ack.mode = QMI_WMS_MESSAGE_MODE_CDMA;
	else
		ack.mode = QMI_WMS_MESSAGE_MODE_GSMWCDMA;

	param = qmi_param_new();
	qmi_param_append(param, 0x01, sizeof(ack), &ack);

	if (qmi_service_send(data->wms, QMI_WMS_SEND_ACK, param,
				send_ack_cb, NULL, NULL) > 0)
		return;

	qmi_param_free(param);
}

static void event_notify(struct qmi_result *result, void *user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	const struct qmi_wms_result_new_msg_notify *notify;

	DBG("");

	/*
	 * The 2 types of MT message TLVs are mutually exclusive, depending on
	 * how the route action is configured. If action is store and notify,
	 * then the MT message TLV is sent. If action is transfer only or
	 * transfer and ack, then the transfer route MT message TLV is sent.
	 */
	notify = qmi_result_get(result, QMI_WMS_RESULT_NEW_MSG_NOTIFY, NULL);
	if (notify) {
		/* route is store and notify */
		if (!qmi_result_get_uint8(result, QMI_WMS_RESULT_MSG_MODE,
						&data->msg_mode))
			DBG("msg mode not found, use mode %d", data->msg_mode);

		DBG("msg type %d ndx %d mode %d", notify->storage_type,
			L_LE32_TO_CPU(notify->storage_index), data->msg_mode);

		/* don't read if list is being processed, get this msg later */
		if (!data->msg_list_chk)
			raw_read(sms, notify->storage_type,
					L_LE32_TO_CPU(notify->storage_index));
	} else {
		/* route is either transfer only or transfer and ACK */
		const struct qmi_wms_result_message *message;

		message = qmi_result_get(result, QMI_WMS_RESULT_MESSAGE, NULL);
		if (message) {
			uint16_t plen;

			plen = L_LE16_TO_CPU(message->msg_length);

			DBG("ack_required %d transaction id %u",
				message->ack_required,
				L_LE32_TO_CPU(message->transaction_id));
			DBG("msg format %d PDU length %d",
				message->msg_format, plen);

			if (message->ack_required == QMI_WMS_ACK_REQUIRED)
				send_ack(data, message);

			ofono_sms_deliver_notify(sms, message->msg_data,
							plen, plen);
		}
	}
}

static void set_routes_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	DBG("");

	ofono_sms_register(sms);

	/*
	 * Modem storage is limited. As a fail safe, delete processed messages
	 * to free device memory to prevent blockage of new messages.
	 */
	data->msg_mode = QMI_WMS_MESSAGE_MODE_CDMA;
	delete_msg(sms, QMI_WMS_MT_READ);
	delete_msg(sms, QMI_WMS_MO_SENT);
	data->msg_mode = QMI_WMS_MESSAGE_MODE_GSMWCDMA;
	delete_msg(sms, QMI_WMS_MT_READ);
	delete_msg(sms, QMI_WMS_MO_SENT);

	/*
	 * Subsystem initialized, now start process to check for unread
	 * messages. First, query msg protocol/mode. If modem supports both
	 * modes, then check messages for both modes since there's no way to
	 * query which mode is active.
	 */
	get_msg_protocol(sms);
}

static void get_routes_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	const struct qmi_wms_route_list *list;
	struct qmi_wms_route_list *new_list;
	struct qmi_param *param;
	uint16_t len, num, i;
	uint8_t value;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto done;

	list = qmi_result_get(result, QMI_WMS_RESULT_ROUTE_LIST, &len);
        if (!list)
		goto done;

	num = L_LE16_TO_CPU(list->count);

	DBG("found %d routes", num);

	for (i = 0; i < num; i++)
		DBG("type %d class %d => type %d value %d",
					list->route[i].msg_type,
					list->route[i].msg_class,
					list->route[i].storage_type,
					list->route[i].action);

	if (qmi_result_get_uint8(result, QMI_WMS_RESULT_STATUS_REPORT, &value))
		DBG("transfer status report %d", value);

	len = 2 + (1 * 4);
	new_list = alloca(len);

	new_list->count = L_CPU_TO_LE16(1);
	new_list->route[0].msg_type = QMI_WMS_MSG_TYPE_P2P;
	new_list->route[0].msg_class = QMI_WMS_MSG_CLASS_NONE;
	new_list->route[0].storage_type = QMI_WMS_STORAGE_TYPE_UIM;
	new_list->route[0].action = QMI_WMS_ACTION_STORE_AND_NOTIFY;

	param = qmi_param_new();

	qmi_param_append(param, QMI_WMS_PARAM_ROUTE_LIST, len, new_list);
	qmi_param_append_uint8(param, QMI_WMS_PARAM_STATUS_REPORT, 0x01);

        if (qmi_service_send(data->wms, QMI_WMS_SET_ROUTES, param,
                                        set_routes_cb, sms, NULL) > 0)
                return;

	qmi_param_free(param);

done:
	ofono_sms_register(sms);
}

static void set_event_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	DBG("");

	if (qmi_service_send(data->wms, QMI_WMS_GET_ROUTES, NULL,
					get_routes_cb, sms, NULL) > 0)
		return;

	ofono_sms_register(sms);
}

static int qmi_sms_probe(struct ofono_sms *sms,
				unsigned int vendor, void *user_data)
{
	struct qmi_service *wms = user_data;
	struct qmi_param *param;
	struct sms_data *data;

	DBG("");

	param = qmi_param_new_uint8(QMI_WMS_PARAM_NEW_MSG_REPORT, 0x01);

	if (!qmi_service_send(wms, QMI_WMS_SET_EVENT, param,
					set_event_cb, sms, NULL)) {
		qmi_param_free(param);
		qmi_service_free(wms);
		return -EIO;
	}

	data = l_new(struct sms_data, 1);
	data->wms = wms;
	memset(&data->rd_msg_id, 0, sizeof(data->rd_msg_id));
	data->msg_mode = QMI_WMS_MESSAGE_MODE_GSMWCDMA;
	qmi_service_register(data->wms, QMI_WMS_EVENT, event_notify, sms, NULL);

	ofono_sms_set_data(sms, data);

	return 0;
}

static void qmi_sms_remove(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	DBG("");

	ofono_sms_set_data(sms, NULL);

	if (data->msg_list)
		l_free(data->msg_list);

	qmi_service_free(data->wms);
	l_free(data);
}

static const struct ofono_sms_driver driver = {
	.probe		= qmi_sms_probe,
	.remove		= qmi_sms_remove,
	.sca_query	= qmi_sca_query,
	.sca_set	= qmi_sca_set,
	.submit		= qmi_submit,
	.bearer_query	= qmi_bearer_query,
	.bearer_set	= qmi_bearer_set,
};

OFONO_ATOM_DRIVER_BUILTIN(sms, qmimodem, &driver)

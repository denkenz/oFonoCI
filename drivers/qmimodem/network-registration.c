/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/netreg.h>

#include "qmi.h"
#include "nas.h"
#include "util.h"

#include "src/common.h"

struct netreg_data {
	struct qmi_service *nas;
	struct ofono_network_operator operator;
	uint8_t current_rat;
	int lac;
	int cellid;
	bool is_roaming;
};

enum roaming_status {
	ROAMING_STATUS_OFF,
	ROAMING_STATUS_ON,
	ROAMING_STATUS_NO_CHANGE,
};

static bool extract_ss_info_time(
		struct qmi_result *result,
		struct ofono_network_time *time)
{
	const struct qmi_nas_3gpp_time *time_3gpp = NULL;
	uint8_t dst_3gpp;
	bool dst_3gpp_valid;
	uint16_t len;

	/* parse 3gpp time & dst */
	dst_3gpp_valid = qmi_result_get_uint8(result, QMI_NAS_RESULT_3GGP_DST,
						&dst_3gpp);

	time_3gpp = qmi_result_get(result, QMI_NAS_RESULT_3GPP_TIME, &len);
	if (time_3gpp && len == sizeof(struct qmi_nas_3gpp_time) &&
			dst_3gpp_valid) {
		time->year = le16toh(time_3gpp->year);
		time->mon = time_3gpp->month;
		time->mday = time_3gpp->day;
		time->hour = time_3gpp->hour;
		time->min = time_3gpp->minute;
		time->sec = time_3gpp->second;
		time->utcoff = time_3gpp->timezone * 15 * 60;
		time->dst = dst_3gpp;
		return true;
	}

	/* TODO: 3gpp2 */

	return false;
}

static bool extract_ss_info(struct qmi_result *result, int *status,
				int *lac, int *cellid, int *tech,
				enum roaming_status *roaming,
				struct ofono_network_operator *operator)
{
	static const uint8_t RESULT_DATA_CAPABILITY_STATUS = 0x11;
	const struct qmi_nas_serving_system *ss;
	const struct qmi_nas_current_plmn *plmn;
	uint8_t i, roaming_status;
	uint16_t value16, len, opname_len;
	uint32_t value32;
	const void *dcs;

	DBG("");

	ss = qmi_result_get(result, QMI_NAS_RESULT_SERVING_SYSTEM, &len);
	if (!ss)
		return false;

	*status = ss->status;

	DBG("serving system status %d", ss->status);

	*tech = -1;

	for (i = ss->radio_if_count; i && *tech == -1; i--) {
		DBG("radio in use %d", ss->radio_if[i - 1]);

		*tech = qmi_nas_rat_to_tech(ss->radio_if[i - 1]);
	}

	*roaming = ROAMING_STATUS_NO_CHANGE;
	if (qmi_result_get_uint8(result, QMI_NAS_RESULT_ROAMING_STATUS,
							&roaming_status)) {
		if (roaming_status == 0)
			*roaming = ROAMING_STATUS_ON;
		else if (roaming_status == 1)
			*roaming = ROAMING_STATUS_OFF;
	}

	if (!operator)
		return true;

	plmn = qmi_result_get(result, QMI_NAS_RESULT_CURRENT_PLMN, &len);
	if (plmn) {
		uint16_t mcc = L_LE16_TO_CPU(plmn->mcc);
		uint16_t mnc = L_LE16_TO_CPU(plmn->mnc);

		if (mcc > 999)
			mcc = 999;

		if (mnc > 999)
			mnc = 999;

		snprintf(operator->mcc, OFONO_MAX_MCC_LENGTH + 1, "%03d", mcc);
		snprintf(operator->mnc, OFONO_MAX_MNC_LENGTH + 1, "%03d", mnc);

		opname_len = plmn->desc_len;
		if (opname_len > OFONO_MAX_OPERATOR_NAME_LENGTH)
			opname_len = OFONO_MAX_OPERATOR_NAME_LENGTH;

		/*
		 * Telit QMI modems can return non-utf-8 characters in
		 * plmn-desc. When that happens, libdbus will abort ofono.
		 * If non-utf-8 characters are detected, use mccmnc string.
		 */
		if (l_utf8_validate(plmn->desc, opname_len, NULL)) {
			strncpy(operator->name, plmn->desc, opname_len);
			operator->name[opname_len] = '\0';
		} else
			snprintf(operator->name, OFONO_MAX_OPERATOR_NAME_LENGTH,
					"%s%s",	operator->mcc, operator->mnc);

		DBG("%s (%s:%s)", operator->name, operator->mcc, operator->mnc);
	}

	dcs = qmi_result_get(result, RESULT_DATA_CAPABILITY_STATUS, &len);
	if (dcs) {
		_auto_(l_strv_free) char **techs =
			qmi_nas_data_capability_status_to_string_list(dcs, len);

		if (techs) {
			_auto_(l_free) char *joined =
						l_strjoinv(techs, ',');

			DBG("radio techs in use: %s", joined);
		}
	}

	if (qmi_result_get_uint16(result, QMI_NAS_RESULT_LOCATION_AREA_CODE,
								&value16))
		*lac = value16;
	else
		*lac = -1;

	if (qmi_result_get_uint32(result, QMI_NAS_RESULT_CELL_ID, &value32))
		*cellid = value32;
	else
		*cellid = -1;

	DBG("roaming %u lac %d cellid %d tech %d", *roaming, *lac, *cellid,
									*tech);

	return true;
}

static int remember_ss_info(struct netreg_data *data, int status, int lac,
					int cellid, enum roaming_status roaming)
{
	if (roaming == ROAMING_STATUS_ON)
		data->is_roaming = true;
	else if (roaming == ROAMING_STATUS_OFF)
		data->is_roaming = false;

	if (status == QMI_NAS_REGISTRATION_STATE_REGISTERED) {
		if (lac >= 0)
			data->lac = lac;
		if (cellid >= 0)
			data->cellid = cellid;
	} else {
		data->lac = -1;
		data->cellid = -1;
	}

	if (status == QMI_NAS_REGISTRATION_STATE_REGISTERED &&
							data->is_roaming)
		status = NETWORK_REGISTRATION_STATUS_ROAMING;

	return status;
}

static void ss_info_notify(struct qmi_result *result, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct ofono_network_time net_time;
	struct netreg_data *data = ofono_netreg_get_data(netreg);
	int status, lac, cellid, tech;
	enum roaming_status roaming;

	DBG("");

	if (extract_ss_info_time(result, &net_time))
		ofono_netreg_time_notify(netreg, &net_time);

	if (!extract_ss_info(result, &status, &lac, &cellid, &tech, &roaming,
							&data->operator))
		return;

	status = remember_ss_info(data, status, lac, cellid, roaming);

	ofono_netreg_status_notify(netreg, status, data->lac, data->cellid,
									tech);
}

static void get_ss_info_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_status_cb_t cb = cbd->cb;
	struct netreg_data *data = cbd->user;
	int status, lac, cellid, tech;
	enum roaming_status roaming;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, cbd->data);
		return;
	}

	if (!extract_ss_info(result, &status, &lac, &cellid, &tech, &roaming,
							&data->operator)) {
		CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, cbd->data);
		return;
	}

	status = remember_ss_info(data, status, lac, cellid, roaming);

	CALLBACK_WITH_SUCCESS(cb, status, data->lac, data->cellid, tech,
								cbd->data);
}

static void qmi_registration_status(struct ofono_netreg *netreg,
				ofono_netreg_status_cb_t cb, void *user_data)
{
	struct netreg_data *data = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("");

	cbd->user = data;

	if (qmi_service_send(data->nas, QMI_NAS_GET_SERVING_SYSTEM, NULL,
					get_ss_info_cb, cbd, l_free) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, cbd->data);

	l_free(cbd);
}

static void qmi_current_operator(struct ofono_netreg *netreg,
				ofono_netreg_operator_cb_t cb, void *user_data)
{
	struct netreg_data *data = ofono_netreg_get_data(netreg);

	DBG("");

	CALLBACK_WITH_SUCCESS(cb, &data->operator, user_data);
}

static void scan_nets_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_operator_list_cb_t cb = cbd->cb;
	struct ofono_network_operator *list;
	const struct qmi_nas_network_list *netlist;
	const struct qmi_nas_network_rat *netrat;
	const void *ptr;
	uint16_t len, num, offset, i;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, 0, NULL, cbd->data);
		return;
	}

	ptr = qmi_result_get(result, QMI_NAS_RESULT_NETWORK_LIST, &len);
	if (!ptr) {
		CALLBACK_WITH_FAILURE(cb, 0, NULL, cbd->data);
		return;
	}

	netlist = ptr;

	num = L_LE16_TO_CPU(netlist->count);
	DBG("found %d operators", num);
	offset = 2;

	list = l_new(struct ofono_network_operator, num);

	for (i = 0; i < num; i++) {
		const struct qmi_nas_network_info *netinfo = ptr + offset;
		uint16_t mcc = L_LE16_TO_CPU(netinfo->mcc);
		uint16_t mnc = L_LE16_TO_CPU(netinfo->mnc);

		if (mcc > 999)
			mcc = 999;

		if (mnc > 999)
			mnc = 999;

		snprintf(list[i].mcc, OFONO_MAX_MCC_LENGTH + 1, "%03d", mcc);
		snprintf(list[i].mnc, OFONO_MAX_MNC_LENGTH + 1, "%03d", mnc);
		strncpy(list[i].name, netinfo->desc, netinfo->desc_len);
		list[i].name[netinfo->desc_len] = '\0';

		if (netinfo->status & 0x10)
			list[i].status = 3;
		else if (netinfo->status & 0x01)
			list[i].status = 2;
		else if (netinfo->status & 0x02)
			list[i].status = 1;
		else
			list[i].status = 0;

		list[i].tech = -1;

		DBG("%s (%s:%s) status %d", list[i].name,
				list[i].mcc, list[i].mnc, list[i].status);

		offset += sizeof(struct qmi_nas_network_info) +
							netinfo->desc_len;
	}

	netrat = qmi_result_get(result, QMI_NAS_RESULT_NETWORK_RAT, &len);
	if (!netrat)
		goto done;

	if (L_LE16_TO_CPU(netrat->count) != num)
		goto done;

	for (i = 0; i < num; i++) {
		DBG("%03d:%02d %d", netrat->info[i].mcc, netrat->info[i].mnc,
							netrat->info[i].rat);

		list[i].tech = qmi_nas_rat_to_tech(netrat->info[i].rat);
	}

done:
	CALLBACK_WITH_SUCCESS(cb, num, list, cbd->data);

	l_free(list);
}

static void qmi_list_operators(struct ofono_netreg *netreg,
			ofono_netreg_operator_list_cb_t cb, void *user_data)
{
	struct netreg_data *data = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("");

	if (qmi_service_send(data->nas, QMI_NAS_NETWORK_SCAN, NULL,
					scan_nets_cb, cbd, l_free) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, 0, NULL, cbd->data);

	l_free(cbd);
}

static void register_net_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_register_cb_t cb = cbd->cb;
	uint16_t error;
	int cme_error;

	DBG("");

	if (qmi_result_set_error(result, &error)) {
		if (error == 26) {
			/* no effect */
			goto done;
		}

		cme_error = qmi_error_to_ofono_cme(error);
		CALLBACK_WITH_CME_ERROR(cb, cme_error, cbd->data);
		return;
	}

done:
	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void qmi_register_auto(struct ofono_netreg *netreg,
				ofono_netreg_register_cb_t cb, void *user_data)
{
	struct netreg_data *data = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_param *param;

	DBG("");

	param = qmi_param_new_uint8(QMI_NAS_PARAM_REGISTER_ACTION,
					QMI_NAS_REGISTER_ACTION_AUTO);

	if (qmi_service_send(data->nas, QMI_NAS_NETWORK_REGISTER, param,
					register_net_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
	CALLBACK_WITH_FAILURE(cb, cbd->data);
	l_free(cbd);
}

static void qmi_register_manual(struct ofono_netreg *netreg,
				const char *mcc, const char *mnc,
				ofono_netreg_register_cb_t cb, void *user_data)
{
	struct netreg_data *data = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_nas_param_register_manual_info info;
	struct qmi_param *param;

	DBG("");

	param = qmi_param_new_uint8(QMI_NAS_PARAM_REGISTER_ACTION,
					QMI_NAS_REGISTER_ACTION_MANUAL);

	info.mcc = atoi(mcc);
	info.mnc = atoi(mnc);
	info.rat = QMI_NAS_NETWORK_RAT_NO_CHANGE;

	qmi_param_append(param, QMI_NAS_PARAM_REGISTER_MANUAL_INFO,
						sizeof(info), &info);

	if (qmi_service_send(data->nas, QMI_NAS_NETWORK_REGISTER, param,
					register_net_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
	CALLBACK_WITH_FAILURE(cb, cbd->data);
	l_free(cbd);
}

static int dbm_to_strength(int8_t dbm)
{
	if (dbm > -55)
		return 100;
	else if (dbm > -65)
		return 80;
	else if (dbm > -75)
		return 60;
	else if (dbm > -85)
		return 40;
	else if (dbm > -95)
		return 20;
	else if (dbm > -105)
		return 0;

	return -1;
}

static void get_rssi_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_strength_cb_t cb = cbd->cb;
	const struct qmi_nas_signal_strength *ss;
	uint16_t len;
	int strength;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	ss = qmi_result_get(result, QMI_NAS_RESULT_SIGNAL_STRENGTH, &len);
	if (!ss) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	DBG("signal with %d dBm on %d", ss->dbm, ss->rat);

	strength = dbm_to_strength(ss->dbm);

	CALLBACK_WITH_SUCCESS(cb, strength, cbd->data);
}

static void qmi_signal_strength(struct ofono_netreg *netreg,
				ofono_netreg_strength_cb_t cb, void *user_data)
{
	struct netreg_data *data = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("");

	if (qmi_service_send(data->nas, QMI_NAS_GET_SIGNAL_STRENGTH, NULL,
					get_rssi_cb, cbd, l_free) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);

	l_free(cbd);
}

static void system_info_notify(struct qmi_result *result, void *user_data)
{
	DBG("");

	qmi_result_print_tlvs(result);
}

static void signal_info_notify(struct qmi_result *result, void *user_data)
{
	DBG("");

	qmi_result_print_tlvs(result);
}

static void event_notify(struct qmi_result *result, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *data = ofono_netreg_get_data(netreg);
	const struct qmi_nas_signal_strength *ss;
	const struct qmi_nas_rf_info *rf;
	uint16_t len;

	DBG("");

	ss = qmi_result_get(result, QMI_NAS_NOTIFY_SIGNAL_STRENGTH, &len);
        if (ss) {
		int strength;

		strength = dbm_to_strength(ss->dbm);

		DBG("signal with %d%%(%d dBm) on %d",
				strength, ss->dbm, ss->rat);

		ofono_netreg_strength_notify(netreg, strength);
	}

	rf = qmi_result_get(result, QMI_NAS_NOTIFY_RF_INFO, &len);
	if (rf) {
		uint8_t i;

		for (i = 0; i < rf->count; i++) {
			DBG("rat %d band %d channel %d", rf->info[i].rat,
					rf->info[i].band, rf->info[i].channel);
		}

		data->current_rat = rf->info[i].rat;
	}
}

static void register_indications_cb(struct qmi_result *result,
							void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *data = ofono_netreg_get_data(netreg);

	if (qmi_result_set_error(result, NULL)) {
		ofono_netreg_remove(netreg);
		return;
	}

	ofono_netreg_register(netreg);

	qmi_service_register(data->nas, QMI_NAS_EVENT_REPORT,
					event_notify, netreg, NULL);

	qmi_service_register(data->nas, QMI_NAS_SERVING_SYSTEM_INDICATION,
					ss_info_notify, netreg, NULL);

	qmi_service_register(data->nas, QMI_NAS_SYSTEM_INFO_INDICATION,
					system_info_notify, netreg, NULL);

	qmi_service_register(data->nas, QMI_NAS_SIGNAL_INFO_INDICATION,
					signal_info_notify, netreg, NULL);
}

static void set_event_report_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *data = ofono_netreg_get_data(netreg);
	static const uint8_t PARAM_SERVING_SYSTEM_EVENTS = 0x13;
	static const uint8_t PARAM_SYSTEM_INFO = 0x18;
	static const uint8_t PARAM_SIGNAL_INFO = 0x19;
	struct qmi_param *param;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto error;

	param = qmi_param_new();

	qmi_param_append_uint8(param, PARAM_SERVING_SYSTEM_EVENTS, 0x01);
	qmi_param_append_uint8(param, PARAM_SYSTEM_INFO, 0x01);
	qmi_param_append_uint8(param, PARAM_SIGNAL_INFO, 0x01);

	if (qmi_service_send(data->nas, QMI_NAS_REGISTER_INDICATIONS, param,
				register_indications_cb, netreg, NULL) > 0)
		return;

	qmi_param_free(param);
error:
	ofono_netreg_remove(netreg);
}

static int qmi_netreg_probe(struct ofono_netreg *netreg,
				unsigned int vendor, void *user_data)
{
	struct qmi_service *nas = user_data;
	struct qmi_param *param;
	static const uint8_t PARAM_REPORT_SIGNAL_STRENGTH = 0x10;
	static const uint8_t PARAM_REPORT_RF_INFO = 0x11;
	struct {
		uint8_t report;					/* bool */
		uint8_t count;
		int8_t dbm[5];
	} __attribute__((__packed__)) ss = { .report = 0x01,
			.count = 5, .dbm[0] = -55, .dbm[1] = -65,
			.dbm[2] = -75, .dbm[3] = -85, .dbm[4] = -95 };
	struct netreg_data *data;

	DBG("");

	param = qmi_param_new();
	qmi_param_append(param, PARAM_REPORT_SIGNAL_STRENGTH, sizeof(ss), &ss);
	qmi_param_append_uint8(param, PARAM_REPORT_RF_INFO, 0x01);

	if (!qmi_service_send(nas, QMI_NAS_SET_EVENT_REPORT, param,
					set_event_report_cb, netreg, NULL)) {
		qmi_param_free(param);
		qmi_service_free(nas);
		return -EIO;
	}

	data = l_new(struct netreg_data, 1);
	data->nas = nas;
	data->operator.name[0] = '\0';
	data->operator.mcc[0] = '\0';
	data->operator.mnc[0] = '\0';
	data->operator.status = -1;
	data->operator.tech = -1;
	data->current_rat = QMI_NAS_NETWORK_RAT_NO_CHANGE;
	data->is_roaming = false;
	data->lac = -1;
	data->cellid = -1;

	ofono_netreg_set_data(netreg, data);

	return 0;
}

static void qmi_netreg_remove(struct ofono_netreg *netreg)
{
	struct netreg_data *data = ofono_netreg_get_data(netreg);

	DBG("");

	ofono_netreg_set_data(netreg, NULL);

	qmi_service_free(data->nas);
	l_free(data);
}

static const struct ofono_netreg_driver driver = {
	.probe			= qmi_netreg_probe,
	.remove			= qmi_netreg_remove,
	.registration_status	= qmi_registration_status,
	.current_operator	= qmi_current_operator,
	.list_operators		= qmi_list_operators,
	.register_auto		= qmi_register_auto,
	.register_manual	= qmi_register_manual,
	.strength		= qmi_signal_strength,
};

OFONO_ATOM_DRIVER_BUILTIN(netreg, qmimodem, &driver)

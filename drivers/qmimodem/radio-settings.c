/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/radio-settings.h>

#include "qmi.h"
#include "nas.h"
#include "dms.h"
#include "util.h"

struct settings_data {
	struct qmi_service *nas;
	struct qmi_service *dms;
	unsigned int rat_mode_any;
};

static void get_system_selection_pref_cb(struct qmi_result *result,
							void* user_data)
{
	struct cb_data *cbd = user_data;
	ofono_radio_settings_rat_mode_query_cb_t cb = cbd->cb;
	unsigned int mode = OFONO_RADIO_ACCESS_MODE_ANY;
	uint16_t pref;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	qmi_result_get_uint16(result,
			QMI_NAS_RESULT_SYSTEM_SELECTION_PREF_MODE, &pref);

	switch (pref) {
	case QMI_NAS_RAT_MODE_PREF_GSM:
		mode = OFONO_RADIO_ACCESS_MODE_GSM;
		break;
	case QMI_NAS_RAT_MODE_PREF_UMTS:
		mode = OFONO_RADIO_ACCESS_MODE_UMTS;
		break;
	case QMI_NAS_RAT_MODE_PREF_LTE:
		mode = OFONO_RADIO_ACCESS_MODE_LTE;
		break;
	case QMI_NAS_RAT_MODE_PREF_GSM|QMI_NAS_RAT_MODE_PREF_LTE:
		mode = OFONO_RADIO_ACCESS_MODE_GSM|OFONO_RADIO_ACCESS_MODE_LTE;
		break;
	}

	CALLBACK_WITH_SUCCESS(cb, mode, cbd->data);
}

static void qmi_query_rat_mode(struct ofono_radio_settings *rs,
			ofono_radio_settings_rat_mode_query_cb_t cb,
			void *user_data)
{
	struct settings_data *data = ofono_radio_settings_get_data(rs);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("");

	if (qmi_service_send(data->nas,
				QMI_NAS_GET_SYSTEM_SELECTION_PREFERENCE, NULL,
				get_system_selection_pref_cb, cbd, l_free) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, -1, data);
}

static void set_system_selection_pref_cb(struct qmi_result *result,
							void* user_data)
{
	struct cb_data *cbd = user_data;
	ofono_radio_settings_rat_mode_set_cb_t cb = cbd->cb;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		return;
	}

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void qmi_set_rat_mode(struct ofono_radio_settings *rs, unsigned int mode,
			ofono_radio_settings_rat_mode_set_cb_t cb,
			void *user_data)
{
	struct settings_data *data = ofono_radio_settings_get_data(rs);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	uint16_t pref = 0;
	struct qmi_param *param;

	DBG("");

	if (mode == OFONO_RADIO_ACCESS_MODE_ANY)
		pref = data->rat_mode_any;
	else {
		if (mode & OFONO_RADIO_ACCESS_MODE_GSM)
			pref |= QMI_NAS_RAT_MODE_PREF_GSM;

		if (mode & OFONO_RADIO_ACCESS_MODE_UMTS)
			pref |= QMI_NAS_RAT_MODE_PREF_UMTS;

		if (mode & OFONO_RADIO_ACCESS_MODE_LTE)
			pref |= QMI_NAS_RAT_MODE_PREF_LTE;
	}

	param = qmi_param_new();

	qmi_param_append_uint16(param, QMI_NAS_PARAM_SYSTEM_SELECTION_PREF_MODE,
			pref);

	if (qmi_service_send(data->nas,
				QMI_NAS_SET_SYSTEM_SELECTION_PREFERENCE, param,
				set_system_selection_pref_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
	CALLBACK_WITH_FAILURE(cb, user_data);
	l_free(cbd);
}

static unsigned int _update_available_rats(struct settings_data *rsd,
					const struct qmi_dms_device_caps *caps)
{
	unsigned int available_rats = 0;
	uint8_t i;

	rsd->rat_mode_any = 0;

	for (i = 0; i < caps->radio_if_count; i++) {
		switch (caps->radio_if[i]) {
		case QMI_DMS_RADIO_IF_GSM:
			available_rats |= OFONO_RADIO_ACCESS_MODE_GSM;
			rsd->rat_mode_any |= QMI_NAS_RAT_MODE_PREF_GSM;
			break;
		case QMI_DMS_RADIO_IF_UMTS:
			rsd->rat_mode_any |= QMI_NAS_RAT_MODE_PREF_UMTS;
			available_rats |= OFONO_RADIO_ACCESS_MODE_UMTS;
			break;
		case QMI_DMS_RADIO_IF_LTE:
			available_rats |= OFONO_RADIO_ACCESS_MODE_LTE;
			rsd->rat_mode_any |= QMI_NAS_RAT_MODE_PREF_LTE;
			break;
		}
	}

	return available_rats;
}

static void get_caps_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_radio_settings *rs = cbd->user;
	struct settings_data *rsd = ofono_radio_settings_get_data(rs);
	ofono_radio_settings_available_rats_query_cb_t cb = cbd->cb;
	const struct qmi_dms_device_caps *caps;
	uint16_t len;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto error;

	caps = qmi_result_get(result, QMI_DMS_RESULT_DEVICE_CAPS, &len);
	if (!caps)
		goto error;

	CALLBACK_WITH_SUCCESS(cb, _update_available_rats(rsd, caps), cbd->data);

	return;

error:
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
}

static void qmi_query_available_rats(struct ofono_radio_settings *rs,
			ofono_radio_settings_available_rats_query_cb_t cb,
			void *data)
{
	struct settings_data *rsd = ofono_radio_settings_get_data(rs);
	struct cb_data *cbd = cb_data_new(cb, data);

	if (!rsd->dms)
		goto error;

	cbd->user = rs;

	if (qmi_service_send(rsd->dms, QMI_DMS_GET_CAPS, NULL,
					get_caps_cb, cbd, l_free) > 0)
		return;

error:
	l_free(cbd);
	CALLBACK_WITH_FAILURE(cb, -1, data);
}

static void get_rat_mode_any_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_radio_settings *rs = user_data;
	struct settings_data *rsd = ofono_radio_settings_get_data(rs);
	const struct qmi_dms_device_caps *caps;
	uint16_t len;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto error;

	caps = qmi_result_get(result, QMI_DMS_RESULT_DEVICE_CAPS, &len);
	if (!caps)
		goto error;

	_update_available_rats(rsd, caps);
	ofono_radio_settings_register(rs);

	return;

error:
	ofono_error("Failed to get RAT modes");
	ofono_radio_settings_remove(rs);
}

static int qmi_radio_settings_probev(struct ofono_radio_settings *rs,
					unsigned int vendor, va_list args)
{
	struct qmi_service *dms = va_arg(args, struct qmi_service *);
	struct qmi_service *nas = va_arg(args, struct qmi_service *);
	struct settings_data *data;

	DBG("");

	if (!qmi_service_send(dms, QMI_DMS_GET_CAPS, NULL,
					get_rat_mode_any_cb, rs, NULL)) {
		qmi_service_free(dms);
		qmi_service_free(nas);
		return -EIO;
	}

	data = l_new(struct settings_data, 1);
	data->dms = dms;
	data->nas = nas;

	ofono_radio_settings_set_data(rs, data);

	return 0;
}

static void qmi_radio_settings_remove(struct ofono_radio_settings *rs)
{
	struct settings_data *data = ofono_radio_settings_get_data(rs);

	DBG("");

	ofono_radio_settings_set_data(rs, NULL);

	qmi_service_free(data->dms);
	qmi_service_free(data->nas);

	l_free(data);
}

static const struct ofono_radio_settings_driver driver = {
	.probev		= qmi_radio_settings_probev,
	.remove		= qmi_radio_settings_remove,
	.set_rat_mode	= qmi_set_rat_mode,
	.query_rat_mode = qmi_query_rat_mode,
	.query_available_rats = qmi_query_available_rats,
};

OFONO_ATOM_DRIVER_BUILTIN(radio_settings, qmimodem, &driver)

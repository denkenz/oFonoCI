/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/location-reporting.h>

#include "qmi.h"
#include "pds.h"
#include "util.h"

struct location_data {
	struct qmi_service *pds;
	int fd;
};

static void event_notify(struct qmi_result *result, void *user_data)
{
	struct ofono_location_reporting *lr = user_data;
	struct location_data *data = ofono_location_reporting_get_data(lr);
	const void *ptr;
	uint16_t len;
	ssize_t written;

	DBG("");

	if (data->fd < 0)
		return;

	ptr = qmi_result_get(result, QMI_PDS_NOTIFY_NMEA, &len);
	if (ptr) {
		written = write(data->fd, ptr, len);
		if (written < 0)
			ofono_warn("Failed to write NMEA data");
	}

	ptr = qmi_result_get(result, QMI_PDS_NOTIFY_NMEA_DEBUG, &len);
	if (ptr) {
		written = write(data->fd, ptr, len);
		if (written < 0)
			ofono_warn("Failed to write NMEA debug");
	}
}

static void state_notify(struct qmi_result *result, void *user_data)
{
	DBG("");
}

static int enable_data_stream(struct ofono_location_reporting *lr)
{
	struct location_data *data = ofono_location_reporting_get_data(lr);
	int pipefd[2];

	DBG("");

	if (pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) < 0)
		return -1;

	data->fd = pipefd[1];

	return pipefd[0];
}

static void disable_data_stream(struct ofono_location_reporting *lr)
{
	struct location_data *data = ofono_location_reporting_get_data(lr);

	DBG("");

	close(data->fd);
	data->fd = -1;
}

static void autotrack_enable_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_location_reporting_enable_cb_t cb = cbd->cb;
	struct ofono_location_reporting *lr = cbd->user;
	int fd;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	fd = enable_data_stream(lr);
	if (fd < 0) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	CALLBACK_WITH_SUCCESS(cb, fd, cbd->data);

	close(fd);
}

static void qmi_location_reporting_enable(struct ofono_location_reporting *lr,
		ofono_location_reporting_enable_cb_t cb, void *user_data)
{
	struct location_data *data = ofono_location_reporting_get_data(lr);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_param *param;

	DBG("");

	cbd->user = lr;

	param = qmi_param_new_uint8(QMI_PDS_PARAM_AUTO_TRACKING, 0x01);

	if (qmi_service_send(data->pds, QMI_PDS_SET_AUTOTRACK, param,
					autotrack_enable_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
	l_free(cbd);
}

static void autotrack_disable_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_location_reporting_disable_cb_t cb = cbd->cb;
	struct ofono_location_reporting *lr = cbd->user;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		return;
	}

	disable_data_stream(lr);

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void qmi_location_reporting_disable(struct ofono_location_reporting *lr,
		ofono_location_reporting_disable_cb_t cb, void *user_data)
{
	struct location_data *data = ofono_location_reporting_get_data(lr);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_param *param;

	DBG("");

	cbd->user = lr;

	param = qmi_param_new_uint8(QMI_PDS_PARAM_AUTO_TRACKING, 0x00);

	if (qmi_service_send(data->pds, QMI_PDS_SET_AUTOTRACK, param,
					autotrack_disable_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);
	CALLBACK_WITH_FAILURE(cb, cbd->data);
	l_free(cbd);
}

static void set_event_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_location_reporting *lr = user_data;
	struct location_data *data = ofono_location_reporting_get_data(lr);

	DBG("");

	qmi_service_register(data->pds, QMI_PDS_EVENT,
					event_notify, lr, NULL);
	qmi_service_register(data->pds, QMI_PDS_STATE_IND,
					state_notify, lr, NULL);

	ofono_location_reporting_register(lr);
}

static int qmi_location_reporting_probe(struct ofono_location_reporting *lr,
					unsigned int vendor, void *user_data)
{
	struct qmi_service *pds = user_data;
	struct location_data *data;
	struct qmi_param *param;

	DBG("");

	param = qmi_param_new();
	qmi_param_append_uint8(param, QMI_PDS_PARAM_REPORT_NMEA, 0x01);
	qmi_param_append_uint8(param, QMI_PDS_PARAM_REPORT_NMEA_DEBUG, 0x00);

	if (!qmi_service_send(pds, QMI_PDS_SET_EVENT, param,
					set_event_cb, lr, NULL)) {
		qmi_param_free(param);
		qmi_service_free(pds);
		return -EIO;
	}

	data = l_new(struct location_data, 1);
	data->pds = pds;
	data->fd = -1;

	ofono_location_reporting_set_data(lr, data);

	return 0;
}

static void qmi_location_reporting_remove(struct ofono_location_reporting *lr)
{
	struct location_data *data = ofono_location_reporting_get_data(lr);

	DBG("");

	ofono_location_reporting_set_data(lr, NULL);

	qmi_service_free(data->pds);
	l_free(data);
}

static const struct ofono_location_reporting_driver driver = {
	.type		= OFONO_LOCATION_REPORTING_TYPE_NMEA,
	.probe		= qmi_location_reporting_probe,
	.remove		= qmi_location_reporting_remove,
	.enable		= qmi_location_reporting_enable,
	.disable	= qmi_location_reporting_disable,
};

OFONO_ATOM_DRIVER_BUILTIN(location_reporting, qmimodem, &driver)

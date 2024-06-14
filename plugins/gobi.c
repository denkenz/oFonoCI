/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <net/if.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/modem.h>
#include <ofono/call-barring.h>
#include <ofono/call-forwarding.h>
#include <ofono/call-settings.h>
#include <ofono/devinfo.h>
#include <ofono/netreg.h>
#include <ofono/netmon.h>
#include <ofono/phonebook.h>
#include <ofono/voicecall.h>
#include <ofono/sim.h>
#include <ofono/stk.h>
#include <ofono/sms.h>
#include <ofono/ussd.h>
#include <ofono/gprs.h>
#include <ofono/gprs-context.h>
#include <ofono/lte.h>
#include <ofono/radio-settings.h>
#include <ofono/location-reporting.h>
#include <ofono/log.h>
#include <ofono/message-waiting.h>

#include <ell/ell.h>

#include <drivers/qmimodem/qmi.h>
#include <drivers/qmimodem/dms.h>
#include <drivers/qmimodem/wda.h>
#include <drivers/qmimodem/util.h>

#define GOBI_DMS	(1 << 0)
#define GOBI_NAS	(1 << 1)
#define GOBI_WMS	(1 << 2)
#define GOBI_WDS	(1 << 3)
#define GOBI_PDS	(1 << 4)
#define GOBI_UIM	(1 << 5)
#define GOBI_VOICE	(1 << 6)
#define GOBI_WDA	(1 << 7)

enum qmi_protocol {
	QMI_PROTOCOL_QMUX,
	QMI_PROTOCOL_QRTR,
};

struct service_request {
	struct qmi_service **member;
	uint32_t service_type;
};

struct gobi_data {
	struct qmi_device *device;
	struct qmi_service *dms;
	struct qmi_service *wda;
	struct qmi_service *nas;
	struct qmi_service *wds;
	struct qmi_service *wms;
	struct qmi_service *voice;
	struct qmi_service *pds;
	struct qmi_service *uim;
	struct service_request service_requests[16];
	int cur_service_request;
	int num_service_requests;
	unsigned long features;
	unsigned int discover_attempts;
	uint8_t oper_mode;
	bool using_mux;
	bool using_qmi_wwan_q;
	int main_net_ifindex;
	char main_net_name[IFNAMSIZ];
	uint32_t max_aggregation_size;
	uint32_t set_powered_id;
	enum qmi_protocol protocol;
};

static void gobi_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

/*
 * Probe the modem.  The following modem properties are expected to be set
 * in order to initialize the driver properly:
 *
 * DeviceProtocol
 *   Can be "qrtr" or "qmux", tells the driver which QMI encapsulation protocol
 *   is being used.
 *
 * NetworkInterface
 *   The string that contains the 'main' network device.  This can be
 *   "rmnet_ipa" on SoC systems, or "wwan0" for upstream linux systems.
 *
 * NetworkInterfaceIndex
 *   The index of the main interface given by NetworkInterface
 *
 * NetworkInterfaceDriver
 *   The kernel driver that is being used by the main network device.  Certain
 *   drivers such as 'qmi_wwan' or 'qmi_wwan_q' are treated specifically.
 *
 * Bus
 *   The bus of the modem.  Values can be "usb", "embedded", or "pci"
 */
static int gobi_probe(struct ofono_modem *modem)
{
	struct gobi_data *data;
	const char *value;
	enum qmi_protocol protocol;
	const char *if_driver;
	const char *ifname;
	int ifindex;
	const char *bus;

	DBG("%p", modem);

	value = ofono_modem_get_string(modem, "DeviceProtocol");

	if (l_streq0(value, "qrtr"))
		protocol = QMI_PROTOCOL_QRTR;
	else if (l_streq0(value, "qmux"))
		protocol = QMI_PROTOCOL_QMUX;
	else
		return -EPROTO;

	if_driver = ofono_modem_get_string(modem,
						"NetworkInterfaceKernelDriver");
	ifname = ofono_modem_get_string(modem, "NetworkInterface");
	ifindex = ofono_modem_get_integer(modem, "NetworkInterfaceIndex");
	bus = ofono_modem_get_string(modem, "Bus");

	DBG("net: %s[%s](%d) %s", ifname, if_driver, ifindex, bus);

	if (!if_driver || !ifname || !ifindex || !bus)
		return -EPROTO;

	data = l_new(struct gobi_data, 1);
	data->protocol = protocol;

	if (!strcmp(if_driver, "qmi_wwan_q"))
		data->using_qmi_wwan_q = true;

	data->main_net_ifindex =
		ofono_modem_get_integer(modem, "NetworkInterfaceIndex");
	l_strlcpy(data->main_net_name,
			ofono_modem_get_string(modem, "NetworkInterface"),
			sizeof(data->main_net_name));
	ofono_modem_set_data(modem, data);
	ofono_modem_set_capabilities(modem, OFONO_MODEM_CAPABILITY_LTE);

	return 0;
}

static void cleanup_services(struct gobi_data *data)
{
	qmi_service_free(data->dms);
	data->dms = NULL;

	qmi_service_free(data->wda);
	data->wda = NULL;

	qmi_service_free(data->nas);
	data->nas = NULL;

	qmi_service_free(data->wds);
	data->wds = NULL;

	qmi_service_free(data->wms);
	data->wms = NULL;

	qmi_service_free(data->voice);
	data->voice = NULL;

	qmi_service_free(data->pds);
	data->pds = NULL;

	qmi_service_free(data->uim);
	data->uim = NULL;
}

static void gobi_remove(struct ofono_modem *modem)
{
	struct gobi_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	ofono_modem_set_data(modem, NULL);

	if (data->set_powered_id) {
		l_netlink_cancel(l_rtnl_get(), data->set_powered_id);
		data->set_powered_id = 0;
	}

	cleanup_services(data);

	qmi_device_free(data->device);

	l_free(data);
}

static void add_service_request(struct gobi_data *data,
					struct qmi_service **member,
					uint32_t service_type)
{
	struct service_request req = { .member = member,
					.service_type = service_type };

	if (data->num_service_requests == L_ARRAY_SIZE(data->service_requests)) {
		ofono_error("No room to add service request");
		return;
	}

	data->service_requests[data->num_service_requests++] = req;
}

static void shutdown_cb(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gobi_data *data = ofono_modem_get_data(modem);

	DBG("");

	data->discover_attempts = 0;

	qmi_device_free(data->device);
	data->device = NULL;

	ofono_modem_set_powered(modem, FALSE);
}

static void shutdown_device(struct ofono_modem *modem)
{
	struct gobi_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	cleanup_services(data);

	if (qmi_device_shutdown(data->device, shutdown_cb, modem, NULL) < 0)
		shutdown_cb(modem);
}

static void power_reset_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_modem *modem = user_data;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		shutdown_device(modem);
		return;
	}

	ofono_modem_set_powered(modem, TRUE);
}

static void get_oper_mode_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gobi_data *data = ofono_modem_get_data(modem);
	struct qmi_param *param;
	uint8_t mode;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		shutdown_device(modem);
		return;
	}

	if (!qmi_result_get_uint8(result, QMI_DMS_RESULT_OPER_MODE, &mode)) {
		shutdown_device(modem);
		return;
	}

	data->oper_mode = mode;

	/*
	 * Telit QMI LTE modem must remain online. If powered down, it also
	 * powers down the sim card, and QMI interface has no way to bring
	 * it back alive.
	 */
	if (ofono_modem_get_boolean(modem, "AlwaysOnline")) {
		ofono_modem_set_powered(modem, TRUE);
		return;
	}

	switch (data->oper_mode) {
	case QMI_DMS_OPER_MODE_ONLINE:
		param = qmi_param_new_uint8(QMI_DMS_PARAM_OPER_MODE,
					QMI_DMS_OPER_MODE_LOW_POWER);
		if (!param) {
			shutdown_device(modem);
			return;
		}

		if (qmi_service_send(data->dms, QMI_DMS_SET_OPER_MODE, param,
					power_reset_cb, modem, NULL) > 0)
			return;

		shutdown_device(modem);
		break;
	default:
		ofono_modem_set_powered(modem, TRUE);
		break;
	}
}

static void get_caps_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gobi_data *data = ofono_modem_get_data(modem);
	const struct qmi_dms_device_caps *caps;
	uint16_t len;
	uint8_t i;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto error;

	caps = qmi_result_get(result, QMI_DMS_RESULT_DEVICE_CAPS, &len);
	if (!caps)
		goto error;

        DBG("service capabilities %d", caps->data_capa);
        DBG("sim supported %d", caps->sim_supported);

        for (i = 0; i < caps->radio_if_count; i++)
                DBG("radio = %d", caps->radio_if[i]);

	if (qmi_service_send(data->dms, QMI_DMS_GET_OPER_MODE, NULL,
					get_oper_mode_cb, modem, NULL) > 0)
		return;

error:
	shutdown_device(modem);
}

static void get_data_format_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gobi_data *data = ofono_modem_get_data(modem);
	uint32_t llproto;
	enum qmi_device_expected_data_format expected_llproto;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto done;

	if (!qmi_result_get_uint32(result, QMI_WDA_LL_PROTOCOL, &llproto))
		goto done;

	expected_llproto = qmi_device_get_expected_data_format(data->device);

	if ((llproto == QMI_WDA_DATA_LINK_PROTOCOL_802_3) &&
			(expected_llproto ==
				QMI_DEVICE_EXPECTED_DATA_FORMAT_RAW_IP)) {
		if (!qmi_device_set_expected_data_format(data->device,
					QMI_DEVICE_EXPECTED_DATA_FORMAT_802_3))
			DBG("Fail to set expected data to 802.3");
		else
			DBG("expected data set to 802.3");
	} else if ((llproto == QMI_WDA_DATA_LINK_PROTOCOL_RAW_IP) &&
			(expected_llproto ==
				QMI_DEVICE_EXPECTED_DATA_FORMAT_802_3)) {
		if (!qmi_device_set_expected_data_format(data->device,
					QMI_DEVICE_EXPECTED_DATA_FORMAT_RAW_IP))
			DBG("Fail to set expected data to raw-ip");
		else
			DBG("expected data set to raw-ip");
	}

done:
	if (qmi_service_send(data->dms, QMI_DMS_GET_CAPS, NULL,
						get_caps_cb, modem, NULL) > 0)
		return;

	shutdown_device(modem);
}

static void create_wda_cb(struct qmi_service *service, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gobi_data *data = ofono_modem_get_data(modem);

	DBG("");

	if (!service) {
		DBG("Failed to request WDA service, continue initialization");
		goto error;
	}

	data->wda = service;

	if (qmi_service_send(data->wda, QMI_WDA_GET_DATA_FORMAT, NULL,
				get_data_format_cb, modem, NULL) > 0)
		return;

error:
	if (qmi_service_send(data->dms, QMI_DMS_GET_CAPS, NULL,
						get_caps_cb, modem, NULL) > 0)
		return;

	shutdown_device(modem);
}

static void request_service_cb(struct qmi_service *service, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gobi_data *data = ofono_modem_get_data(modem);
	struct service_request *req =
		&data->service_requests[data->cur_service_request];

	DBG("");

	if (!service)
		goto error;

	*req->member = service;

	data->cur_service_request += 1;
	if (data->cur_service_request == data->num_service_requests) {
		DBG("All services requested, proceeding to create WDA");

		if (qmi_service_create_shared(data->device, QMI_SERVICE_WDA,
						create_wda_cb, modem, NULL))
			return;

		goto error;
	}

	req = &data->service_requests[data->cur_service_request];
	DBG("Requesting: %u", req->service_type);

	if (qmi_service_create_shared(data->device, req->service_type,
					request_service_cb, modem, NULL))
		return;

error:
	shutdown_device(modem);
}

static void discover_cb(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gobi_data *data = ofono_modem_get_data(modem);

	DBG("");

	if (qmi_device_has_service(data->device, QMI_SERVICE_DMS))
		data->features |= GOBI_DMS;
	if (qmi_device_has_service(data->device, QMI_SERVICE_NAS))
		data->features |= GOBI_NAS;
	if (qmi_device_has_service(data->device, QMI_SERVICE_WMS))
		data->features |= GOBI_WMS;
	if (qmi_device_has_service(data->device, QMI_SERVICE_WDS))
		data->features |= GOBI_WDS;
	if (qmi_device_has_service(data->device, QMI_SERVICE_WDA))
		data->features |= GOBI_WDA;
	if (qmi_device_has_service(data->device, QMI_SERVICE_PDS))
		data->features |= GOBI_PDS;
	if (qmi_device_has_service(data->device, QMI_SERVICE_UIM))
		data->features |= GOBI_UIM;
	if (qmi_device_has_service(data->device, QMI_SERVICE_VOICE))
			data->features |= GOBI_VOICE;

	if (!(data->features & GOBI_DMS)) {
		if (++data->discover_attempts < 3 &&
				!qmi_device_discover(data->device, discover_cb,
								modem, NULL))
			return;

		goto error;
	}

	add_service_request(data, &data->dms, QMI_SERVICE_DMS);
	if (data->features & GOBI_NAS)
		add_service_request(data, &data->nas, QMI_SERVICE_NAS);
	if (data->features & GOBI_WDS)
		add_service_request(data, &data->wds, QMI_SERVICE_WDS);
	if (data->features & GOBI_WMS)
		add_service_request(data, &data->wms, QMI_SERVICE_WMS);
	if (data->features & GOBI_VOICE)
		add_service_request(data, &data->voice, QMI_SERVICE_VOICE);
	if (data->features & GOBI_UIM)
		add_service_request(data, &data->uim, QMI_SERVICE_UIM);

	if (qmi_service_create_shared(data->device, QMI_SERVICE_DMS,
					request_service_cb, modem, NULL) > 0)
		return;
error:
	shutdown_device(modem);
}

static int gobi_enable(struct ofono_modem *modem)
{
	struct gobi_data *data = ofono_modem_get_data(modem);
	const char *device;
	int r;

	DBG("%p", modem);

	switch (data->protocol) {
	case QMI_PROTOCOL_QRTR:
		data->device = qmi_device_new_qrtr();
		break;
	case QMI_PROTOCOL_QMUX:
		device = ofono_modem_get_string(modem, "Device");
		if (!device)
			return -EINVAL;

		data->device = qmi_device_new_qmux(device);
		break;
	}

	if (!data->device)
		return -EIO;

	if (getenv("OFONO_QMI_DEBUG"))
		qmi_device_set_debug(data->device, gobi_debug, "QMI: ");

	r = qmi_device_discover(data->device, discover_cb, modem, NULL);
	if (!r)
		return -EINPROGRESS;

	return r;
}

static void power_disable_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_modem *modem = user_data;

	DBG("");

	shutdown_device(modem);
}

static int gobi_disable(struct ofono_modem *modem)
{
	struct gobi_data *data = ofono_modem_get_data(modem);
	struct qmi_param *param;

	DBG("%p", modem);

	/*
	 * Telit QMI modem must remain online. If powered down, it also
	 * powers down the sim card, and QMI interface has no way to bring
	 * it back alive.
	 */
	if (ofono_modem_get_boolean(modem, "AlwaysOnline"))
		goto out;

	param = qmi_param_new_uint8(QMI_DMS_PARAM_OPER_MODE,
					QMI_DMS_OPER_MODE_LOW_POWER);
	if (!param)
		return -ENOMEM;

	if (qmi_service_send(data->dms, QMI_DMS_SET_OPER_MODE, param,
					power_disable_cb, modem, NULL) > 0)
		return -EINPROGRESS;

	qmi_param_free(param);
out:
	shutdown_device(modem);

	return -EINPROGRESS;
}

static void set_online_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_modem_online_cb_t cb = cbd->cb;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		CALLBACK_WITH_FAILURE(cb, cbd->data);
	else
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void powered_up_cb(int error, uint16_t type,
				const void *msg, uint32_t len,
				void *user_data)
{
	struct cb_data *cbd = user_data;
	struct gobi_data *data = cbd->user;
	struct qmi_param *param;
	ofono_modem_online_cb_t cb = cbd->cb;

	DBG("error: %d", error);

	data->set_powered_id = 0;

	if (error)
		goto error;

	param = qmi_param_new_uint8(QMI_DMS_PARAM_OPER_MODE,
						QMI_DMS_OPER_MODE_ONLINE);
	if (!param)
		goto error;

	if (data->using_qmi_wwan_q)
		l_sysctl_set_u32(1, "/sys/class/net/%s/link_state",
					data->main_net_name);

	cb_data_ref(cbd);

	if (qmi_service_send(data->dms, QMI_DMS_SET_OPER_MODE, param,
				set_online_cb, cbd, cb_data_unref) > 0)
		return;

	qmi_param_free(param);
	cb_data_unref(cbd);
error:
	CALLBACK_WITH_FAILURE(cb, cbd->data);
}

static void powered_down_cb(int error, uint16_t type,
				const void *msg, uint32_t len,
				void *user_data)
{
	struct cb_data *cbd = user_data;
	struct gobi_data *data = cbd->user;
	struct qmi_param *param;
	ofono_modem_online_cb_t cb = cbd->cb;

	DBG("error: %d", error);

	data->set_powered_id = 0;

	if (error)
		goto error;

	param = qmi_param_new_uint8(QMI_DMS_PARAM_OPER_MODE,
					QMI_DMS_OPER_MODE_LOW_POWER);
	if (!param)
		goto error;

	if (data->using_qmi_wwan_q)
		l_sysctl_set_u32(0, "/sys/class/net/%s/link_state",
					data->main_net_name);

	cb_data_ref(cbd);

	if (qmi_service_send(data->dms, QMI_DMS_SET_OPER_MODE, param,
				set_online_cb, cbd, cb_data_unref) > 0)
		return;

	qmi_param_free(param);
	cb_data_unref(cbd);
error:
	CALLBACK_WITH_FAILURE(cb, cbd->data);
}

static void gobi_set_online(struct ofono_modem *modem, ofono_bool_t online,
				ofono_modem_online_cb_t cb, void *user_data)
{
	struct gobi_data *data = ofono_modem_get_data(modem);
	struct l_netlink *rtnl = l_rtnl_get();
	struct cb_data *cbd = cb_data_new(cb, user_data);
	l_netlink_command_func_t powered_cb;

	DBG("%p %s using_mux: %s", modem, online ? "online" : "offline",
		data->using_mux ? "yes" : "no");

	cbd->user = data;

	if (online)
		powered_cb = powered_up_cb;
	else
		powered_cb = powered_down_cb;

	if (!data->using_mux) {
		powered_cb(0, 0, NULL, 0, cbd);
		cb_data_unref(cbd);
		return;
	}

	data->set_powered_id = l_rtnl_set_powered(rtnl, data->main_net_ifindex,
							online, powered_cb, cbd,
							cb_data_unref);
	if (data->set_powered_id)
		return;

	cb_data_unref(cbd);
	CALLBACK_WITH_FAILURE(cb, user_data);
}

static void gobi_pre_sim(struct ofono_modem *modem)
{
	struct gobi_data *data = ofono_modem_get_data(modem);
	bool legacy = ofono_modem_get_boolean(modem, "ForceSimLegacy");

	DBG("%p", modem);

	ofono_devinfo_create(modem, 0, "qmimodem", qmi_service_clone(data->dms));

	if ((data->features & GOBI_UIM) && !legacy)
		ofono_sim_create(modem, 0, "qmimodem", data->device);
	else /* DMS always available */
		ofono_sim_create(modem, 0, "qmimodem_legacy",
						qmi_service_clone(data->dms));

	if (data->features & GOBI_VOICE)
		ofono_voicecall_create(modem, 0, "qmimodem", data->device);

	if (data->features & GOBI_PDS)
		ofono_location_reporting_create(modem, 0, "qmimodem",
							data->device);
}

static void gobi_setup_gprs(struct ofono_modem *modem)
{
	struct gobi_data *data = ofono_modem_get_data(modem);
	int n_premux = ofono_modem_get_integer(modem, "NumPremuxInterfaces");
	struct ofono_gprs *gprs;
	struct ofono_gprs_context *gc;
	const char *interface;
	char buf[256];
	int i;

	gprs = ofono_gprs_create(modem, 0, "qmimodem", data->device);
	if (!gprs) {
		ofono_warn("Unable to create gprs for: %s",
					ofono_modem_get_path(modem));
		return;
	}

	/* Simple case of 802.3 interface, no QMAP */
	if (n_premux == 0) {
		interface = ofono_modem_get_string(modem, "NetworkInterface");

		gc = ofono_gprs_context_create(modem, 0, "qmimodem",
							data->device);
		if (!gc) {
			ofono_warn("Unable to create gprs-context for: %s",
					ofono_modem_get_path(modem));
			return;
		}

		ofono_gprs_add_context(gprs, gc);
		ofono_gprs_context_set_interface(gc, interface);

		return;
	}

	data->using_mux = true;

	data->max_aggregation_size =
		ofono_modem_get_integer(modem, "MaxAggregationSize");
	DBG("max_aggregation_size: %u", data->max_aggregation_size);

	for (i = 0; i < n_premux; i++) {
		int mux_id;

		sprintf(buf, "PremuxInterface%dMuxId", i + 1);
		mux_id = ofono_modem_get_integer(modem, buf);

		gc = ofono_gprs_context_create(modem, mux_id, "qmimodem",
							data->device);

		if (!gc) {
			ofono_warn("gprs-context creation failed for [%d] %s",
					i + 1, ofono_modem_get_path(modem));
			continue;
		}

		sprintf(buf, "PremuxInterface%d", i + 1);
		interface = ofono_modem_get_string(modem, buf);

		ofono_gprs_add_context(gprs, gc);
		ofono_gprs_context_set_interface(gc, interface);
	}
}

static void gobi_post_sim(struct ofono_modem *modem)
{
	struct gobi_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	ofono_lte_create(modem, 0, "qmimodem", data->device);

	if (data->features & GOBI_NAS)
		ofono_radio_settings_create(modem, 0, "qmimodem", data->device);

	if (data->features & GOBI_WMS)
		ofono_sms_create(modem, 0, "qmimodem", data->device);

	if ((data->features & GOBI_WMS) && (data->features & GOBI_UIM) &&
			!ofono_modem_get_boolean(modem, "ForceSimLegacy")) {
		struct ofono_message_waiting *mw =
					ofono_message_waiting_create(modem);

		if (mw)
			ofono_message_waiting_register(mw);
	}

	if (data->features & GOBI_WDS)
		gobi_setup_gprs(modem);
}

static void gobi_post_online(struct ofono_modem *modem)
{
	struct gobi_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	if (data->features & GOBI_NAS) {
		ofono_netreg_create(modem, 0, "qmimodem", data->device);
		ofono_netmon_create(modem, 0, "qmimodem", data->device);
	}

	if (data->features & GOBI_VOICE) {
		ofono_ussd_create(modem, 0, "qmimodem", data->device);
		ofono_call_settings_create(modem, 0, "qmimodem", data->device);
		ofono_call_barring_create(modem, 0, "qmimodem", data->device);
		ofono_call_forwarding_create(modem, 0, "qmimodem",
						data->device);
	}
}

static struct ofono_modem_driver gobi_driver = {
	.probe		= gobi_probe,
	.remove		= gobi_remove,
	.enable		= gobi_enable,
	.disable	= gobi_disable,
	.set_online	= gobi_set_online,
	.pre_sim	= gobi_pre_sim,
	.post_sim	= gobi_post_sim,
	.post_online	= gobi_post_online,
};

OFONO_MODEM_DRIVER_BUILTIN(gobi, &gobi_driver)

/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <arpa/inet.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>

#include "qmi.h"
#include "wds.h"
#include "util.h"

struct gprs_context_data {
	struct qmi_service *wds;
	struct qmi_device *dev;
	unsigned int active_context;
	uint32_t pkt_handle;
	uint8_t mux_id;
};

static void pkt_status_notify(struct qmi_result *result, void *user_data)
{
	static const uint8_t RESULT_CONN_STATUS = 0x01;
	static const uint8_t RESULT_IP_FAMILY = 0x12;
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	const struct {
		uint8_t status;
		uint8_t reconf;
	} __attribute__((__packed__)) *status;
	uint16_t len;
	uint8_t ip_family;

	DBG("");

	status = qmi_result_get(result, RESULT_CONN_STATUS, &len);
	if (!status)
		return;

	DBG("conn status %d", status->status);

	if (qmi_result_get_uint8(result, RESULT_IP_FAMILY, &ip_family))
		DBG("ip family %d", ip_family);

	switch (status->status) {
	case QMI_WDS_CONNECTION_STATUS_DISCONNECTED:
		if (data->pkt_handle) {
			/* The context has been disconnected by the network */
			ofono_gprs_context_deactivated(gc, data->active_context);
			data->pkt_handle = 0;
			data->active_context = 0;
		}
		break;
	}
}

static void get_settings_ipv4(struct ofono_gprs_context *gc,
					struct qmi_result *result)
{
	static const uint8_t RESULT_PRIMARY_DNS = 0x15;
	static const uint8_t RESULT_SECONDARY_DNS = 0x16;
	static const uint8_t RESULT_IP_ADDRESS = 0x1e;
	static const uint8_t RESULT_GATEWAY = 0x20;
	static const uint8_t RESULT_GATEWAY_NETMASK = 0x21;
	uint32_t ip_addr;
	struct in_addr addr;
	char* straddr;
	const char *dns[3] = { NULL, NULL, NULL };
	char dns_buf[2][INET_ADDRSTRLEN];

	if (qmi_result_get_uint32(result, RESULT_IP_ADDRESS, &ip_addr)) {
		addr.s_addr = htonl(ip_addr);
		straddr = inet_ntoa(addr);
		DBG("IP addr: %s", straddr);
		ofono_gprs_context_set_ipv4_address(gc, straddr, 1);
	}

	if (qmi_result_get_uint32(result, RESULT_GATEWAY, &ip_addr)) {
		addr.s_addr = htonl(ip_addr);
		straddr = inet_ntoa(addr);
		DBG("Gateway: %s", straddr);
		ofono_gprs_context_set_ipv4_gateway(gc, straddr);
	}

	if (qmi_result_get_uint32(result, RESULT_GATEWAY_NETMASK, &ip_addr)) {
		addr.s_addr = htonl(ip_addr);
		straddr = inet_ntoa(addr);
		DBG("Gateway netmask: %s", straddr);
		ofono_gprs_context_set_ipv4_netmask(gc, straddr);
	}

	if (qmi_result_get_uint32(result, RESULT_PRIMARY_DNS, &ip_addr)) {
		addr.s_addr = htonl(ip_addr);
		dns[0] = inet_ntop(AF_INET, &addr, dns_buf[0], sizeof(dns_buf[0]));
		DBG("Primary DNS: %s", dns[0]);
	}

	if (qmi_result_get_uint32(result, RESULT_SECONDARY_DNS, &ip_addr)) {
		addr.s_addr = htonl(ip_addr);
		dns[1] = inet_ntop(AF_INET, &addr, dns_buf[1], sizeof(dns_buf[1]));
		DBG("Secondary DNS: %s", dns[1]);
	}

	if (dns[0])
		ofono_gprs_context_set_ipv4_dns_servers(gc, dns);
}

static void get_settings_cb(struct qmi_result *result, void *user_data)
{
	static const uint8_t RESULT_PDP_TYPE = 0x11;	/* uint8 */
	static const uint8_t RESULT_APN = 0x14;		/* string */
	static const uint8_t RESULT_IP_FAMILY = 0x2b;	/* uint8 */
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	uint8_t pdp_type, ip_family;
	char *apn;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto done;

	apn = qmi_result_get_string(result, RESULT_APN);
	if (apn) {
		DBG("APN: %s", apn);
		l_free(apn);
	}

	if (qmi_result_get_uint8(result, RESULT_PDP_TYPE, &pdp_type))
		DBG("PDP type %d", pdp_type);

	if (!qmi_result_get_uint8(result, RESULT_IP_FAMILY, &ip_family)) {
		ofono_error("No IP family in results");
		goto done;
	}

	switch (ip_family) {
	case QMI_WDS_IP_FAMILY_IPV4:
		get_settings_ipv4(gc, result);
		break;
	case QMI_WDS_IP_FAMILY_IPV6:
		break;
	default:
		break;
	}

done:
	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void start_net_cb(struct qmi_result *result, void *user_data)
{
	static const uint8_t RESULT_PACKET_HANDLE = 0x01;
	static const uint8_t PARAM_REQUESTED_SETTINGS = 0x10;
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint32_t handle;
	uint32_t requested_settings = 0;
	struct qmi_param *param;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto error;

	if (!qmi_result_get_uint32(result, RESULT_PACKET_HANDLE, &handle))
		goto error;

	DBG("packet handle %d", handle);

	data->pkt_handle = handle;

	/*
	 * Explicitly request certain information to be provided.  The requested
	 * settings is a bit field, with each bit representing whether the
	 * TLV is included in the GET_CURRENT_SETTINGS response.  We request the
	 * following settings:
	 * 2 - PDP Type, 3 - APN Name, 4 - DNS, 5 - Granted QOS,
	 * 6 - Username, 7 - Auth Proto
	 * 8 - IP Address, 9 - Gateway, 13 - MTU, 14 - DNS List,
	 * 15 - IP Family, 17 - Extended Technology
	 */
	L_BITS_SET(&requested_settings, 2, 3, 4, 5, 6, 7, 8, 9, 13, 14, 15, 17);
	param = qmi_param_new_uint32(PARAM_REQUESTED_SETTINGS,
						requested_settings);

	if (qmi_service_send(data->wds, QMI_WDS_GET_CURRENT_SETTINGS, param,
				get_settings_cb, cbd, cb_data_unref) > 0) {
		cb_data_ref(cbd);
		return;
	}

	qmi_param_free(param);

error:
	data->active_context = 0;
	CALLBACK_WITH_FAILURE(cb, cbd->data);
}

/*
 * This function gets called for "automatic" contexts, those which are
 * not activated via activate_primary.  For these, we will still need
 * to call start_net in order to get the packet handle for the context.
 * The process for automatic contexts is essentially identical to that
 * for others.
 */
static void qmi_gprs_read_settings(struct ofono_gprs_context* gc,
					unsigned int cid,
					ofono_gprs_context_cb_t cb,
					void *user_data)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("cid %u", cid);

	data->active_context = cid;

	cbd->user = gc;

	if (qmi_service_send(data->wds, QMI_WDS_START_NETWORK, NULL,
					start_net_cb, cbd, cb_data_unref) > 0)
		return;

	data->active_context = 0;

	CALLBACK_WITH_FAILURE(cb, cbd->data);

	l_free(cbd);
}

static void qmi_activate_primary(struct ofono_gprs_context *gc,
				const struct ofono_gprs_primary_context *ctx,
				ofono_gprs_context_cb_t cb, void *user_data)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_param *param;
	uint8_t ip_family;
	uint8_t auth;

	DBG("cid %u", ctx->cid);

	cbd->user = gc;

	data->active_context = ctx->cid;

	switch (ctx->proto) {
	case OFONO_GPRS_PROTO_IP:
		ip_family = QMI_WDS_IP_FAMILY_IPV4;
		break;
	case OFONO_GPRS_PROTO_IPV6:
		ip_family = QMI_WDS_IP_FAMILY_IPV6;
		break;
	default:
		goto error;
	}

	param = qmi_param_new();

	qmi_param_append(param, QMI_WDS_PARAM_APN,
					strlen(ctx->apn), ctx->apn);

	qmi_param_append_uint8(param, QMI_WDS_PARAM_IP_FAMILY, ip_family);

	auth = qmi_wds_auth_from_ofono(ctx->auth_method);

	qmi_param_append_uint8(param, QMI_WDS_PARAM_AUTHENTICATION_PREFERENCE,
					auth);

	if (auth && ctx->username[0] != '\0')
		qmi_param_append(param, QMI_WDS_PARAM_USERNAME,
					strlen(ctx->username), ctx->username);

	if (auth && ctx->password[0] != '\0')
		qmi_param_append(param, QMI_WDS_PARAM_PASSWORD,
					strlen(ctx->password), ctx->password);

	if (qmi_service_send(data->wds, QMI_WDS_START_NETWORK, param,
					start_net_cb, cbd, cb_data_unref) > 0)
		return;

	qmi_param_free(param);

error:
	data->active_context = 0;

	CALLBACK_WITH_FAILURE(cb, cbd->data);

	l_free(cbd);
}

static void stop_net_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		if (cb)
			CALLBACK_WITH_FAILURE(cb, cbd->data);
		return;
	}

	data->pkt_handle = 0;

	if (cb)
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	else
		ofono_gprs_context_deactivated(gc, data->active_context);

	data->active_context = 0;
}

static void qmi_deactivate_primary(struct ofono_gprs_context *gc,
				unsigned int cid,
				ofono_gprs_context_cb_t cb, void *user_data)
{
	static const uint8_t PARAM_PACKET_HANDLE = 0x01;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct qmi_param *param;

	DBG("cid %u", cid);

	cbd->user = gc;

	param = qmi_param_new_uint32(PARAM_PACKET_HANDLE, data->pkt_handle);

	if (qmi_service_send(data->wds, QMI_WDS_STOP_NETWORK, param,
					stop_net_cb, cbd, l_free) > 0)
		return;

	qmi_param_free(param);

	if (cb)
		CALLBACK_WITH_FAILURE(cb, user_data);

	l_free(cbd);
}

static void qmi_gprs_context_detach_shutdown(struct ofono_gprs_context *gc,
						unsigned int cid)
{
	DBG("");

	qmi_deactivate_primary(gc, cid, NULL, NULL);
}

static void bind_mux_data_port_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_gprs_context *gc = user_data;

	DBG("");

	if (qmi_result_set_error(result, NULL)) {
		ofono_error("Failed to bind MUX");
		ofono_gprs_context_remove(gc);
		return;
	}
}

static void qmi_gprs_context_bind_mux(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct ofono_modem *modem = ofono_gprs_context_get_modem(gc);
	struct qmi_param *param;
	const char *interface_number;
	const char *bus;
	struct {
		uint32_t endpoint_type;
		uint32_t interface_number;
	} __attribute__((packed)) endpoint_info;
	uint8_t u8;

	bus = ofono_modem_get_string(modem, "Bus");
	if (!bus) {
		ofono_error("%s: Missing 'Bus'", ofono_modem_get_path(modem));
		goto error;
	}

	if (!strcmp(bus, "pcie"))
		endpoint_info.endpoint_type = QMI_DATA_ENDPOINT_TYPE_PCIE;
	else if (!strcmp(bus, "usb"))
		endpoint_info.endpoint_type = QMI_DATA_ENDPOINT_TYPE_HSUSB;
	else if (!strcmp(bus, "embedded"))
		endpoint_info.endpoint_type = QMI_DATA_ENDPOINT_TYPE_EMBEDDED;
	else {
		ofono_error("%s: Invalid 'Bus' value",
				ofono_modem_get_path(modem));
		goto error;
	}

	interface_number = ofono_modem_get_string(modem, "InterfaceNumber");
	if (!interface_number && endpoint_info.endpoint_type !=
					QMI_DATA_ENDPOINT_TYPE_EMBEDDED) {
		ofono_error("%s: Missing 'InterfaceNumber'",
					ofono_modem_get_path(modem));
		goto error;
	} else if (!interface_number)
		u8 = 1;	/* Default for embedded modems */
	else if (l_safe_atox8(interface_number, &u8) < 0) {
		ofono_error("%s: Invalid InterfaceNumber",
					ofono_modem_get_path(modem));
		goto error;
	}

	endpoint_info.interface_number = u8;

	DBG("interface_number: %d", u8);
	DBG("mux_id: %hhx", data->mux_id);

	param = qmi_param_new();

	qmi_param_append(param, 0x10, sizeof(endpoint_info), &endpoint_info);
	qmi_param_append_uint8(param, 0x11, data->mux_id);
	qmi_param_append_uint32(param, 0x13, QMI_WDS_CLIENT_TYPE_TETHERED);

	if (qmi_service_send(data->wds, QMI_WDS_BIND_MUX_DATA_PORT, param,
				bind_mux_data_port_cb, gc, NULL) > 0)
		return;

	qmi_param_free(param);
error:
	ofono_error("Failed to BIND_MUX_DATA_PORT");
	ofono_gprs_context_remove(gc);
}

static void create_wds_cb(struct qmi_service *service, void *user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	DBG("");

	if (!service) {
		ofono_error("Failed to request WDS service");
		ofono_gprs_context_remove(gc);
		return;
	}

	data->wds = service;

	qmi_service_register(data->wds, QMI_WDS_PACKET_SERVICE_STATUS,
					pkt_status_notify, gc, NULL);

	if (data->mux_id)
		qmi_gprs_context_bind_mux(gc);
}

static int qmi_gprs_context_probe(struct ofono_gprs_context *gc,
					unsigned int vendor, void *user_data)
{
	struct qmi_device *device = user_data;
	struct gprs_context_data *data;

	DBG("");

	data = l_new(struct gprs_context_data, 1);

	ofono_gprs_context_set_data(gc, data);
	data->dev = device;
	data->mux_id = vendor;

	qmi_service_create_shared(data->dev, QMI_SERVICE_WDS, create_wds_cb, gc,
									NULL);
	return 0;
}

static void qmi_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	DBG("");

	ofono_gprs_context_set_data(gc, NULL);

	if (data->wds)
		qmi_service_free(data->wds);

	l_free(data);
}

static const struct ofono_gprs_context_driver driver = {
	.probe			= qmi_gprs_context_probe,
	.remove			= qmi_gprs_context_remove,
	.activate_primary	= qmi_activate_primary,
	.deactivate_primary	= qmi_deactivate_primary,
	.read_settings		= qmi_gprs_read_settings,
	.detach_shutdown	= qmi_gprs_context_detach_shutdown,
};

OFONO_ATOM_DRIVER_BUILTIN(gprs_context, qmimodem, &driver)

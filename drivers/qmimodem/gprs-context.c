/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
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

	if (!qmi_result_get_uint8(result, RESULT_IP_FAMILY, &ip_family))
		return;

	DBG("conn status %d ip family %d", status->status, ip_family);

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

static void get_settings_ipv6(struct ofono_gprs_context *gc,
					struct qmi_result *result)
{
	static const uint8_t RESULT_IP_ADDRESS = 0x25;
	static const uint8_t RESULT_GATEWAY = 0x26;
	static const uint8_t RESULT_PRIMARY_DNS = 0x27;
	static const uint8_t RESULT_SECONDARY_DNS = 0x28;
	static const uint8_t RESULT_MTU = 0x29;
	const char *dns[3] = { NULL, NULL, NULL };
	char dns1str[INET6_ADDRSTRLEN];
	char dns2str[INET6_ADDRSTRLEN];
	char ipv6str[INET6_ADDRSTRLEN];
	const void *tlv;
	uint16_t len;
	uint32_t mtu;

	tlv = qmi_result_get(result, RESULT_IP_ADDRESS, &len);
	if (tlv && len == sizeof(struct in6_addr) + 1) {
		const struct in6_addr *ip = tlv;
		uint8_t prefix_len = l_get_u8(ip + 1);

		inet_ntop(AF_INET6, ip, ipv6str, sizeof(ipv6str));
		ofono_gprs_context_set_ipv6_address(gc, ipv6str);
		ofono_gprs_context_set_ipv6_prefix_length(gc, prefix_len);
	}

	tlv = qmi_result_get(result, RESULT_GATEWAY, &len);
	if (tlv && len == sizeof(struct in6_addr) + 1) {
		const struct in6_addr *gw = tlv;

		inet_ntop(AF_INET6, gw, ipv6str, sizeof(ipv6str));
		ofono_gprs_context_set_ipv6_gateway(gc, ipv6str);
	}

	tlv = qmi_result_get(result, RESULT_PRIMARY_DNS, &len);
	if (tlv && len == sizeof(struct in6_addr)) {
		const struct in6_addr *dns1 = tlv;

		inet_ntop(AF_INET6, dns1, dns1str, sizeof(dns1str));
		dns[0] = dns1str;
	}

	tlv = qmi_result_get(result, RESULT_SECONDARY_DNS, &len);
	if (tlv && len == sizeof(struct in6_addr)) {
		const struct in6_addr *dns2 = tlv;

		inet_ntop(AF_INET6, dns2, dns2str, sizeof(dns2str));
		dns[1] = dns2str;
	}

	if (dns[0])
		ofono_gprs_context_set_ipv6_dns_servers(gc, dns);

	if (qmi_result_get_uint32(result, RESULT_MTU, &mtu))
		DBG("MTU: %u", mtu);
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
	static const uint8_t RESULT_IP_FAMILY = 0x2b;	/* uint8 */
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	uint8_t ip_family;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto done;

	if (!qmi_result_get_uint8(result, RESULT_IP_FAMILY, &ip_family)) {
		ofono_error("No IP family in results");
		goto done;
	}

	switch (ip_family) {
	case QMI_WDS_IP_FAMILY_IPV4:
		get_settings_ipv4(gc, result);
		break;
	case QMI_WDS_IP_FAMILY_IPV6:
		get_settings_ipv6(gc, result);
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

static void get_lte_attach_param_cb(struct qmi_result *result, void *user_data)
{
	static const uint8_t RESULT_IP_SUPPORT_TYPE = 0x11;
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint16_t error;
	uint8_t iptype;
	struct qmi_param *param;
	uint8_t ip_family;

	DBG("");

	if (qmi_result_set_error(result, &error))
		goto error;

	if (!qmi_result_get_uint8(result, RESULT_IP_SUPPORT_TYPE, &iptype))
		goto error;

	switch (iptype) {
	case QMI_WDS_IP_SUPPORT_IPV4:
		ip_family = QMI_WDS_IP_FAMILY_IPV4;
		break;
	case QMI_WDS_IP_SUPPORT_IPV6:
		ip_family = QMI_WDS_IP_FAMILY_IPV6;
		break;
	case QMI_WDS_IP_SUPPORT_IPV4V6:
		ip_family = QMI_WDS_IP_FAMILY_IPV4;
		break;
	default:
		goto error;
	}

	param = qmi_param_new_uint8(QMI_WDS_PARAM_IP_FAMILY, ip_family);

	if (qmi_service_send(data->wds, QMI_WDS_START_NETWORK, param,
					start_net_cb, cbd, cb_data_unref) > 0) {
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

	if (qmi_service_send(data->wds, QMI_WDS_GET_LTE_ATTACH_PARAMETERS,
				NULL, get_lte_attach_param_cb, cbd,
				cb_data_unref) > 0) {
		data->active_context = cid;
		cbd->user = gc;
		return;
	}

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

static int qmi_gprs_context_bind_mux(struct ofono_gprs_context *gc,
					struct qmi_service *wds,
					uint8_t mux_id)
{
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
		return -EINVAL;
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
		return -ENOTSUP;
	}

	switch (endpoint_info.endpoint_type) {
	case QMI_DATA_ENDPOINT_TYPE_PCIE:
		endpoint_info.interface_number = 0x04; /* Magic for PCIE */
		break;
	case QMI_DATA_ENDPOINT_TYPE_EMBEDDED:
		endpoint_info.interface_number = 0x01;
		break;
	case QMI_DATA_ENDPOINT_TYPE_HSUSB:
		interface_number = ofono_modem_get_string(modem,
							"InterfaceNumber");
		if (!l_safe_atox8(interface_number, &u8)) {
			endpoint_info.interface_number = u8;
			break;
		}

		ofono_error("%s: Missing or invalid 'InterfaceNumber'",
					ofono_modem_get_path(modem));
		return -EINVAL;
	default:
		return -ENOTSUP;
	}

	DBG("interface_number: %d", endpoint_info.interface_number);
	DBG("mux_id: %hhx", mux_id);

	param = qmi_param_new();

	qmi_param_append(param, 0x10, sizeof(endpoint_info), &endpoint_info);
	qmi_param_append_uint8(param, 0x11, mux_id);
	qmi_param_append_uint32(param, 0x13, QMI_WDS_CLIENT_TYPE_TETHERED);

	if (qmi_service_send(wds, QMI_WDS_BIND_MUX_DATA_PORT, param,
				bind_mux_data_port_cb, gc, NULL) > 0)
		return 0;

	qmi_param_free(param);
	return -EIO;
}

static int qmi_gprs_context_probev(struct ofono_gprs_context *gc,
					unsigned int vendor, va_list args)
{
	int mux_id = va_arg(args, int);
	_auto_(qmi_service_free) struct qmi_service *ipv4 =
					va_arg(args, struct qmi_service *);
	_auto_(qmi_service_free) struct qmi_service *ipv6 =
					va_arg(args, struct qmi_service *);
	struct gprs_context_data *data;

	DBG("");

	if (mux_id != -1) {
		int r = qmi_gprs_context_bind_mux(gc, ipv4, mux_id);

		if (r < 0)
			return r;
	}

	data = l_new(struct gprs_context_data, 1);
	data->wds = l_steal_ptr(ipv4);
	data->mux_id = mux_id;

	qmi_service_register(data->wds, QMI_WDS_PACKET_SERVICE_STATUS,
					pkt_status_notify, gc, NULL);

	ofono_gprs_context_set_data(gc, data);

	return 0;
}

static void qmi_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	DBG("");

	ofono_gprs_context_set_data(gc, NULL);

	qmi_service_free(data->wds);
	l_free(data);
}

static const struct ofono_gprs_context_driver driver = {
	.flags			= OFONO_ATOM_DRIVER_FLAG_REGISTER_ON_PROBE,
	.probev			= qmi_gprs_context_probev,
	.remove			= qmi_gprs_context_remove,
	.activate_primary	= qmi_activate_primary,
	.deactivate_primary	= qmi_deactivate_primary,
	.read_settings		= qmi_gprs_read_settings,
	.detach_shutdown	= qmi_gprs_context_detach_shutdown,
};

OFONO_ATOM_DRIVER_BUILTIN(gprs_context, qmimodem, &driver)

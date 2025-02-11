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
#include "common.h"
#include "wds.h"
#include "util.h"

struct gprs_context_data {
	struct qmi_service *ipv4;
	struct qmi_service *ipv6;
	unsigned int active_context;
	uint32_t packet_handle_ipv4;
	uint32_t packet_handle_ipv6;
	uint32_t start_network_ipv4_id;
	uint32_t start_network_ipv6_id;
	uint8_t mux_id;
};

static void check_all_deactivated(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	if (data->packet_handle_ipv4 || data->packet_handle_ipv6)
		return;

	/* All families have been disconnected */
	ofono_gprs_context_deactivated(gc, data->active_context);
	data->active_context = 0;
}

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
		if (ip_family == QMI_WDS_IP_FAMILY_IPV4 &&
				data->packet_handle_ipv4) {
			data->packet_handle_ipv4 = 0;
			check_all_deactivated(gc);
		}

		if (ip_family == QMI_WDS_IP_FAMILY_IPV6 &&
				data->packet_handle_ipv6) {
			data->packet_handle_ipv6 = 0;
			check_all_deactivated(gc);
		}

		break;
	}
}

static void check_all_activated(struct gprs_context_data *data,
					ofono_gprs_context_cb_t cb,
					void *user_data)
{
	if (data->start_network_ipv4_id || data->start_network_ipv6_id)
		return;

	if (!data->packet_handle_ipv4 && !data->packet_handle_ipv6) {
		data->active_context = 0;
		CALLBACK_WITH_FAILURE(cb, user_data);
		return;
	}

	CALLBACK_WITH_SUCCESS(cb, user_data);
}

static void get_settings_ipv6_cb(struct qmi_result *result, void *user_data)
{
	static const uint8_t RESULT_IP_ADDRESS = 0x25;
	static const uint8_t RESULT_GATEWAY = 0x26;
	static const uint8_t RESULT_PRIMARY_DNS = 0x27;
	static const uint8_t RESULT_SECONDARY_DNS = 0x28;
	static const uint8_t RESULT_MTU = 0x29;
	struct cb_data *cbd = user_data;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint16_t error;
	const char *dns[3] = { NULL, NULL, NULL };
	char dns1str[INET6_ADDRSTRLEN];
	char dns2str[INET6_ADDRSTRLEN];
	char ipv6str[INET6_ADDRSTRLEN];
	const void *tlv;
	uint16_t len;
	uint32_t mtu;

	data->start_network_ipv6_id = 0;

	if (qmi_result_set_error(result, &error)) {
		DBG("error: %u", error);
		goto done;
	}

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

done:
	check_all_activated(data, cbd->cb, cbd->data);
}

static void get_settings_ipv4_cb(struct qmi_result *result, void *user_data)
{
	static const uint8_t RESULT_PRIMARY_DNS = 0x15;
	static const uint8_t RESULT_SECONDARY_DNS = 0x16;
	static const uint8_t RESULT_IP_ADDRESS = 0x1e;
	static const uint8_t RESULT_GATEWAY = 0x20;
	static const uint8_t RESULT_GATEWAY_NETMASK = 0x21;
	struct cb_data *cbd = user_data;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint16_t error;
	uint32_t ip_addr;
	struct in_addr addr;
	char* straddr;
	const char *dns[3] = { NULL, NULL, NULL };
	char dns_buf[2][INET_ADDRSTRLEN];

	data->start_network_ipv4_id = 0;

	if (qmi_result_set_error(result, &error)) {
		DBG("error: %u", error);
		goto done;
	}

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

done:
	check_all_activated(data, cbd->cb, cbd->data);
}

static uint32_t send_get_current_settings(struct qmi_service *wds,
						qmi_service_result_func_t func,
						void *user_data,
						qmi_destroy_func_t destroy)
{
	static const uint8_t PARAM_REQUESTED_SETTINGS = 0x10;
	uint32_t requested_settings = 0;
	struct qmi_param *param;
	uint32_t id;
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
	id = qmi_service_send(wds, QMI_WDS_GET_CURRENT_SETTINGS, param,
				func, user_data, destroy);

	if (!id)
		qmi_param_free(param);

	return id;
}

static void start_network_common_cb(int family, struct qmi_result *result,
					struct cb_data *cbd,
					struct qmi_service *wds,
					qmi_service_result_func_t func,
					uint32_t *packet_handle,
					uint32_t *family_start_id)
{
	static const uint8_t RESULT_PACKET_HANDLE = 0x01;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint16_t error;

	*family_start_id = 0;

	if (!qmi_result_set_error(result, &error))
		error = 0;

	DBG("family: %d, error: %u", family, error);

	if (error)
		goto error;

	if (!qmi_result_get_uint32(result, RESULT_PACKET_HANDLE, packet_handle))
		goto error;

	*family_start_id =
		send_get_current_settings(wds, func,
						cb_data_ref(cbd), cb_data_unref);
	if (*family_start_id)
		return;

	*packet_handle = 0;
	cb_data_unref(cbd);
error:
	check_all_activated(data, cbd->cb, cbd->data);
}

static void start_network_ipv4_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	start_network_common_cb(4, result, user_data,
				data->ipv4, get_settings_ipv4_cb,
				&data->packet_handle_ipv4,
				&data->start_network_ipv4_id);
}

static void start_network_ipv6_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	start_network_common_cb(6, result, user_data,
				data->ipv6, get_settings_ipv6_cb,
				&data->packet_handle_ipv6,
				&data->start_network_ipv6_id);
}

static struct qmi_param *param_from_context(uint8_t ip_family,
				const struct ofono_gprs_primary_context *ctx)
{
	struct qmi_param *param = qmi_param_new();
	uint8_t auth;

	qmi_param_append_uint8(param, QMI_WDS_PARAM_IP_FAMILY, ip_family);

	if (!ctx)
		goto done;

	qmi_param_append(param, QMI_WDS_PARAM_APN,
					strlen(ctx->apn), ctx->apn);

	auth = qmi_wds_auth_from_ofono(ctx->auth_method);
	qmi_param_append_uint8(param, QMI_WDS_PARAM_AUTHENTICATION_PREFERENCE,
					auth);

	if (auth && ctx->username[0] != '\0')
		qmi_param_append(param, QMI_WDS_PARAM_USERNAME,
					strlen(ctx->username), ctx->username);

	if (auth && ctx->password[0] != '\0')
		qmi_param_append(param, QMI_WDS_PARAM_PASSWORD,
					strlen(ctx->password), ctx->password);
done:
	return param;
}

static int start_network(uint8_t iptype, struct gprs_context_data *data,
				const struct ofono_gprs_primary_context *ctx,
				struct cb_data *cbd)
{
	struct qmi_param *param;

	if (!L_IN_SET(iptype, QMI_WDS_IP_SUPPORT_IPV4, QMI_WDS_IP_SUPPORT_IPV6,
				QMI_WDS_IP_SUPPORT_IPV4V6))
		return -EINVAL;

	if (iptype == QMI_WDS_IP_SUPPORT_IPV4 ||
			iptype == QMI_WDS_IP_SUPPORT_IPV4V6) {
		param = param_from_context(QMI_WDS_IP_FAMILY_IPV4, ctx);

		data->start_network_ipv4_id =
			qmi_service_send(data->ipv4, QMI_WDS_START_NETWORK,
					param, start_network_ipv4_cb,
					cb_data_ref(cbd), cb_data_unref);

		if (!data->start_network_ipv4_id) {
			cb_data_unref(cbd);
			qmi_param_free(param);
		}
	}

	if (iptype == QMI_WDS_IP_SUPPORT_IPV6 ||
			iptype == QMI_WDS_IP_SUPPORT_IPV4V6) {
		param = param_from_context(QMI_WDS_IP_FAMILY_IPV6, ctx);

		data->start_network_ipv6_id =
			qmi_service_send(data->ipv6, QMI_WDS_START_NETWORK,
					param, start_network_ipv6_cb,
					cb_data_ref(cbd), cb_data_unref);

		if (!data->start_network_ipv6_id) {
			cb_data_unref(cbd);
			qmi_param_free(param);
		}
	}

	if (data->start_network_ipv4_id || data->start_network_ipv6_id)
		return 0;

	return -EIO;
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

	if (!qmi_result_set_error(result, &error))
		error = 0;

	DBG("error: %u", error);

	if (error)
		goto error;

	if (!qmi_result_get_uint8(result, RESULT_IP_SUPPORT_TYPE, &iptype))
		goto error;

	if (!start_network(iptype, data, NULL, cbd))
		return;

error:
	data->active_context = 0;
	CALLBACK_WITH_FAILURE(cb, cbd->data);
}

/*
 * This function gets called for "automatic" contexts, those which are
 * not activated via activate_primary.  For these, we will still need
 * to call start_network in order to get the packet handle for the context.
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

	if (qmi_service_send(data->ipv4, QMI_WDS_GET_LTE_ATTACH_PARAMETERS,
				NULL, get_lte_attach_param_cb, cbd,
				cb_data_unref) > 0)
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
	enum ofono_gprs_proto proto = ctx->proto;
	struct cb_data *cbd;
	int ip_type;
	int r;

	DBG("cid %u", ctx->cid);

	if (!L_IN_SET(proto, OFONO_GPRS_PROTO_IP, OFONO_GPRS_PROTO_IPV6,
					OFONO_GPRS_PROTO_IPV4V6))
		goto error;

	ip_type = qmi_wds_ip_support_from_ofono(ctx->proto);
	if (ip_type < 0)
		goto error;

	if (qmi_wds_auth_from_ofono(ctx->auth_method) < 0)
		goto error;

	data->active_context = ctx->cid;
	cbd = cb_data_new(cb, user_data);
	cbd->user = gc;

	r = start_network(ip_type, data, ctx, cbd);
	cb_data_unref(cbd);

	if (!r)
		return;

	data->active_context = 0;
error:
	CALLBACK_WITH_FAILURE(cb, user_data);
}

static uint32_t send_stop_net(struct qmi_service *wds, uint32_t packet_handle,
				qmi_service_result_func_t func,
				void *user_data, qmi_destroy_func_t destroy)
{
	static const uint8_t PARAM_PACKET_HANDLE = 0x01;
	struct qmi_param *param = qmi_param_new_uint32(PARAM_PACKET_HANDLE,
							packet_handle);
	uint32_t id;

	id = qmi_service_send(wds, QMI_WDS_STOP_NETWORK, param,
				func, user_data, destroy);

	if (!id)
		qmi_param_free(param);

	return id;
}

static void stop_net_ipv4_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint16_t error;

	if (!qmi_result_set_error(result, &error))
		error = 0;

	DBG("error: %u", error);

	data->packet_handle_ipv4 = 0;
	data->active_context = 0;

	if (error)
		CALLBACK_WITH_FAILURE(cb, cbd->data);
	else
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void stop_net_ipv6_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint16_t error;

	if (!qmi_result_set_error(result, &error))
		error = 0;

	DBG("error: %u", error);

	data->packet_handle_ipv6 = 0;

	if (data->packet_handle_ipv4) {
		if (send_stop_net(data->ipv4, data->packet_handle_ipv4,
					stop_net_ipv4_cb,
					cb_data_ref(cbd), cb_data_unref))
			return;

		cb_data_unref(cbd);
		data->active_context = 0;
		data->packet_handle_ipv4 = 0;
		goto error;
	} else
		data->active_context = 0;

	if (!error) {
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
		return;
	}
error:
	CALLBACK_WITH_FAILURE(cb, cbd->data);
}

static void qmi_deactivate_primary(struct ofono_gprs_context *gc,
				unsigned int cid,
				ofono_gprs_context_cb_t cb, void *user_data)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd;
	uint32_t id;

	DBG("cid %u", cid);

	if (!data->packet_handle_ipv4 && !data->packet_handle_ipv6)
		goto error;

	cbd = cb_data_new(cb, user_data);
	cbd->user = gc;

	if (data->packet_handle_ipv6)
		id = send_stop_net(data->ipv6, data->packet_handle_ipv6,
					stop_net_ipv6_cb, cbd, cb_data_unref);
	else
		id = send_stop_net(data->ipv4, data->packet_handle_ipv4,
					stop_net_ipv4_cb, cbd, cb_data_unref);

	if (id)
		return;

	data->packet_handle_ipv6 = 0;
	data->packet_handle_ipv4 = 0;
	data->active_context = 0;

	l_free(cbd);
error:
	CALLBACK_WITH_FAILURE(cb, user_data);
}

static void stop_net_detach_ipv4_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint16_t error;

	if (!qmi_result_set_error(result, &error))
		error = 0;

	DBG("error: %u", error);

	data->packet_handle_ipv4 = 0;
	check_all_deactivated(gc);
}

static void stop_net_detach_ipv6_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint16_t error;

	if (!qmi_result_set_error(result, &error))
		error = 0;

	DBG("error: %u", error);

	data->packet_handle_ipv6 = 0;
	check_all_deactivated(gc);
}

static void qmi_gprs_context_detach_shutdown(struct ofono_gprs_context *gc,
						unsigned int cid)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	DBG("");

	if (data->packet_handle_ipv6 &&
			!send_stop_net(data->ipv6, data->packet_handle_ipv6,
					stop_net_detach_ipv6_cb, gc, NULL))
		data->packet_handle_ipv6 = 0;

	if (data->packet_handle_ipv4 &&
			!send_stop_net(data->ipv4, data->packet_handle_ipv4,
					stop_net_detach_ipv4_cb, gc, NULL))
		data->packet_handle_ipv4 = 0;

	if (data->packet_handle_ipv4 || data->packet_handle_ipv6)
		return;

	data->active_context = 0;
}

static void set_ip_family_preference_cb(struct qmi_result *result,
							void *user_data)
{
	struct ofono_gprs_context *gc = user_data;
	uint16_t error;

	if (!qmi_result_set_error(result, &error))
		error = 0;

	DBG("%u", error);

	if (error)
		ofono_gprs_context_remove(gc);
}

static int set_ip_family_preference(struct ofono_gprs_context *gc,
						struct qmi_service *wds,
						uint8_t family)
{
	static const uint8_t PARAM_IP_FAMILY_PREFERENCE = 0x01;
	struct qmi_param *param =
			qmi_param_new_uint8(PARAM_IP_FAMILY_PREFERENCE, family);

	if (qmi_service_send(wds, QMI_WDS_SET_IP_FAMILY, param,
				set_ip_family_preference_cb, gc, NULL) > 0)
		return 0;

	qmi_param_free(param);
	return -EIO;
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
	struct qmi_endpoint_info endpoint_info;
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
	int r;

	DBG("");

	if (mux_id != -1) {
		r = qmi_gprs_context_bind_mux(gc, ipv4, mux_id);
		if (r < 0)
			return r;

		r = qmi_gprs_context_bind_mux(gc, ipv6, mux_id);
		if (r < 0)
			return r;
	}

	/*
	 * Default family preference for new WDS services is IPv4.  For the
	 * service used for IPv6 contexts, issue a SET_IP_FAMILY_PREFERENCE
	 * command
	 */
	r = set_ip_family_preference(gc, ipv6, QMI_WDS_IP_FAMILY_IPV6);
	if (r < 0)
		return r;

	data = l_new(struct gprs_context_data, 1);
	data->ipv4 = l_steal_ptr(ipv4);
	data->ipv6 = l_steal_ptr(ipv6);
	data->mux_id = mux_id;

	qmi_service_register(data->ipv4, QMI_WDS_PACKET_SERVICE_STATUS,
					pkt_status_notify, gc, NULL);
	qmi_service_register(data->ipv6, QMI_WDS_PACKET_SERVICE_STATUS,
					pkt_status_notify, gc, NULL);

	ofono_gprs_context_set_data(gc, data);

	return 0;
}

static void qmi_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	DBG("");

	ofono_gprs_context_set_data(gc, NULL);

	qmi_service_free(data->ipv4);
	qmi_service_free(data->ipv6);
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

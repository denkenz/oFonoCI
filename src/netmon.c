/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2016  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include "ofono.h"
#include "netmonagent.h"

#define CELL_INFO_DICT_APPEND(p_dict, key, info, type, dbus_type)	do { \
	type value; \
	if (info < 0) \
		break; \
	value = (type) info; \
	ofono_dbus_dict_append(p_dict, key, dbus_type, &value); \
} while (0)

struct ofono_netmon {
	const struct ofono_netmon_driver *driver;
	DBusMessage *pending;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter arr;
	void *driver_data;
	struct ofono_atom *atom;
	struct netmon_agent *agent;
};

static const char *cell_type_to_tech_name(enum ofono_netmon_cell_type type)
{
	switch (type) {
	case OFONO_NETMON_CELL_TYPE_GSM:
		return "gsm";
	case OFONO_NETMON_CELL_TYPE_UMTS:
		return "umts";
	case OFONO_NETMON_CELL_TYPE_LTE:
		return "lte";
	}

	return NULL;
}

static void netmon_cell_info_dict_append(DBusMessageIter *dict,
					va_list *arglist, int info_type)
{
	char *mcc;
	char *mnc;
	int intval;
	enum ofono_netmon_info next_info_type = info_type;

	while (next_info_type != OFONO_NETMON_INFO_INVALID) {
		switch (next_info_type) {
		case OFONO_NETMON_INFO_MCC:
			mcc = va_arg(*arglist, char *);

			if (mcc && strlen(mcc))
				ofono_dbus_dict_append(dict,
						"MobileCountryCode",
						DBUS_TYPE_STRING, &mcc);
			break;

		case OFONO_NETMON_INFO_MNC:
			mnc = va_arg(*arglist, char *);

			if (mnc && strlen(mnc))
				ofono_dbus_dict_append(dict,
						"MobileNetworkCode",
						DBUS_TYPE_STRING, &mnc);
			break;

		case OFONO_NETMON_INFO_LAC:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "LocationAreaCode",
					intval, uint16_t, DBUS_TYPE_UINT16);
			break;

		case OFONO_NETMON_INFO_CI:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "CellId",
					intval, uint32_t, DBUS_TYPE_UINT32);
			break;

		case OFONO_NETMON_INFO_ARFCN:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "ARFCN",
					intval, uint16_t, DBUS_TYPE_UINT16);
			break;

		case OFONO_NETMON_INFO_BSIC:
				intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "BSIC",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_RXLEV:
				intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "ReceivedSignalStrength",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_TIMING_ADVANCE:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "TimingAdvance",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_PSC:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "PrimaryScramblingCode",
					intval, uint16_t, DBUS_TYPE_UINT16);
			break;

		case OFONO_NETMON_INFO_BER:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "BitErrorRate",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_RSSI:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "Strength",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_RSCP:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "ReceivedSignalCodePower",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_ECN0:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "ReceivedEnergyRatio",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_RSRQ:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict,
					"ReferenceSignalReceivedQuality",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_RSRP:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict,
					"ReferenceSignalReceivedPower",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_EARFCN:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "EARFCN",
					intval, uint16_t, DBUS_TYPE_UINT16);
			break;

		case OFONO_NETMON_INFO_EBAND:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "EBand",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_CQI:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "ChannelQualityIndicator",
					intval, uint8_t, DBUS_TYPE_BYTE);
			break;

		case OFONO_NETMON_INFO_PCI:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "PhysicalCellId",
					intval, uint16_t, DBUS_TYPE_UINT16);
			break;

		case OFONO_NETMON_INFO_TAC:
			intval = va_arg(*arglist, int);

			CELL_INFO_DICT_APPEND(dict, "TrackingAreaCode",
					intval, uint16_t, DBUS_TYPE_UINT16);
			break;

		case OFONO_NETMON_INFO_SNR:
			intval = va_arg(*arglist, int);

			ofono_dbus_dict_append(dict, "SingalToNoiseRatio",
					DBUS_TYPE_INT32, &intval);
			break;

		case OFONO_NETMON_INFO_INVALID:
			break;
		}

		next_info_type = va_arg(*arglist, int);
	}
}

void ofono_netmon_serving_cell_notify(struct ofono_netmon *netmon,
					enum ofono_netmon_cell_type type,
					int info_type, ...)
{
	va_list arglist;
	DBusMessage *agent_notify = NULL;
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *technology = cell_type_to_tech_name(type);

	if (netmon->pending != NULL) {
		netmon->reply = dbus_message_new_method_return(netmon->pending);
		dbus_message_iter_init_append(netmon->reply, &iter);
	} else if (netmon->agent != NULL) {
		agent_notify = netmon_agent_new_method_call(netmon->agent,
					"ServingCellInformationChanged");

		dbus_message_iter_init_append(agent_notify, &iter);
	} else
		return;

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);

	va_start(arglist, info_type);

	if (technology == NULL)
		goto done;

	ofono_dbus_dict_append(&dict, "Technology",
						DBUS_TYPE_STRING, &technology);

	netmon_cell_info_dict_append(&dict, &arglist, info_type);

done:
	va_end(arglist);

	dbus_message_iter_close_container(&iter, &dict);

	if (agent_notify)
		netmon_agent_send_no_reply(netmon->agent, agent_notify);
}

static void serving_cell_info_callback(const struct ofono_error *error,
		void *data)
{
	struct ofono_netmon *netmon = data;
	DBusMessage *reply = netmon->reply;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		if (reply)
			dbus_message_unref(reply);

		reply = __ofono_error_failed(netmon->pending);
        } else if (!reply) {
		DBusMessageIter iter;
		DBusMessageIter dict;

		reply = dbus_message_new_method_return(netmon->pending);
		dbus_message_iter_init_append(reply, &iter);
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);
		dbus_message_iter_close_container(&iter, &dict);
	}

	netmon->reply = NULL;
	__ofono_dbus_pending_reply(&netmon->pending, reply);
}

static DBusMessage *netmon_get_serving_cell_info(DBusConnection *conn,
			DBusMessage *msg, void *data)
{
	struct ofono_netmon *netmon = data;

	if (!netmon->driver->request_update)
		return __ofono_error_not_implemented(msg);

	if (netmon->pending)
		return __ofono_error_busy(msg);

	netmon->pending = dbus_message_ref(msg);

	netmon->driver->request_update(netmon,
					serving_cell_info_callback, netmon);

	return NULL;
}

static void periodic_updates_enabled_cb(const struct ofono_error *error,
					void *data)
{
	struct ofono_netmon *netmon = data;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		ofono_error("Error enabling periodic updates");

		netmon_agent_free(netmon->agent);
		return;
	}
}

static void periodic_updates_disabled_cb(const struct ofono_error *error,
					void *data)
{
	if (error->type != OFONO_ERROR_TYPE_NO_ERROR)
		ofono_error("Error disabling periodic updates");
}

static void agent_removed_cb(gpointer user_data)
{
	struct ofono_netmon *netmon = user_data;

	netmon->agent = NULL;

	netmon->driver->enable_periodic_update(netmon, 0, 0,
						periodic_updates_disabled_cb,
						NULL);
}

static DBusMessage *netmon_register_agent(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct ofono_netmon *netmon = data;
	const char *agent_path;
	const unsigned int enable = 1;
	unsigned int period;

	if (netmon->agent)
		return __ofono_error_busy(msg);

	if (!netmon->driver->enable_periodic_update)
		return __ofono_error_not_implemented(msg);

	if (dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &agent_path,
				DBUS_TYPE_UINT32, &period,
				DBUS_TYPE_INVALID) == FALSE)
		return __ofono_error_invalid_args(msg);

	if (!dbus_validate_path(agent_path, NULL))
		return __ofono_error_invalid_format(msg);

	if (!period)
		return __ofono_error_invalid_args(msg);

	/* minimum period is 5 seconds, to avoid frequent updates*/
	if (period < 5)
		period = 5;

	netmon->agent = netmon_agent_new(agent_path,
					dbus_message_get_sender(msg));

	if (netmon->agent == NULL)
		return __ofono_error_failed(msg);

	netmon_agent_set_removed_notify(netmon->agent, agent_removed_cb, netmon);

	netmon->driver->enable_periodic_update(netmon, enable, period,
					periodic_updates_enabled_cb, netmon);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *netmon_unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct ofono_netmon *netmon = data;
	const char *agent_path;
	const char *agent_bus = dbus_message_get_sender(msg);

	if (!netmon->driver->enable_periodic_update)
		return __ofono_error_not_implemented(msg);

	if (dbus_message_get_args(msg, NULL,
					DBUS_TYPE_OBJECT_PATH, &agent_path,
					DBUS_TYPE_INVALID) == FALSE)
		return __ofono_error_invalid_args(msg);

	if (netmon->agent == NULL)
		return __ofono_error_failed(msg);

	if (!netmon_agent_matches(netmon->agent, agent_path, agent_bus))
		return __ofono_error_access_denied(msg);

	netmon_agent_free(netmon->agent);

	return dbus_message_new_method_return(msg);
}


void ofono_netmon_neighbouring_cell_notify(struct ofono_netmon *netmon,
					enum ofono_netmon_cell_type type,
					int info_type, ...)
{
	va_list arglist;
	DBusMessageIter dict;
	DBusMessageIter strct;
	const char *tech = cell_type_to_tech_name(type);

	if (netmon->pending == NULL)
		return;

	if (!netmon->reply) {
		netmon->reply = dbus_message_new_method_return(netmon->pending);
		dbus_message_iter_init_append(netmon->reply, &netmon->iter);

		dbus_message_iter_open_container(&netmon->iter, DBUS_TYPE_ARRAY,
					DBUS_STRUCT_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					DBUS_STRUCT_END_CHAR_AS_STRING,
					&netmon->arr);
	}

	tech = cell_type_to_tech_name(type);

	dbus_message_iter_open_container(&netmon->arr, DBUS_TYPE_STRUCT,
						NULL, &strct);
	dbus_message_iter_open_container(&strct, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);

	va_start(arglist, info_type);

	if (tech == NULL)
		goto done;

	ofono_dbus_dict_append(&dict, "Technology",
					DBUS_TYPE_STRING, &tech);

	netmon_cell_info_dict_append(&dict, &arglist, info_type);

done:
	va_end(arglist);

	dbus_message_iter_close_container(&strct, &dict);
	dbus_message_iter_close_container(&netmon->arr, &strct);
}

static void neighbouring_cell_info_callback(const struct ofono_error *error,
						void *data)
{
	struct ofono_netmon *netmon = data;
	DBusMessage *reply = netmon->reply;

	DBG("");

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		if (reply)
			dbus_message_unref(reply);

		reply = __ofono_error_failed(netmon->pending);
        } else if (!reply) {
		DBusMessageIter iter;
		DBusMessageIter dict;

		reply = dbus_message_new_method_return(netmon->pending);
		dbus_message_iter_init_append(reply, &iter);
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);
		dbus_message_iter_close_container(&iter, &dict);
	} else {
		dbus_message_iter_close_container(&netmon->iter, &netmon->arr);
	}

	netmon->reply = NULL;
	__ofono_dbus_pending_reply(&netmon->pending, reply);
}

static DBusMessage *netmon_get_neighbouring_cell_info(DBusConnection *conn,
			DBusMessage *msg, void *data)
{
	struct ofono_netmon *netmon = data;

	if (!netmon->driver->neighbouring_cell_update)
		return __ofono_error_not_implemented(msg);

	if (netmon->pending)
		return __ofono_error_busy(msg);

	netmon->pending = dbus_message_ref(msg);

	netmon->driver->neighbouring_cell_update(netmon,
				neighbouring_cell_info_callback, netmon);

	return NULL;
}

static const GDBusMethodTable netmon_methods[] = {
	{ GDBUS_ASYNC_METHOD("GetServingCellInformation",
			NULL, GDBUS_ARGS({ "cellinfo", "a{sv}" }),
			netmon_get_serving_cell_info) },
	{ GDBUS_METHOD("RegisterAgent",
			GDBUS_ARGS({ "path", "o"}, { "period", "u"}), NULL,
			netmon_register_agent) },
	{ GDBUS_METHOD("UnregisterAgent",
			GDBUS_ARGS({ "agent", "o" }), NULL,
			netmon_unregister_agent) },
	{ GDBUS_ASYNC_METHOD("GetNeighbouringCellInformation",
			NULL, GDBUS_ARGS({ "cellinfo", "a(a{sv})" }),
			netmon_get_neighbouring_cell_info) },
	{ }
};

static void netmon_unregister(struct ofono_atom *atom)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(atom);
	const char *path = __ofono_atom_get_path(atom);

	ofono_modem_remove_interface(modem, OFONO_NETMON_INTERFACE);
	g_dbus_unregister_interface(conn, path, OFONO_NETMON_INTERFACE);
}

static void netmon_remove(struct ofono_atom *atom)
{
	struct ofono_netmon *netmon = __ofono_atom_get_data(atom);

	if (netmon == NULL)
		return;

	if (netmon->driver && netmon->driver->remove)
		netmon->driver->remove(netmon);

	g_free(netmon);
}

OFONO_DEFINE_ATOM_CREATE(netmon, OFONO_ATOM_TYPE_NETMON)

void ofono_netmon_register(struct ofono_netmon *netmon)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(netmon->atom);
	const char *path = __ofono_atom_get_path(netmon->atom);

	if (!g_dbus_register_interface(conn, path,
				OFONO_NETMON_INTERFACE,
				netmon_methods, NULL, NULL,
				netmon, NULL)) {
		ofono_error("Could not create %s interface",
				OFONO_NETMON_INTERFACE);
		return;
	}

	ofono_modem_add_interface(modem, OFONO_NETMON_INTERFACE);

	__ofono_atom_register(netmon->atom, netmon_unregister);
}

void ofono_netmon_remove(struct ofono_netmon *netmon)
{
	__ofono_atom_free(netmon->atom);
}

void ofono_netmon_set_data(struct ofono_netmon *netmon, void *data)
{
	netmon->driver_data = data;
}

void *ofono_netmon_get_data(struct ofono_netmon *netmon)
{
	return netmon->driver_data;
}

/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __OFONO_DBUS_H
#define __OFONO_DBUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dbus/dbus.h>

#define OFONO_SERVICE	"org.ofono"
#define OFONO_MANAGER_INTERFACE "org.ofono.Manager"
#define OFONO_MANAGER_PATH "/"
#define OFONO_MODEM_INTERFACE "org.ofono.Modem"
#define OFONO_CALL_BARRING_INTERFACE "org.ofono.CallBarring"
#define OFONO_CALL_FORWARDING_INTERFACE "org.ofono.CallForwarding"
#define OFONO_CALL_METER_INTERFACE "org.ofono.CallMeter"
#define OFONO_CALL_SETTINGS_INTERFACE "org.ofono.CallSettings"
#define OFONO_CALL_VOLUME_INTERFACE OFONO_SERVICE ".CallVolume"
#define OFONO_CELL_BROADCAST_INTERFACE "org.ofono.CellBroadcast"
#define OFONO_CONNECTION_CONTEXT_INTERFACE "org.ofono.ConnectionContext"
#define OFONO_CONNECTION_MANAGER_INTERFACE "org.ofono.ConnectionManager"
#define OFONO_MESSAGE_MANAGER_INTERFACE "org.ofono.MessageManager"
#define OFONO_MESSAGE_INTERFACE "org.ofono.Message"
#define OFONO_MESSAGE_WAITING_INTERFACE "org.ofono.MessageWaiting"
#define OFONO_SUPPLEMENTARY_SERVICES_INTERFACE "org.ofono.SupplementaryServices"
#define OFONO_NETWORK_REGISTRATION_INTERFACE "org.ofono.NetworkRegistration"
#define OFONO_NETWORK_OPERATOR_INTERFACE "org.ofono.NetworkOperator"
#define OFONO_PHONEBOOK_INTERFACE "org.ofono.Phonebook"
#define OFONO_RADIO_SETTINGS_INTERFACE "org.ofono.RadioSettings"
#define OFONO_AUDIO_SETTINGS_INTERFACE "org.ofono.AudioSettings"
#define OFONO_TEXT_TELEPHONY_INTERFACE "org.ofono.TextTelephony"
#define OFONO_SIM_MANAGER_INTERFACE "org.ofono.SimManager"
#define OFONO_VOICECALL_INTERFACE "org.ofono.VoiceCall"
#define OFONO_VOICECALL_MANAGER_INTERFACE "org.ofono.VoiceCallManager"
#define OFONO_STK_INTERFACE OFONO_SERVICE ".SimToolkit"
#define OFONO_SIM_APP_INTERFACE OFONO_SERVICE ".SimToolkitAgent"
#define OFONO_LOCATION_REPORTING_INTERFACE OFONO_SERVICE ".LocationReporting"
#define OFONO_GNSS_INTERFACE "org.ofono.AssistedSatelliteNavigation"
#define OFONO_GNSS_POSR_AGENT_INTERFACE "org.ofono.PositioningRequestAgent"
#define OFONO_USIM_APPLICATION_INTERFACE "org.ofono.USimApplication"
#define OFONO_ISIM_APPLICATION_INTERFACE "org.ofono.ISimApplication"
#define OFONO_SIM_AUTHENTICATION_INTERFACE "org.ofono.SimAuthentication"
#define OFONO_HANDSFREE_INTERFACE OFONO_SERVICE ".Handsfree"
#define OFONO_SIRI_INTERFACE OFONO_SERVICE ".Siri"
#define OFONO_NETMON_INTERFACE OFONO_SERVICE ".NetworkMonitor"
#define OFONO_NETMON_AGENT_INTERFACE OFONO_SERVICE ".NetworkMonitorAgent"
#define OFONO_LTE_INTERFACE OFONO_SERVICE ".LongTermEvolution"
#define OFONO_IMS_INTERFACE OFONO_SERVICE ".IpMultimediaSystem"

/* Essentially a{sv} */
#define OFONO_PROPERTIES_ARRAY_SIGNATURE DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING \
					DBUS_TYPE_STRING_AS_STRING \
					DBUS_TYPE_VARIANT_AS_STRING \
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING

DBusConnection *ofono_dbus_get_connection(void);

void ofono_dbus_dict_append(DBusMessageIter *dict, const char *key, int type,
				const void *value);

void ofono_dbus_dict_append_array(DBusMessageIter *dict, const char *key,
					int type, const void *val);

void ofono_dbus_dict_append_dict(DBusMessageIter *dict, const char *key,
					int type, const void *val);

int ofono_dbus_signal_property_changed(DBusConnection *conn, const char *path,
					const char *interface, const char *name,
					int type, const void *value);

int ofono_dbus_signal_array_property_changed(DBusConnection *conn,
						const char *path,
						const char *interface,
						const char *name, int type,
						const void *value);

int ofono_dbus_signal_dict_property_changed(DBusConnection *conn,
						const char *path,
						const char *interface,
						const char *name, int type,
						const void *value);

#ifdef __cplusplus
}
#endif

#endif /* __OFONO_DBUS_H */

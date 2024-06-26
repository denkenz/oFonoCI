/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <glib.h>
#include <gdbus.h>

#include "ofono.h"

static void append_modem(struct ofono_modem *modem, void *userdata)
{
	DBusMessageIter *array = userdata;
	const char *path = ofono_modem_get_path(modem);
	DBusMessageIter entry, dict;

	if (ofono_modem_is_registered(modem) == FALSE)
		return;

	dbus_message_iter_open_container(array, DBUS_TYPE_STRUCT,
						NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
					&path);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY,
				OFONO_PROPERTIES_ARRAY_SIGNATURE,
				&dict);

	__ofono_modem_append_properties(modem, &dict);
	dbus_message_iter_close_container(&entry, &dict);
	dbus_message_iter_close_container(array, &entry);
}

static DBusMessage *manager_get_modems(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_STRUCT_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_OBJECT_PATH_AS_STRING
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING
					DBUS_STRUCT_END_CHAR_AS_STRING,
					&array);
	__ofono_modem_foreach(append_modem, &array);
	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("GetModems",
				NULL, GDBUS_ARGS({ "modems", "a(oa{sv})" }),
				manager_get_modems) },
	{ }
};

static const GDBusSignalTable manager_signals[] = {
	{ GDBUS_SIGNAL("ModemAdded",
		GDBUS_ARGS({ "path", "o" }, { "properties", "a{sv}" })) },
	{ GDBUS_SIGNAL("ModemRemoved",
		GDBUS_ARGS({ "path", "o" })) },
	{ }
};

static int manager_init(void)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	gboolean ret;

	ret = g_dbus_register_interface(conn, OFONO_MANAGER_PATH,
					OFONO_MANAGER_INTERFACE,
					manager_methods, manager_signals,
					NULL, NULL, NULL);

	if (ret == FALSE)
		return -1;

	return 0;
}

static void manager_cleanup(void)
{
	DBusConnection *conn = ofono_dbus_get_connection();

	g_dbus_unregister_interface(conn, OFONO_MANAGER_PATH,
					OFONO_MANAGER_INTERFACE);
}

OFONO_MODULE(manager, manager_init, manager_cleanup)

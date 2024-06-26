/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 * Copyright (C) 2011  BMW Car IT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib.h>
#include <gatchat.h>
#include <gatresult.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>

#include <drivers/atmodem/atutil.h>

struct devinfo_data {
	char *device_address;
	guint register_source;
};

static void hfp_query_serial(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb,
				void *data)
{
	struct devinfo_data *dev = ofono_devinfo_get_data(info);
	CALLBACK_WITH_SUCCESS(cb, dev->device_address, data);
}

static gboolean hfp_devinfo_register(gpointer user_data)
{
	struct ofono_devinfo *info = user_data;
	struct devinfo_data *dd = ofono_devinfo_get_data(info);

	dd->register_source = 0;

	ofono_devinfo_register(info);

	return FALSE;
}

static int hfp_devinfo_probe(struct ofono_devinfo *info, unsigned int vendor,
				void *user)
{
	const char *device_address = user;
	struct devinfo_data *dd;

	dd = g_new0(struct devinfo_data, 1);
	dd->device_address = g_strdup(device_address);

	ofono_devinfo_set_data(info, dd);

	dd->register_source = g_idle_add(hfp_devinfo_register, info);
	return 0;
}

static void hfp_devinfo_remove(struct ofono_devinfo *info)
{
	struct devinfo_data *dd = ofono_devinfo_get_data(info);

	ofono_devinfo_set_data(info, NULL);
	if (dd == NULL)
		return;

	if (dd->register_source != 0)
		g_source_remove(dd->register_source);

	g_free(dd->device_address);
	g_free(dd);
}

static const struct ofono_devinfo_driver driver = {
	.probe			= hfp_devinfo_probe,
	.remove			= hfp_devinfo_remove,
	.query_serial		= hfp_query_serial
};

OFONO_ATOM_DRIVER_BUILTIN(devinfo, hfpmodem, &driver)

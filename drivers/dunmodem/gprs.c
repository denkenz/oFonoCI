/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011  BMW Car IT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <gatchat.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs.h>

#include <drivers/atmodem/atutil.h>

static void dun_gprs_set_attached(struct ofono_gprs *gprs, int attached,
						ofono_gprs_cb_t cb, void *data)
{
	DBG("");

	CALLBACK_WITH_SUCCESS(cb, data);
}

static gboolean dun_gprs_finish_registration(gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;

	ofono_gprs_register(gprs);

	return FALSE;
}

static int dun_gprs_probe(struct ofono_gprs *gprs,
					unsigned int vendor, void *data)
{
	DBG("");

	g_idle_add(dun_gprs_finish_registration, gprs);

	return 0;
}

static void dun_gprs_remove(struct ofono_gprs *gprs)
{
	DBG("");
}

static void dun_gprs_attached_status(struct ofono_gprs *gprs,
						ofono_gprs_status_cb_t cb,
						void *data)
{
	DBG("");

	CALLBACK_WITH_SUCCESS(cb, 1, data);
}

static const struct ofono_gprs_driver driver = {
	.probe			= dun_gprs_probe,
	.remove			= dun_gprs_remove,
	.set_attached		= dun_gprs_set_attached,
	.attached_status	= dun_gprs_attached_status,
};

OFONO_ATOM_DRIVER_BUILTIN(gprs, dunmodem, &driver)

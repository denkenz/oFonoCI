/*
 * oFono - Open Source Telephony
 * Copyright (C) 2010  Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2010  ProFUSION embedded systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __OFONO_LOCATION_REPORTING_H
#define __OFONO_LOCATION_REPORTING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>

#include <ofono/types.h>

struct ofono_location_reporting;

enum ofono_location_reporting_type {
	OFONO_LOCATION_REPORTING_TYPE_NMEA = 0,
};

typedef void (*ofono_location_reporting_enable_cb_t)(
						const struct ofono_error *error,
						int fd, void *data);
typedef void (*ofono_location_reporting_disable_cb_t)(
						const struct ofono_error *error,
						void *data);

struct ofono_location_reporting_driver {
	unsigned int flags;
	enum ofono_location_reporting_type type;
	int (*probe)(struct ofono_location_reporting *lr, unsigned int vendor,
								void *data);
	int (*probev)(struct ofono_location_reporting *lr, unsigned int vendor,
								va_list args);
	void (*remove)(struct ofono_location_reporting *lr);
	void (*enable)(struct ofono_location_reporting *lr,
			ofono_location_reporting_enable_cb_t cb, void *data);
	void (*disable)(struct ofono_location_reporting *lr,
			ofono_location_reporting_disable_cb_t cb, void *data);
};

struct ofono_location_reporting *ofono_location_reporting_create(
						struct ofono_modem *modem,
						unsigned int vendor,
						const char *driver, ...);

void ofono_location_reporting_register(struct ofono_location_reporting *lr);
void ofono_location_reporting_remove(struct ofono_location_reporting *lr);

void ofono_location_reporting_set_data(struct ofono_location_reporting *lr,
								void *data);
void *ofono_location_reporting_get_data(struct ofono_location_reporting *lr);

struct ofono_modem *ofono_location_reporting_get_modem(
					struct ofono_location_reporting *lr);

#ifdef __cplusplus
}
#endif

#endif /* __OFONO_LOCATION_REPORTING_H */

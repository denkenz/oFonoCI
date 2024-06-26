/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __OFONO_GPRS_H
#define __OFONO_GPRS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>

#include <ofono/types.h>

struct ofono_gprs;
struct ofono_gprs_context;

typedef void (*ofono_gprs_status_cb_t)(const struct ofono_error *error,
						int status, void *data);

typedef void (*ofono_gprs_cb_t)(const struct ofono_error *error, void *data);

struct ofono_gprs_driver {
	unsigned int flags;
	int (*probe)(struct ofono_gprs *gprs, unsigned int vendor,
			void *data);
	int (*probev)(struct ofono_gprs *gprs, unsigned int vendor,
			va_list args);
	void (*remove)(struct ofono_gprs *gprs);
	void (*set_attached)(struct ofono_gprs *gprs, int attached,
				ofono_gprs_cb_t cb, void *data);
	void (*attached_status)(struct ofono_gprs *gprs,
					ofono_gprs_status_cb_t cb, void *data);
	void (*list_active_contexts)(struct ofono_gprs *gprs,
					ofono_gprs_cb_t cb, void *data);
};

enum gprs_suspend_cause {
	GPRS_SUSPENDED_DETACHED,
	GPRS_SUSPENDED_SIGNALLING,
	GPRS_SUSPENDED_CALL,
	GPRS_SUSPENDED_NO_COVERAGE,
	GPRS_SUSPENDED_UNKNOWN_CAUSE,
};

void ofono_gprs_status_notify(struct ofono_gprs *gprs, int status);
void ofono_gprs_detached_notify(struct ofono_gprs *gprs);
void ofono_gprs_suspend_notify(struct ofono_gprs *gprs, int cause);
void ofono_gprs_resume_notify(struct ofono_gprs *gprs);
void ofono_gprs_bearer_notify(struct ofono_gprs *gprs, int bearer);

struct ofono_modem *ofono_gprs_get_modem(struct ofono_gprs *gprs);

struct ofono_gprs *ofono_gprs_create(struct ofono_modem *modem,
					unsigned int vendor, const char *driver,
					...);
void ofono_gprs_register(struct ofono_gprs *gprs);
void ofono_gprs_remove(struct ofono_gprs *gprs);

void ofono_gprs_set_data(struct ofono_gprs *gprs, void *data);
void *ofono_gprs_get_data(struct ofono_gprs *gprs);

void ofono_gprs_set_cid_range(struct ofono_gprs *gprs,
				unsigned int min, unsigned int max);
void ofono_gprs_add_context(struct ofono_gprs *gprs,
				struct ofono_gprs_context *gc);

void ofono_gprs_cid_activated(struct ofono_gprs  *gprs, unsigned int cid,
				const char *apn);

#ifdef __cplusplus
}
#endif

#endif /* __OFONO_GPRS_H */

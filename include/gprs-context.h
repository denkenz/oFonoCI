/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __OFONO_GPRS_CONTEXT_H
#define __OFONO_GPRS_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>

#include <ofono/types.h>

struct ofono_gprs_context;
struct ofono_modem;

enum ofono_gprs_context_type {
	OFONO_GPRS_CONTEXT_TYPE_ANY = 0,
	OFONO_GPRS_CONTEXT_TYPE_INTERNET	= 0x0001,
	OFONO_GPRS_CONTEXT_TYPE_MMS		= 0x0002,
	OFONO_GPRS_CONTEXT_TYPE_WAP		= 0x0004,
	OFONO_GPRS_CONTEXT_TYPE_IMS		= 0x0008,
	OFONO_GPRS_CONTEXT_TYPE_SUPL		= 0x0010,
	OFONO_GPRS_CONTEXT_TYPE_IA		= 0x0020,
};

struct ofono_gprs_primary_context {
	unsigned int cid;
	char apn[OFONO_GPRS_MAX_APN_LENGTH + 1];
	char username[OFONO_GPRS_MAX_USERNAME_LENGTH + 1];
	char password[OFONO_GPRS_MAX_PASSWORD_LENGTH + 1];
	enum ofono_gprs_proto proto;
	enum ofono_gprs_auth_method auth_method;
};

typedef void (*ofono_gprs_context_cb_t)(const struct ofono_error *error,
					void *data);

struct ofono_gprs_context_driver {
	unsigned int flags;
	int (*probe)(struct ofono_gprs_context *gc, unsigned int vendor,
			void *data);
	int (*probev)(struct ofono_gprs_context *gc, unsigned int vendor,
			va_list args);
	void (*remove)(struct ofono_gprs_context *gc);
	void (*activate_primary)(struct ofono_gprs_context *gc,
				const struct ofono_gprs_primary_context *ctx,
				ofono_gprs_context_cb_t cb, void *data);
	void (*deactivate_primary)(struct ofono_gprs_context *gc,
					unsigned int id,
					ofono_gprs_context_cb_t cb, void *data);
	void (*detach_shutdown)(struct ofono_gprs_context *gc,
					unsigned int id);
	void (*read_settings)(struct ofono_gprs_context *gc,
				unsigned int cid,
				ofono_gprs_context_cb_t cb, void *data);
};

void ofono_gprs_context_deactivated(struct ofono_gprs_context *gc,
					unsigned int id);

struct ofono_gprs_context *ofono_gprs_context_create(struct ofono_modem *modem,
						unsigned int vendor,
						const char *driver, ...);
void ofono_gprs_context_remove(struct ofono_gprs_context *gc);

void ofono_gprs_context_set_data(struct ofono_gprs_context *gc, void *data);
void *ofono_gprs_context_get_data(struct ofono_gprs_context *gc);

struct ofono_modem *ofono_gprs_context_get_modem(struct ofono_gprs_context *gc);

void ofono_gprs_context_set_type(struct ofono_gprs_context *gc,
					enum ofono_gprs_context_type type);
enum ofono_gprs_context_type ofono_gprs_context_get_type(
						struct ofono_gprs_context *gc);

const char *ofono_gprs_context_get_interface(struct ofono_gprs_context *gc);

void ofono_gprs_context_set_interface(struct ofono_gprs_context *gc,
					const char *interface);

void ofono_gprs_context_set_ipv4_address(struct ofono_gprs_context *gc,
						const char *address,
						ofono_bool_t static_ip);
void ofono_gprs_context_set_ipv4_netmask(struct ofono_gprs_context *gc,
						const char *netmask);
void ofono_gprs_context_set_ipv4_prefix_length(struct ofono_gprs_context *gc,
						unsigned int prefix);
void ofono_gprs_context_set_ipv4_gateway(struct ofono_gprs_context *gc,
						const char *gateway);
void ofono_gprs_context_set_ipv4_dns_servers(struct ofono_gprs_context *gc,
						const char **dns);

void ofono_gprs_context_set_ipv6_address(struct ofono_gprs_context *gc,
						const char *address);
void ofono_gprs_context_set_ipv6_prefix_length(struct ofono_gprs_context *gc,
						unsigned char length);
void ofono_gprs_context_set_ipv6_gateway(struct ofono_gprs_context *gc,
						const char *gateway);
void ofono_gprs_context_set_ipv6_dns_servers(struct ofono_gprs_context *gc,
						const char **dns);
#ifdef __cplusplus
}
#endif

#endif /* __OFONO_GPRS_CONTEXT_H */

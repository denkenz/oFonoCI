/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __OFONO_PLUGIN_H
#define __OFONO_PLUGIN_H

#include <ofono/version.h>
#include <ofono/log.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OFONO_API_SUBJECT_TO_CHANGE
#error "Please define OFONO_API_SUBJECT_TO_CHANGE to acknowledge your \
understanding that oFono hasn't reached a stable API."
#endif

#define OFONO_PLUGIN_PRIORITY_LOW      -100
#define OFONO_PLUGIN_PRIORITY_DEFAULT     0
#define OFONO_PLUGIN_PRIORITY_HIGH      100

/**
 * SECTION:plugin
 * @title: Plugin premitives
 * @short_description: Functions for declaring plugins
 */

struct ofono_plugin_desc {
	const char *name;
	const char *description;
	const char *version;
	int priority;
	int (*init) (void);
	void (*exit) (void);
	void *debug_start;
	void *debug_stop;
};

/**
 * OFONO_PLUGIN_DEFINE:
 * @name: plugin name
 * @description: plugin description
 * @version: plugin version string
 * @init: init function called on plugin loading
 * @exit: exit function called on plugin removal
 *
 * Macro for defining a plugin descriptor
 */
#ifdef OFONO_PLUGIN_BUILTIN
#define OFONO_PLUGIN_DEFINE(name, description, version, priority, init, exit) \
		struct ofono_plugin_desc __ofono_builtin_ ## name = { \
			#name, description, version, priority, init, exit \
		};
#else
#define OFONO_PLUGIN_DEFINE(name, description, version, priority, init, exit) \
		extern struct ofono_debug_desc __start___debug[] \
				__attribute__ ((weak, visibility("hidden"))); \
		extern struct ofono_debug_desc __stop___debug[] \
				__attribute__ ((weak, visibility("hidden"))); \
		extern struct ofono_plugin_desc ofono_plugin_desc \
				__attribute__ ((visibility("default"))); \
		struct ofono_plugin_desc ofono_plugin_desc = { \
			#name, description, version, priority, init, exit, \
			__start___debug, __stop___debug \
		};
#endif

#ifdef __cplusplus
}
#endif

#endif /* __OFONO_PLUGIN_H */

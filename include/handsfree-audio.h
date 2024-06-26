/*
 * oFono - Open Source Telephony
 * Copyright (C) 2013  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __OFONO_HANDSFREE_AUDIO_H
#define __OFONO_HANDSFREE_AUDIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ofono/types.h>

struct ofono_handsfree_card;

enum ofono_handsfree_card_type {
	OFONO_HANDSFREE_CARD_TYPE_HANDSFREE,
	OFONO_HANDSFREE_CARD_TYPE_GATEWAY,
};

typedef void (*ofono_handsfree_card_connect_cb_t)(
				const struct ofono_error *error, void *data);

struct ofono_handsfree_card_driver {
	const char *name;
	int (*probe)(struct ofono_handsfree_card *card, unsigned int vendor,
			void *data);
	void (*remove)(struct ofono_handsfree_card *card);
	void (*connect)(struct ofono_handsfree_card *card,
				ofono_handsfree_card_connect_cb_t cb,
				void *data);
	void (*sco_connected_hint)(struct ofono_handsfree_card *card);
};

struct ofono_handsfree_card *ofono_handsfree_card_create(unsigned int vendor,
				enum ofono_handsfree_card_type type,
				const char *driver,
				void *data);
int ofono_handsfree_card_register(struct ofono_handsfree_card *card);
void ofono_handsfree_card_remove(struct ofono_handsfree_card *card);
ofono_bool_t ofono_handsfree_card_set_codec(struct ofono_handsfree_card *card,
							unsigned char codec);

ofono_bool_t ofono_handsfree_audio_has_wideband(void);

ofono_bool_t ofono_handsfree_audio_has_transparent_sco(void);

void ofono_handsfree_card_set_data(struct ofono_handsfree_card *card,
					void *data);
void *ofono_handsfree_card_get_data(struct ofono_handsfree_card *card);

void ofono_handsfree_card_set_remote(struct ofono_handsfree_card *card,
					const char *remote);
const char *ofono_handsfree_card_get_remote(struct ofono_handsfree_card *card);

void ofono_handsfree_card_set_local(struct ofono_handsfree_card *card,
					const char *local);
const char *ofono_handsfree_card_get_local(struct ofono_handsfree_card *card);

int ofono_handsfree_card_connect_sco(struct ofono_handsfree_card *card);

void ofono_handsfree_audio_ref(void);
void ofono_handsfree_audio_unref(void);

int ofono_handsfree_card_driver_register(
				const struct ofono_handsfree_card_driver *d);
void ofono_handsfree_card_driver_unregister(
				const struct ofono_handsfree_card_driver *d);

#ifdef __cplusplus
}
#endif

#endif /* __OFONO_HANDSFREE_AUDIO_H */

/*
 * oFono - Open Source Telephony
 * Copyright (C) 2009-2010  Nokia Corporation and/or its subsidiary(-ies)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __ISIMODEM_UTIL_H
#define __ISIMODEM_UTIL_H

struct isi_cb_data {
	void *cb;
	void *data;
	void *user;
};

static inline struct isi_cb_data *isi_cb_data_new(void *user, void *cb,
							void *data)
{
	struct isi_cb_data *ret;

	ret = g_try_new0(struct isi_cb_data, 1);
	if (ret) {
		ret->cb = cb;
		ret->data = data;
		ret->user = user;
	}
	return ret;
}

#define CALLBACK_WITH_FAILURE(f, args...)		\
	do {						\
		struct ofono_error e;			\
		e.type = OFONO_ERROR_TYPE_FAILURE;	\
		e.error = 0;				\
		f(&e, ##args);				\
	} while (0)

#define CALLBACK_WITH_SUCCESS(f, args...)		\
	do {						\
		struct ofono_error e;			\
		e.type = OFONO_ERROR_TYPE_NO_ERROR;	\
		e.error = 0;				\
		f(&e, ##args);				\
	} while (0)

#define ISI_RESOURCE_DBG(msg)					\
	DBG("QSO: %s [0x%02X] v%03d.%03d",			\
		pn_resource_name(g_isi_msg_resource((msg))),	\
		g_isi_msg_resource((msg)),			\
		g_isi_msg_version_major((msg)),			\
		g_isi_msg_version_minor((msg)));

#define ISI_VERSION_AT_LEAST(ver,maj,min)			\
	((ver) != NULL && ((ver)->major > (maj) ||		\
		((ver)->major == (maj) &&			\
			(ver)->minor >= (min))))

#define ALIGN4(val) (((val) + 3) & ~3)

#define ISI_16BIT(val)						\
	(((val) >> 8) & 0xFF), ((val) & 0xFF)

#define ISI_32BIT(val)						\
	(((val) >> 24) & 0xFF), (((val) >> 16) & 0xFF),		\
	(((val) >> 8) & 0xFF), ((val) & 0xFF)

#endif /* !__ISIMODEM_UTIL_H */

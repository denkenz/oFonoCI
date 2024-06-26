/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include "ofono.h"

struct ofono_watchlist *__ofono_watchlist_new(ofono_destroy_func destroy)
{
	struct ofono_watchlist *watchlist;

	watchlist = g_new0(struct ofono_watchlist, 1);
	watchlist->destroy = destroy;

	return watchlist;
}

unsigned int __ofono_watchlist_add_item(struct ofono_watchlist *watchlist,
					struct ofono_watchlist_item *item)
{
	item->id = ++watchlist->next_id;

	watchlist->items = g_slist_prepend(watchlist->items, item);

	return item->id;
}

gboolean __ofono_watchlist_remove_item(struct ofono_watchlist *watchlist,
					unsigned int id)
{
	struct ofono_watchlist_item *item;
	GSList *p;
	GSList *c;

	p = NULL;
	c = watchlist->items;

	while (c) {
		item = c->data;

		if (item->id != id) {
			p = c;
			c = c->next;
			continue;
		}

		if (p)
			p->next = c->next;
		else
			watchlist->items = c->next;

		if (item->destroy)
			item->destroy(item->notify_data);

		if (watchlist->destroy)
			watchlist->destroy(item);
		g_slist_free_1(c);

		return TRUE;
	}

	return FALSE;
}

void __ofono_watchlist_free(struct ofono_watchlist *watchlist)
{
	struct ofono_watchlist_item *item;
	GSList *l;

	for (l = watchlist->items; l; l = l->next) {
		item = l->data;

		if (item->destroy)
			item->destroy(item->notify_data);

		if (watchlist->destroy)
			watchlist->destroy(item);
	}

	g_slist_free(watchlist->items);
	watchlist->items = NULL;
	g_free(watchlist);
}

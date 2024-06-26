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
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include "ofono.h"

#include "common.h"

#define LEN_MAX 128
#define TYPE_INTERNATIONAL 145

#define PHONEBOOK_FLAG_CACHED 0x1

enum phonebook_number_type {
	TEL_TYPE_HOME,
	TEL_TYPE_MOBILE,
	TEL_TYPE_FAX,
	TEL_TYPE_WORK,
	TEL_TYPE_OTHER,
};

struct ofono_phonebook {
	DBusMessage *pending;
	int storage_index; /* go through all supported storage */
	int flags;
	struct l_string *vcards_builder; /* entries with vcard 3.0 format */
	char *cached_vcards;
	GSList *merge_list; /* cache the entries that may need a merge */
	const struct ofono_phonebook_driver *driver;
	void *driver_data;
	struct ofono_atom *atom;
};

struct phonebook_number {
	char *number;
	int type;
	enum phonebook_number_type category;
};

struct phonebook_person {
	GSList *number_list; /* one person may have more than one numbers */
	char *text;
	int hidden;
	char *group;
	char *email;
	char *sip_uri;
};

static const char *storage_support[] = { "SM", "ME", NULL };
static void export_phonebook(struct ofono_phonebook *pb);

/* according to RFC 2425, the output string may need folding */
static void vcard_printf(struct l_string *str, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	int len_temp, line_number, i;
	unsigned int line_delimit = 75;
	size_t buflen;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	buflen = strlen(buf);
	line_number = strlen(buf) / line_delimit + 1;

	for (i = 0; i < line_number; i++) {
		len_temp = MIN(line_delimit, buflen - line_delimit * i);
		l_string_append_fixed(str,  buf + line_delimit * i, len_temp);
		if (i != line_number - 1)
			l_string_append(str, "\r\n ");
	}

	l_string_append(str, "\r\n");
}

/*
 * According to RFC 2426, we need escape following characters:
 * '\n', '\r', ';', ',', '\'.
 */
static void add_slash(char *dest, const char *src, int len_max, int len)
{
	int i, j;

	for (i = 0, j = 0; i < len && j < len_max; i++, j++) {
		switch (src[i]) {
		case '\n':
			dest[j++] = '\\';
			dest[j] = 'n';
			break;
		case '\r':
			dest[j++] = '\\';
			dest[j] = 'r';
			break;
		case '\\':
		case ';':
		case ',':
			dest[j++] = '\\';
			/* fall through */
		default:
			dest[j] = src[i];
			break;
		}
	}
	dest[j] = 0;
	return;
}

static void vcard_printf_begin(struct l_string *vcards)
{
	vcard_printf(vcards, "BEGIN:VCARD");
	vcard_printf(vcards, "VERSION:3.0");
}

static void vcard_printf_text(struct l_string *vcards, const char *text)
{
	char field[LEN_MAX];
	add_slash(field, text, LEN_MAX, strlen(text));
	vcard_printf(vcards, "FN:%s", field);
}

static void vcard_printf_number(struct l_string *vcards,
					const char *number, int type,
					enum phonebook_number_type category)
{
	char *pref = "", *intl = "", *category_string = "";
	char buf[128];

	if (number == NULL || !strlen(number) || !type)
		return;

	switch (category) {
	case TEL_TYPE_HOME:
		category_string = "HOME,VOICE";
		break;
	case TEL_TYPE_MOBILE:
		category_string = "CELL,VOICE";
		break;
	case TEL_TYPE_FAX:
		category_string = "FAX";
		break;
	case TEL_TYPE_WORK:
		category_string = "WORK,VOICE";
		break;
	case TEL_TYPE_OTHER:
		category_string = "VOICE";
		break;
	}

	if ((type == TYPE_INTERNATIONAL) && (number[0] != '+'))
		intl = "+";

	snprintf(buf, sizeof(buf), "TEL;TYPE=%s%s:%s%s", pref,
			category_string, intl, number);
	vcard_printf(vcards, buf, number);
}

static void vcard_printf_group(struct l_string *vcards, const char *group)
{
	int len = 0;

	if (group)
		len = strlen(group);

	if (len) {
		char field[LEN_MAX];
		add_slash(field, group, LEN_MAX, len);
		vcard_printf(vcards, "CATEGORIES:%s", field);
	}
}

static void vcard_printf_email(struct l_string *vcards, const char *email)
{
	int len = 0;

	if (email)
		len = strlen(email);

	if (len) {
		char field[LEN_MAX];
		add_slash(field, email, LEN_MAX, len);
		vcard_printf(vcards,
				"EMAIL;TYPE=INTERNET:%s", field);
	}
}

static void vcard_printf_sip_uri(struct l_string *vcards, const char *sip_uri)
{
	int len = 0;

	if (sip_uri)
		len = strlen(sip_uri);

	if (len) {
		char field[LEN_MAX];
		add_slash(field, sip_uri, LEN_MAX, len);
		vcard_printf(vcards, "IMPP;TYPE=SIP:%s", field);
	}
}

static void vcard_printf_end(struct l_string *vcards)
{
	vcard_printf(vcards, "END:VCARD");
	vcard_printf(vcards, "");
}

static void print_number(gpointer pointer, gpointer user_data)
{
	struct phonebook_number *pn = pointer;
	struct l_string *vcards = user_data;
	vcard_printf_number(vcards, pn->number, pn->type, pn->category);
}

static void destroy_number(gpointer pointer)
{
	struct phonebook_number *pn = pointer;
	l_free(pn->number);
	g_free(pn);
}

static void print_merged_entry(gpointer pointer, gpointer user_data)
{
	struct phonebook_person *person = pointer;
	struct l_string *vcards = user_data;
	vcard_printf_begin(vcards);
	vcard_printf_text(vcards, person->text);

	g_slist_foreach(person->number_list, print_number, vcards);

	vcard_printf_group(vcards, person->group);
	vcard_printf_email(vcards, person->email);
	vcard_printf_sip_uri(vcards, person->sip_uri);
	vcard_printf_end(vcards);
}

static void destroy_merged_entry(gpointer pointer)
{
	struct phonebook_person *person = pointer;
	l_free(person->text);
	l_free(person->group);
	l_free(person->email);
	l_free(person->sip_uri);

	g_slist_free_full(person->number_list, destroy_number);

	g_free(person);
}

static DBusMessage *generate_export_entries_reply(struct ofono_phonebook *pb,
							DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
							&pb->cached_vcards);

	return reply;
}

static gboolean need_merge(const char *text)
{
	int len;
	char c;

	if (text == NULL)
		return FALSE;

	len = strlen(text);

	if (len < 2)
		return FALSE;

	c = tolower(text[len-1]);

	if ((text[len-2] == '/') &&
			((c == 'w') || (c == 'h') || (c == 'm') || (c == 'o')))
		return TRUE;

	return FALSE;
}

static void merge_field_generic(char **str1, const char *str2)
{
	if ((*str1 == NULL) && (str2 != NULL) && (strlen(str2) != 0))
		*str1 = l_strdup(str2);
}

static void merge_field_number(GSList **l, const char *number, int type, char c)
{
	struct phonebook_number *pn = g_new0(struct phonebook_number, 1);
	enum phonebook_number_type category;

	pn->number = l_strdup(number);
	pn->type = type;
	switch (tolower(c)) {
	case 'w':
		category = TEL_TYPE_WORK;
		break;
	case 'h':
		category = TEL_TYPE_HOME;
		break;
	case 'm':
		category = TEL_TYPE_MOBILE;
		break;
	case 'f':
		category = TEL_TYPE_FAX;
		break;
	case 'o':
	default:
		category = TEL_TYPE_OTHER;
		break;
	}
	pn->category = category;
	*l = g_slist_append(*l, pn);
}

void ofono_phonebook_entry(struct ofono_phonebook *phonebook, int index,
				const char *number, int type,
				const char *text, int hidden,
				const char *group,
				const char *adnumber, int adtype,
				const char *secondtext, const char *email,
				const char *sip_uri, const char *tel_uri)
{
	/* There's really nothing to do */
	if ((number == NULL || number[0] == '\0') &&
			(text == NULL || text[0] == '\0'))
		return;

	/*
	 * We need to collect all the entries that belong to one person,
	 * so that only one vCard will be generated at last.
	 * Entries only differ with '/w', '/h', '/m', etc. in field text
	 * are deemed as entries of one person.
	 */
	if (need_merge(text)) {
		GSList *l;
		size_t len_text = strlen(text) - 2;
		struct phonebook_person *person;

		for (l = phonebook->merge_list; l; l = l->next) {
			person = l->data;
			if (!strncmp(text, person->text, len_text) &&
					(strlen(person->text) == len_text))
				break;
		}

		if (l == NULL) {
			person = g_new0(struct phonebook_person, 1);
			phonebook->merge_list =
				g_slist_prepend(phonebook->merge_list, person);
			person->text = l_strndup(text, len_text);
		}

		merge_field_number(&(person->number_list), number, type,
					text[len_text + 1]);
		merge_field_number(&(person->number_list), adnumber, adtype,
					text[len_text + 1]);

		merge_field_generic(&(person->group), group);
		merge_field_generic(&(person->email), email);
		merge_field_generic(&(person->sip_uri), sip_uri);

		return;
	}

	vcard_printf_begin(phonebook->vcards_builder);

	if (text == NULL || text[0] == '\0')
		vcard_printf_text(phonebook->vcards_builder, number);
	else
		vcard_printf_text(phonebook->vcards_builder, text);

	vcard_printf_number(phonebook->vcards_builder, number, type,
				TEL_TYPE_OTHER);
	vcard_printf_number(phonebook->vcards_builder, adnumber, adtype,
				TEL_TYPE_OTHER);
	vcard_printf_group(phonebook->vcards_builder, group);
	vcard_printf_email(phonebook->vcards_builder, email);
	vcard_printf_sip_uri(phonebook->vcards_builder, sip_uri);
	vcard_printf_end(phonebook->vcards_builder);
}

static void export_phonebook_cb(const struct ofono_error *error, void *data)
{
	struct ofono_phonebook *phonebook = data;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR)
		ofono_error("export_entries_one_storage_cb with %s failed",
				storage_support[phonebook->storage_index]);

	/* convert the collected entries that are already merged to vcard */
	phonebook->merge_list = g_slist_reverse(phonebook->merge_list);
	g_slist_foreach(phonebook->merge_list, print_merged_entry,
				phonebook->vcards_builder);
	g_slist_free_full(phonebook->merge_list, destroy_merged_entry);
	phonebook->merge_list = NULL;

	phonebook->storage_index++;
	export_phonebook(phonebook);
}

static void export_phonebook(struct ofono_phonebook *phonebook)
{
	DBusMessage *reply;
	const char *pb = storage_support[phonebook->storage_index];

	if (pb) {
		phonebook->driver->export_entries(phonebook, pb,
						export_phonebook_cb, phonebook);
		return;
	}

	phonebook->cached_vcards = l_string_unwrap(phonebook->vcards_builder);
	phonebook->vcards_builder = NULL;
	phonebook->flags |= PHONEBOOK_FLAG_CACHED;

	reply = generate_export_entries_reply(phonebook, phonebook->pending);
	if (reply == NULL) {
		dbus_message_unref(phonebook->pending);
		return;
	}

	__ofono_dbus_pending_reply(&phonebook->pending, reply);
}

static DBusMessage *import_entries(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct ofono_phonebook *phonebook = data;

	if (phonebook->pending)
		return  __ofono_error_busy(phonebook->pending);

	if (phonebook->flags & PHONEBOOK_FLAG_CACHED)
		return generate_export_entries_reply(phonebook, msg);

	phonebook->pending = dbus_message_ref(msg);

	phonebook->vcards_builder = l_string_new(0);
	phonebook->storage_index = 0;
	export_phonebook(phonebook);

	return NULL;
}

static const GDBusMethodTable phonebook_methods[] = {
	{ GDBUS_ASYNC_METHOD("Import",
			NULL, GDBUS_ARGS({ "entries", "s" }),
			import_entries) },
	{ }
};

static const GDBusSignalTable phonebook_signals[] = {
	{ }
};

static void phonebook_unregister(struct ofono_atom *atom)
{
	struct ofono_phonebook *pb = __ofono_atom_get_data(atom);
	const char *path = __ofono_atom_get_path(pb->atom);
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(pb->atom);

	ofono_modem_remove_interface(modem, OFONO_PHONEBOOK_INTERFACE);
	g_dbus_unregister_interface(conn, path, OFONO_PHONEBOOK_INTERFACE);
}

static void phonebook_remove(struct ofono_atom *atom)
{
	struct ofono_phonebook *pb = __ofono_atom_get_data(atom);

	DBG("atom: %p", atom);

	if (pb == NULL)
		return;

	if (pb->driver && pb->driver->remove)
		pb->driver->remove(pb);

	l_string_free(pb->vcards_builder);
	l_free(pb->cached_vcards);
	g_free(pb);
}

OFONO_DEFINE_ATOM_CREATE(phonebook, OFONO_ATOM_TYPE_PHONEBOOK)

void ofono_phonebook_register(struct ofono_phonebook *pb)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(pb->atom);
	struct ofono_modem *modem = __ofono_atom_get_modem(pb->atom);

	if (!g_dbus_register_interface(conn, path, OFONO_PHONEBOOK_INTERFACE,
					phonebook_methods, phonebook_signals,
					NULL, pb, NULL)) {
		ofono_error("Could not create %s interface",
				OFONO_PHONEBOOK_INTERFACE);

		return;
	}

	ofono_modem_add_interface(modem, OFONO_PHONEBOOK_INTERFACE);

	__ofono_atom_register(pb->atom, phonebook_unregister);
}

void ofono_phonebook_remove(struct ofono_phonebook *pb)
{
	__ofono_atom_free(pb->atom);
}

void ofono_phonebook_set_data(struct ofono_phonebook *pb, void *data)
{
	pb->driver_data = data;
}

void *ofono_phonebook_get_data(struct ofono_phonebook *pb)
{
	return pb->driver_data;
}

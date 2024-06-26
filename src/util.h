/*
 * oFono - Open Source Telephony
 * Copyright (C) 2008-2011  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdbool.h>

enum gsm_dialect {
	GSM_DIALECT_DEFAULT = 0,
	GSM_DIALECT_TURKISH,
	GSM_DIALECT_SPANISH,
	GSM_DIALECT_PORTUGUESE,
	GSM_DIALECT_BENGALI,
	GSM_DIALECT_GUJARATI,
	GSM_DIALECT_HINDI,
	GSM_DIALECT_KANNADA,
	GSM_DIALECT_MALAYALAM,
	GSM_DIALECT_ORIYA,
	GSM_DIALECT_PUNJABI,
	GSM_DIALECT_TAMIL,
	GSM_DIALECT_TELUGU,
	GSM_DIALECT_URDU,
};

enum cbs_language {
	CBS_LANGUAGE_GERMAN = 0x0,
	CBS_LANGUAGE_ENGLISH = 0x1,
	CBS_LANGUAGE_ITALIAN = 0x2,
	CBS_LANGUAGE_FRENCH = 0x3,
	CBS_LANGUAGE_SPANISH = 0x4,
	CBS_LANGUAGE_DUTCH = 0x5,
	CBS_LANGUAGE_SWEDISH = 0x6,
	CBS_LANGUAGE_DANISH = 0x7,
	CBS_LANGUAGE_PORTUGESE = 0x8,
	CBS_LANGUAGE_FINNISH = 0x9,
	CBS_LANGUAGE_NORWEGIAN = 0xA,
	CBS_LANGUAGE_GREEK = 0xB,
	CBS_LANGUAGE_TURKISH = 0xC,
	CBS_LANGUAGE_HUNGARIAN = 0xD,
	CBS_LANGUAGE_POLISH = 0xE,
	CBS_LANGUAGE_UNSPECIFIED = 0xF,
	CBS_LANGUAGE_CZECH = 0x20,
	CBS_LANGUAGE_HEBREW = 0x21,
	CBS_LANGUAGE_ARABIC = 0x22,
	CBS_LANGUAGE_RUSSIAN = 0x23,
	CBS_LANGUAGE_ICELANDIC = 0x24
};

char *convert_gsm_to_utf8(const unsigned char *text, long len, long *items_read,
				long *items_written, unsigned char terminator);

char *convert_gsm_to_utf8_with_lang(const unsigned char *text, long len,
					long *items_read, long *items_written,
					unsigned char terminator,
					enum gsm_dialect locking_shift_lang,
					enum gsm_dialect single_shift_lang);

unsigned char *convert_utf8_to_gsm(const char *text, long len, long *items_read,
				long *items_written, unsigned char terminator);

unsigned char *convert_utf8_to_gsm_with_lang(const char *text, long len,
					long *items_read, long *items_written,
					unsigned char terminator,
					enum gsm_dialect locking_shift_lang,
					enum gsm_dialect single_shift_lang);

unsigned char *convert_utf8_to_gsm_best_lang(const char *utf8, long len,
					long *items_read, long *items_written,
					unsigned char terminator,
					enum gsm_dialect hint,
					enum gsm_dialect *used_locking,
					enum gsm_dialect *used_single);

unsigned char *decode_hex_own_buf(const char *in, long len, long *items_written,
					unsigned char terminator,
					unsigned char *buf);

char *encode_hex_own_buf(const unsigned char *in, long len,
				unsigned char terminator, char *buf);

unsigned char *unpack_7bit_own_buf(const unsigned char *in, long len,
					int byte_offset, bool ussd,
					long max_to_unpack, long *items_written,
					unsigned char terminator,
					unsigned char *buf);

unsigned char *unpack_7bit(const unsigned char *in, long len, int byte_offset,
				bool ussd, long max_to_unpack,
				long *items_written, unsigned char terminator);

unsigned char *pack_7bit_own_buf(const unsigned char *in, long len,
					int byte_offset, bool ussd,
					long *items_written,
					unsigned char terminator,
					unsigned char *buf);

unsigned char *pack_7bit(const unsigned char *in, long len, int byte_offset,
				bool ussd,
				long *items_written, unsigned char terminator);

char *sim_string_to_utf8(const unsigned char *buffer, int length);

unsigned char *utf8_to_sim_string(const char *utf,
					int max_length, int *out_length);

unsigned char *convert_ucs2_to_gsm_with_lang(const unsigned char *text,
						long len, long *items_read,
						long *items_written,
						unsigned char terminator,
						enum gsm_dialect locking_lang,
						enum gsm_dialect single_lang);

unsigned char *convert_ucs2_to_gsm(const unsigned char *text, long len,
					long *items_read, long *items_written,
					unsigned char terminator);

bool iso639_2_from_language(enum cbs_language lang, char *iso639);

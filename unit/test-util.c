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
#include <strings.h>
#include <stdio.h>
#include <assert.h>
#include <glib.h>
#include <ell/ell.h>

#include "util.h"

static const bool VERBOSE = false;

const unsigned char invalid_gsm_extended[] = {
	0x1b, 0x15
};

const unsigned char invalid_gsm_extended_len[] = {
	0x1b, 0x28, 0x1b
};

const unsigned char invalid_ucs2[] = {
	0x03, 0x93, 0x00, 0x00
};

unsigned short gsm_to_unicode_map[] =
{
0x00,	0x0040,
0x01,	0x00A3,
0x02,	0x0024,
0x03,	0x00A5,
0x04,	0x00E8,
0x05,	0x00E9,
0x06,	0x00F9,
0x07,	0x00EC,
0x08,	0x00F2,
0x09,	0x00C7,
0x0A,	0x000A,
0x0B,	0x00D8,
0x0C,	0x00F8,
0x0D,	0x000D,
0x0E,	0x00C5,
0x0F,	0x00E5,
0x10,	0x0394,
0x11,	0x005F,
0x12,	0x03A6,
0x13,	0x0393,
0x14,	0x039B,
0x15,	0x03A9,
0x16,	0x03A0,
0x17,	0x03A8,
0x18,	0x03A3,
0x19,	0x0398,
0x1A,	0x039E,
/*0x1B,	0x00A0,*/
0x1B0A,	0x000C,
0x1B14,	0x005E,
0x1B28,	0x007B,
0x1B29,	0x007D,
0x1B2F,	0x005C,
0x1B3C,	0x005B,
0x1B3D,	0x007E,
0x1B3E,	0x005D,
0x1B40,	0x007C,
0x1B65,	0x20AC,
0x1C,	0x00C6,
0x1D,	0x00E6,
0x1E,	0x00DF,
0x1F,	0x00C9,
0x20,	0x0020,
0x21,	0x0021,
0x22,	0x0022,
0x23,	0x0023,
0x24,	0x00A4,
0x25,	0x0025,
0x26,	0x0026,
0x27,	0x0027,
0x28,	0x0028,
0x29,	0x0029,
0x2A,	0x002A,
0x2B,	0x002B,
0x2C,	0x002C,
0x2D,	0x002D,
0x2E,	0x002E,
0x2F,	0x002F,
0x30,	0x0030,
0x31,	0x0031,
0x32,	0x0032,
0x33,	0x0033,
0x34,	0x0034,
0x35,	0x0035,
0x36,	0x0036,
0x37,	0x0037,
0x38,	0x0038,
0x39,	0x0039,
0x3A,	0x003A,
0x3B,	0x003B,
0x3C,	0x003C,
0x3D,	0x003D,
0x3E,	0x003E,
0x3F,	0x003F,
0x40,	0x00A1,
0x41,	0x0041,
0x42,	0x0042,
0x43,	0x0043,
0x44,	0x0044,
0x45,	0x0045,
0x46,	0x0046,
0x47,	0x0047,
0x48,	0x0048,
0x49,	0x0049,
0x4A,	0x004A,
0x4B,	0x004B,
0x4C,	0x004C,
0x4D,	0x004D,
0x4E,	0x004E,
0x4F,	0x004F,
0x50,	0x0050,
0x51,	0x0051,
0x52,	0x0052,
0x53,	0x0053,
0x54,	0x0054,
0x55,	0x0055,
0x56,	0x0056,
0x57,	0x0057,
0x58,	0x0058,
0x59,	0x0059,
0x5A,	0x005A,
0x5B,	0x00C4,
0x5C,	0x00D6,
0x5D,	0x00D1,
0x5E,	0x00DC,
0x5F,	0x00A7,
0x60,	0x00BF,
0x61,	0x0061,
0x62,	0x0062,
0x63,	0x0063,
0x64,	0x0064,
0x65,	0x0065,
0x66,	0x0066,
0x67,	0x0067,
0x68,	0x0068,
0x69,	0x0069,
0x6A,	0x006A,
0x6B,	0x006B,
0x6C,	0x006C,
0x6D,	0x006D,
0x6E,	0x006E,
0x6F,	0x006F,
0x70,	0x0070,
0x71,	0x0071,
0x72,	0x0072,
0x73,	0x0073,
0x74,	0x0074,
0x75,	0x0075,
0x76,	0x0076,
0x77,	0x0077,
0x78,	0x0078,
0x79,	0x0079,
0x7A,	0x007A,
0x7B,	0x00E4,
0x7C,	0x00F6,
0x7D,	0x00F1,
0x7E,	0x00FC,
0x7F,	0x00E0,
};

unsigned short gsm_turkish_to_unicode_map[] =
{
0x00, 0x0040,
0x01, 0x00A3,
0x02, 0x0024,
0x03, 0x00A5,
0x04, 0x20AC,
0x05, 0x00E9,
0x06, 0x00F9,
0x07, 0x0131,
0x08, 0x00F2,
0x09, 0x00C7,
0x0A, 0x000A,
0x0B, 0x011E,
0x0C, 0x011F,
0x0D, 0x000D,
0x0E, 0x00C5,
0x0F, 0x00E5,
0x10, 0x0394,
0x11, 0x005F,
0x12, 0x03A6,
0x13, 0x0393,
0x14, 0x039B,
0x15, 0x03A9,
0x16, 0x03A0,
0x17, 0x03A8,
0x18, 0x03A3,
0x19, 0x0398,
0x1A, 0x039E,
/* We're not including some of the single shift codes to this map,
* because the turkish variant isn't symmetric, i.e., the same
* character is present in both the locking shift table as well as the
* single shift table */
0x1B0A, 0x000C,
0x1B14, 0x005E,
0x1B28, 0x007B,
0x1B29, 0x007D,
0x1B2F, 0x005C,
0x1B3C, 0x005B,
0x1B3D, 0x007E,
0x1B3E, 0x005D,
0x1B40, 0x007C,
/*0x1B47, 0x011E,*/
/*0x1B49, 0x0130,*/
/*0x1B53, 0x015E,*/
/*0x1B63, 0x00E7,*/
/*0x1B65, 0x20AC,*/
/*0x1B67, 0x011F,*/
/*0x1B69, 0x0131,*/
/*0x1B73, 0x015F,*/
0x1C, 0x015E,
0x1D, 0x015F,
0x1E, 0x00DF,
0x1F, 0x00C9,
0x20, 0x0020,
0x21, 0x0021,
0x22, 0x0022,
0x23, 0x0023,
0x24, 0x00A4,
0x25, 0x0025,
0x26, 0x0026,
0x27, 0x0027,
0x28, 0x0028,
0x29, 0x0029,
0x2A, 0x002A,
0x2B, 0x002B,
0x2C, 0x002C,
0x2D, 0x002D,
0x2E, 0x002E,
0x2F, 0x002F,
0x30, 0x0030,
0x31, 0x0031,
0x32, 0x0032,
0x33, 0x0033,
0x34, 0x0034,
0x35, 0x0035,
0x36, 0x0036,
0x37, 0x0037,
0x38, 0x0038,
0x39, 0x0039,
0x40, 0x0130,
0x3A, 0x003A,
0x3B, 0x003B,
0x3C, 0x003C,
0x3D, 0x003D,
0x3E, 0x003E,
0x3F, 0x003F,
0x40, 0x0130,
0x41, 0x0041,
0x42, 0x0042,
0x43, 0x0043,
0x44, 0x0044,
0x45, 0x0045,
0x46, 0x0046,
0x47, 0x0047,
0x48, 0x0048,
0x49, 0x0049,
0x4A, 0x004A,
0x4B, 0x004B,
0x4C, 0x004C,
0x4D, 0x004D,
0x4E, 0x004E,
0x4F, 0x004F,
0x50, 0x0050,
0x51, 0x0051,
0x52, 0x0052,
0x53, 0x0053,
0x54, 0x0054,
0x55, 0x0055,
0x56, 0x0056,
0x57, 0x0057,
0x58, 0x0058,
0x59, 0x0059,
0x5A, 0x005A,
0x5B, 0x00C4,
0x5C, 0x00D6,
0x5D, 0x00D1,
0x5E, 0x00DC,
0x5F, 0x00A7,
0x60, 0x00E7,
0x61, 0x0061,
0x62, 0x0062,
0x63, 0x0063,
0x64, 0x0064,
0x65, 0x0065,
0x66, 0x0066,
0x67, 0x0067,
0x68, 0x0068,
0x69, 0x0069,
0x6A, 0x006A,
0x6B, 0x006B,
0x6C, 0x006C,
0x6D, 0x006D,
0x6E, 0x006E,
0x6F, 0x006F,
0x70, 0x0070,
0x71, 0x0071,
0x72, 0x0072,
0x73, 0x0073,
0x74, 0x0074,
0x75, 0x0075,
0x76, 0x0076,
0x77, 0x0077,
0x78, 0x0078,
0x79, 0x0079,
0x7A, 0x007A,
0x7B, 0x00E4,
0x7C, 0x00F6,
0x7D, 0x00F1,
0x7E, 0x00FC,
0x7F, 0x00E0
};

#define UTF8_LENGTH(c) \
	((c) < 0x80 ? 1 : \
	 ((c) < 0x800 ? 2 : 3))

static void test_invalid(void)
{
	long nwritten;
	long nread;
	short unsigned int exp_code;
	long exp_res_length;
	char *res, *exp_res = NULL;
	unsigned char *gsm;

	res = convert_gsm_to_utf8(invalid_gsm_extended, 0, &nread, &nwritten,
					0);
	g_assert(res);
	g_assert(nread == 0);
	g_assert(nwritten == 0);
	g_assert(res[0] == '\0');
	l_free(res);

	/*
	 * In case of invalid GSM extended code, we should display
	 * the character of the main default alphabet table.
	 */
	res = convert_gsm_to_utf8(invalid_gsm_extended,
					sizeof(invalid_gsm_extended),
					&nread, &nwritten, 0);

	exp_code = gsm_to_unicode_map[invalid_gsm_extended[1]*2 + 1];

	exp_res_length = UTF8_LENGTH(exp_code);
	exp_res = l_new(char, exp_res_length + 1);
	l_utf8_from_wchar(exp_code, exp_res);

	g_assert(!strcmp(res, exp_res));
	g_assert(nread == exp_res_length);
	l_free(exp_res);
	l_free(res);

	res = convert_gsm_to_utf8(invalid_gsm_extended_len,
					sizeof(invalid_gsm_extended_len),
					&nread, &nwritten, 0);
	g_assert(res == NULL);
	g_assert(nread == 3);

	gsm = convert_ucs2_to_gsm(invalid_ucs2,
					sizeof(invalid_ucs2),
					&nread, &nwritten, 0);
	g_assert(gsm == NULL);
	g_assert(nread == 2);

	nread = 0;
	gsm = convert_ucs2_to_gsm(invalid_ucs2,
					sizeof(invalid_ucs2) - 1,
					&nread, &nwritten, 0);
	g_assert(gsm == NULL);
	g_assert(nread == 0);
}

static void test_valid(void)
{
	long nwritten;
	long nread;
	char *res;
	int i;
	long size;
	wchar_t verify;
	unsigned char *back;

	unsigned char buf[2];

	static int map_size =
		sizeof(gsm_to_unicode_map) / sizeof(unsigned short) / 2;

	for (i = 0; i < map_size; i++) {
		unsigned short c = gsm_to_unicode_map[i*2];

		if (c & 0x1b00) {
			buf[0] = 0x1b;
			buf[1] = c & 0x7f;
			size = 2;
		} else {
			size = 1;
			buf[0] = c & 0x7f;
		}

		res = convert_gsm_to_utf8(buf, size, &nread, &nwritten, 0);
		g_assert(res);

		if (VERBOSE)
			printf("size: %ld, nread:%ld, nwritten:%ld, %s\n",
				size, nread, nwritten, res);

		g_assert(nread == size);

		g_assert(l_utf8_get_codepoint(res, nwritten, &verify) > 0);
		g_assert(verify == gsm_to_unicode_map[i*2+1]);
		g_assert(nwritten == UTF8_LENGTH(verify));

		back = convert_utf8_to_gsm(res, -1, &nread, &nwritten, 0);
		g_assert(back);
		g_assert(nwritten == size);

		if (c & 0x1b00) {
			g_assert(back[0] == 0x1b);
			g_assert(back[1] == (c & 0x7f));
		} else {
			g_assert(back[0] == (c & 0x7f));
		}

		l_free(back);
		l_free(res);
	}
}

static void test_valid_turkish(void)
{
	long nwritten;
	long nread;
	char *res;
	int i;
	long size;
	wchar_t verify;
	unsigned char *back;

	unsigned char buf[2];

	static int map_size =
		sizeof(gsm_turkish_to_unicode_map) / sizeof(unsigned short) / 2;

	for (i = 0; i < map_size; i++) {
		unsigned short c = gsm_turkish_to_unicode_map[i*2];

		if (c & 0x1b00) {
			buf[0] = 0x1b;
			buf[1] = c & 0x7f;
			size = 2;
		} else {
			size = 1;
			buf[0] = c & 0x7f;
		}

		res = convert_gsm_to_utf8_with_lang(buf, size, &nread,
							&nwritten, 0, 1, 1);
		g_assert(res);

		if (VERBOSE)
			printf("size: %ld, nread:%ld, nwritten:%ld, %s\n",
				size, nread, nwritten, res);

		g_assert(nread == size);

		g_assert(l_utf8_get_codepoint(res, nwritten, &verify) > 0);
		g_assert(verify == gsm_turkish_to_unicode_map[i*2+1]);
		g_assert(nwritten == UTF8_LENGTH(verify));

		back = convert_utf8_to_gsm_with_lang(res, -1, &nread,
							&nwritten, 0, 1, 1);
		g_assert(back);
		g_assert(nwritten == size);

		if (c & 0x1b00) {
			g_assert(back[0] == 0x1b);
			g_assert(back[1] == (c & 0x7f));
		} else {
			g_assert(back[0] == (c & 0x7f));
		}

		l_free(back);
		l_free(res);
	}
}

static const char hex_packed_sms[] = "493A283D0795C3F33C88FE06C9CB6132885EC6D34"
					"1EDF27C1E3E97E7207B3A0C0A5241E377BB1D"
					"7693E72E";
static const char expected[] = "It is easy to read text messages via AT "
				"commands.";
static int reported_text_size = 49;

static void test_decode_encode(void)
{
	const char *sms = hex_packed_sms;
	unsigned char *decoded, *packed;
	char *utf8, *hex_packed;
	unsigned char *gsm, *gsm_encoded;
	size_t hex_decoded_size;
	long unpacked_size, packed_size;
	long gsm_encoded_size;

	if (VERBOSE)
		printf("Size of the orig string: %u\n",
			(unsigned int)strlen(sms));

	decoded = l_util_from_hexstring(sms, &hex_decoded_size);
	g_assert(decoded != NULL);

	if (VERBOSE)
		printf("Decode to %zu bytes\n", hex_decoded_size);

	if (VERBOSE) {
		size_t i;

		printf("%s\n", sms);

		for (i = 0; i < hex_decoded_size; i++)
			printf("%02X", decoded[i]);
		printf("\n");
	}

	gsm = unpack_7bit(decoded, hex_decoded_size, 0, false,
				reported_text_size, &unpacked_size, 0xff);

	g_assert(gsm != NULL);

	if (VERBOSE)
		printf("String unpacked to %ld bytes\n", unpacked_size);

	utf8 = convert_gsm_to_utf8(gsm, -1, NULL, NULL, 0xff);
	g_assert(utf8);

	if (VERBOSE)
		printf("String is: -->%s<--\n", utf8);

	g_assert(strcmp(utf8, expected) == 0);

	gsm_encoded = convert_utf8_to_gsm(utf8, -1, NULL,
						&gsm_encoded_size, 0xff);

	g_assert(gsm_encoded != NULL);

	if (VERBOSE)
		printf("Converted back to GSM string of %ld bytes\n",
				gsm_encoded_size);

	g_assert(gsm_encoded[gsm_encoded_size] == 0xff);
	g_assert(gsm_encoded_size == unpacked_size);
	g_assert(memcmp(gsm_encoded, gsm, gsm_encoded_size) == 0);

	l_free(utf8);
	l_free(gsm);

	packed = pack_7bit(gsm_encoded, -1, 0, false, &packed_size, 0xff);

	l_free(gsm_encoded);

	g_assert(packed != NULL);

	if (VERBOSE)
		printf("Packed GSM to size of %ld bytes\n", packed_size);

	if (VERBOSE) {
		long i;

		for (i = 0; i < packed_size; i++)
			printf("%02X", packed[i]);
		printf("\n");
	}

	g_assert((size_t) packed_size == hex_decoded_size);
	g_assert(memcmp(packed, decoded, packed_size) == 0);
	g_free(decoded);

	hex_packed = l_util_hexstring(packed, packed_size);
	g_assert(hex_packed != NULL);
	l_free(packed);

	if (VERBOSE)
		printf("Hex encoded packed to size %ld bytes\n",
				(long)strlen(hex_packed));

	g_assert(strlen(hex_packed) == strlen(sms));
	g_assert(strcasecmp(hex_packed, sms) == 0);

	l_free(hex_packed);
}

static void test_pack_size(void)
{
	unsigned char c1[] = { 'a' };
	unsigned char c2[] = { 'a', 'b' };
	unsigned char c3[] = { 'a', 'b', 'c' };
	unsigned char c4[] = { 'a', 'b', 'c', 'd' };
	unsigned char c5[] = { 'a', 'b', 'c', 'd', 'e' };
	unsigned char c6[] = { 'a', 'b', 'c', 'd', 'e', 'f' };
	unsigned char c7[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
	unsigned char c8[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };

	unsigned char *packed;
	long size;

	packed = pack_7bit(c1, 1, 0, false, &size, 0);
	g_assert(packed != NULL);
	g_assert(size == 1);
	l_free(packed);

	packed = pack_7bit(c2, 2, 0, false, &size, 0);
	g_assert(packed != NULL);
	g_assert(size == 2);
	l_free(packed);

	packed = pack_7bit(c3, 3, 0, false, &size, 0);
	g_assert(packed != NULL);
	g_assert(size == 3);
	l_free(packed);

	packed = pack_7bit(c4, 4, 0, false, &size, 0);
	g_assert(packed != NULL);
	g_assert(size == 4);
	l_free(packed);

	packed = pack_7bit(c5, 5, 0, false, &size, 0);
	g_assert(packed != NULL);
	g_assert(size == 5);
	l_free(packed);

	packed = pack_7bit(c6, 6, 0, false, &size, 0);
	g_assert(packed != NULL);
	g_assert(size == 6);
	l_free(packed);

	packed = pack_7bit(c7, 7, 0, false, &size, 0);
	g_assert(packed != NULL);
	g_assert(size == 7);
	g_assert((packed[6] & 0xfe) == 0);
	l_free(packed);

	packed = pack_7bit(c7, 7, 0, true, &size, 0);
	g_assert(packed != NULL);
	g_assert(size == 7);
	g_assert(((packed[6] & 0xfe) >> 1) == '\r');
	l_free(packed);

	packed = pack_7bit(c8, 8, 0, false, &size, 0);
	g_assert(packed != NULL);
	g_assert(size == 7);
	l_free(packed);
}

static void test_cr_handling(void)
{
	unsigned char c7[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
	unsigned char c7_expected[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g',
					'\r' };
	unsigned char c8[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', '\r' };
	unsigned char c8_expected[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g',
					'\r', '\r' };

	unsigned char *packed;
	unsigned char *unpacked;
	long packed_size;
	long unpacked_size;

	packed = pack_7bit(c8, 8, 0, true, &packed_size, 0);
	g_assert(packed != NULL);
	g_assert(packed_size == 8);
	g_assert(((packed[6] & 0xfe) >> 1) == '\r');
	g_assert((packed[7] & 0x7f) == '\r');

	unpacked = unpack_7bit(packed, 8, 0, true, -1, &unpacked_size, 0);
	if (VERBOSE)
		printf("Unpacked to size: %ld\n", unpacked_size);

	g_assert(unpacked != NULL);
	g_assert(unpacked_size == 9);
	g_assert(memcmp(c8_expected, unpacked, 9) == 0);

	l_free(unpacked);
	l_free(packed);

	packed = pack_7bit(c7, 7, 0, true, &packed_size, 0);
	g_assert(packed != NULL);
	g_assert(packed_size == 7);
	g_assert(((packed[6] & 0xfe) >> 1) == '\r');

	unpacked = unpack_7bit(packed, 7, 0, true, -1, &unpacked_size, 0);
	if (VERBOSE)
		printf("Unpacked to size: %ld\n", unpacked_size);

	g_assert(unpacked != NULL);
	g_assert(unpacked_size == 7);
	g_assert(memcmp(c7, unpacked, 7) == 0);

	l_free(unpacked);
	l_free(packed);

	/* As above, but now unpack using SMS style, we should now have cr at
	 * the end of the stream
	 */
	packed = pack_7bit(c7, 7, 0, true, &packed_size, 0);
	unpacked = unpack_7bit(packed, 7, 0, false, 8, &unpacked_size, 0);
	if (VERBOSE)
		printf("Unpacked to size: %ld\n", unpacked_size);

	g_assert(unpacked != NULL);
	g_assert(unpacked_size == 8);
	g_assert(memcmp(c7_expected, unpacked, 8) == 0);

	l_free(unpacked);
	l_free(packed);
}

static void test_sms_handling(void)
{
	unsigned char c7[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };

	unsigned char *packed;
	unsigned char *unpacked;
	long packed_size;
	long unpacked_size;

	packed = pack_7bit(c7, 7, 0, FALSE, &packed_size, 0);
	g_assert(packed != NULL);
	g_assert(packed_size == 7);

	unpacked = unpack_7bit(packed, 7, 0, FALSE, 8, &unpacked_size, 0xff);
	if (VERBOSE)
		printf("Unpacked to size: %ld\n", unpacked_size);

	g_assert(unpacked != NULL);
	g_assert(unpacked_size == 8);
	g_assert(unpacked[7] == 0);
	g_assert(unpacked[8] == 0xff);

	l_free(unpacked);
	l_free(packed);

	packed = pack_7bit(c7, 7, 0, FALSE, &packed_size, 0);
	g_assert(packed != NULL);
	g_assert(packed_size == 7);

	unpacked = unpack_7bit(packed, 7, 0, FALSE, 7, &unpacked_size, 0xff);
	if (VERBOSE)
		printf("Unpacked to size: %ld\n", unpacked_size);

	g_assert(unpacked != NULL);
	g_assert(unpacked_size == 7);
	g_assert(unpacked[7] == 0xff);

	l_free(unpacked);
	l_free(packed);
}

static void test_offset_handling(void)
{
	unsigned char c7[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
	unsigned char c8[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };
	unsigned char c9[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i' };
	unsigned char *packed;
	unsigned char *unpacked;
	long packed_size;
	long unpacked_size;

	/* Pack at offset = 2 bytes, e.g. starting with 21st bit */
	packed = pack_7bit(c7, 6, 2, FALSE, &packed_size, 0);

	if (VERBOSE)
		printf("Packed to size: %ld\n", packed_size);

	g_assert(packed != NULL);
	g_assert(packed_size == 6);

	unpacked = unpack_7bit(packed, 6, 2, FALSE, 6, &unpacked_size, 0xff);
	if (VERBOSE)
		printf("Unpacked to size: %ld\n", unpacked_size);

	g_assert(unpacked != NULL);
	g_assert(unpacked_size == 6);
	g_assert(unpacked[6] == 0xff);
	g_assert(unpacked[0] == 'a');
	g_assert(unpacked[5] == 'f');

	l_free(unpacked);
	l_free(packed);

	/* Pack at offset = 6 bytes, we should be able to fit one character
	 * into the first byte, and the other 7 characters into the following
	 * 7 bytes.  The 7 MSB bits of the last byte should be 0 since
	 * we're not using CBS packing
	 */
	packed = pack_7bit(c8, 8, 6, FALSE, &packed_size, 0);

	if (VERBOSE)
		printf("Packed to size: %ld\n", packed_size);

	g_assert(packed != NULL);
	g_assert(packed_size == 8);

	unpacked = unpack_7bit(packed, 8, 6, FALSE, 8, &unpacked_size, 0xff);
	if (VERBOSE)
		printf("Unpacked to size: %ld\n", unpacked_size);

	g_assert(unpacked != NULL);
	g_assert(unpacked_size == 8);
	g_assert(unpacked[8] == 0xff);
	g_assert(unpacked[0] == 'a');
	g_assert(unpacked[7] == 'h');

	l_free(unpacked);
	l_free(packed);

	/* Same as above, but instead pack in 9 characters */
	packed = pack_7bit(c9, 9, 6, FALSE, &packed_size, 0);

	if (VERBOSE)
		printf("Packed to size: %ld\n", packed_size);

	g_assert(packed != NULL);
	g_assert(packed_size == 8);

	unpacked = unpack_7bit(packed, 8, 6, FALSE, 9, &unpacked_size, 0xff);
	if (VERBOSE)
		printf("Unpacked to size: %ld\n", unpacked_size);

	g_assert(unpacked != NULL);
	g_assert(unpacked_size == 9);
	g_assert(unpacked[9] == 0xff);
	g_assert(unpacked[0] == 'a');
	g_assert(unpacked[8] == 'i');

	l_free(unpacked);
	l_free(packed);
}

static unsigned char sim_7bit[] = { 0x6F, 0x46, 0x6F, 0x6E, 0x6F, 0xFF, 0xFF };
static unsigned char sim_80_1[] = { 0x80, 0x00, 0x6F, 0x00, 0x6E, 0x00,
					0x6F };
static unsigned char sim_80_2[] = { 0x80, 0x00, 0x6F, 0x00, 0x6E, 0x00,
					0x6F, 0xFF, 0xFF, 0xFF};
static unsigned char sim_80_3[] = { 0x80, 0x00, 0x6F, 0x00, 0x6E, 0x00,
					0x6F, 0xFF, 0xFF};
static unsigned char sim_81_0[] = { 0x81, 0x05, 0x13, 0x53, 0x95, 0xA6,
					0xA6, 0xFF, 0xFF };
static unsigned char sim_81_1[] = { 0x81, 0x03, 0x00, 0x6F, 0x6E, 0x6F, 0xFF };
static unsigned char sim_81_2[] = { 0x81, 0x05, 0x08, 0xB3, 0xB4, 0xB5, 0x53,
					0x54, 0xFF, 0xFF, 0xFF };
static unsigned char sim_82_0[] = { 0x82, 0x05, 0x05, 0x30, 0x2D, 0x82,
					0xD3, 0x2D, 0x31 };
static unsigned char sim_82_1[] = { 0x82, 0x05, 0x04, 0x00, 0x2D, 0xB3, 0xB4,
					0x2D, 0x31 };
static unsigned char sim_82_2[] = { 0x82, 0x05, 0xD8, 0x00, 0x2D, 0xB3, 0xB4,
					0x2D, 0x31 };
static unsigned char sim_7bit_empty[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static void test_sim(void)
{
	char *utf8;

	utf8 = sim_string_to_utf8(sim_7bit, sizeof(sim_7bit));

	g_assert(utf8);
	g_assert(strcmp(utf8, "oFono") == 0);
	l_free(utf8);

	utf8 = sim_string_to_utf8(sim_80_1, sizeof(sim_80_1));
	g_assert(utf8);
	g_assert(strcmp(utf8, "ono") == 0);
	l_free(utf8);

	utf8 = sim_string_to_utf8(sim_80_2, sizeof(sim_80_2));
	g_assert(utf8);
	g_assert(strcmp(utf8, "ono") == 0);
	l_free(utf8);

	utf8 = sim_string_to_utf8(sim_80_3, sizeof(sim_80_3));
	g_assert(utf8);
	g_assert(strcmp(utf8, "ono") == 0);
	l_free(utf8);

	utf8 = sim_string_to_utf8(sim_81_0, sizeof(sim_81_0));
	g_assert(utf8);
	l_free(utf8);

	utf8 = sim_string_to_utf8(sim_81_2, sizeof(sim_81_2));
	g_assert(utf8);
	l_free(utf8);

	utf8 = sim_string_to_utf8(sim_81_1, sizeof(sim_81_1));
	g_assert(utf8);
	g_assert(strcmp(utf8, "ono") == 0);
	l_free(utf8);

	utf8 = sim_string_to_utf8(sim_82_0, sizeof(sim_82_0));
	g_assert(utf8);
	l_free(utf8);

	utf8 = sim_string_to_utf8(sim_82_1, sizeof(sim_82_1));
	g_assert(utf8);
	l_free(utf8);

	utf8 = sim_string_to_utf8(sim_82_2, sizeof(sim_82_2));
	g_assert(utf8 == NULL);

	utf8 = sim_string_to_utf8(sim_7bit_empty, sizeof(sim_7bit_empty));
	g_assert(utf8);
	g_assert(strcmp(utf8, "") == 0);
	l_free(utf8);
}

static void test_unicode_to_gsm(void)
{
	long nwritten;
	long nread;
	int i;
	unsigned char *res;
	char *utf8;
	unsigned char buf[2];
	unsigned char *back;
	uint16_t verify;

	static int map_size =
		sizeof(gsm_to_unicode_map) / sizeof(unsigned short) / 2;

	for (i = 0; i < map_size; i++) {
		unsigned short c = gsm_to_unicode_map[i*2+1];

		buf[0] = c >> 8;
		buf[1] = c & 0xff;

		res = convert_ucs2_to_gsm(buf, 2, &nread, &nwritten, 0);
		g_assert(res);

		if (VERBOSE)
			printf("nread:%ld, nwritten:%ld, %s\n",
				nread, nwritten, res);

		if (res[0] == 0x1B)
			g_assert(nwritten == 2);
		else
			g_assert(nwritten == 1);

		utf8 = l_utf8_from_ucs2be(buf, 2);
		g_assert(utf8);

		back = convert_utf8_to_gsm(utf8, strlen(utf8), &nread,
						&nwritten, 0);
		g_assert(back);

		if (back[0] == 0x1B) {
			g_assert(nwritten == 2);
			verify = back[0] << 8 | back[1];
		} else {
			g_assert(nwritten == 1);
			verify = back[0];
		}

		if (VERBOSE)
			printf("nwritten:%ld, verify: 0x%x\n",
				nwritten, verify);

		g_assert(verify == gsm_to_unicode_map[i*2]);

		l_free(res);
		l_free(back);
		l_free(utf8);
	}
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/testutil/Invalid Conversions", test_invalid);
	g_test_add_func("/testutil/Valid Conversions", test_valid);
	g_test_add_func("/testutil/Valid Turkish National Variant Conversions",
			test_valid_turkish);
	g_test_add_func("/testutil/Decode Encode", test_decode_encode);
	g_test_add_func("/testutil/Pack Size", test_pack_size);
	g_test_add_func("/testutil/CBS CR Handling", test_cr_handling);
	g_test_add_func("/testutil/SMS Handling", test_sms_handling);
	g_test_add_func("/testutil/Offset Handling", test_offset_handling);
	g_test_add_func("/testutil/SIM conversions", test_sim);
	g_test_add_func("/testutil/Valid Unicode to GSM Conversion",
			test_unicode_to_gsm);

	return g_test_run();
}

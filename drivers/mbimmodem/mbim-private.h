/*
 * oFono - Open Source Telephony
 * Copyright (C) 2017  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define align_len(len, boundary) (((len)+(boundary)-1) & ~((boundary)-1))

enum mbim_control_message {
	MBIM_OPEN_MSG = 0x1,
	MBIM_CLOSE_MSG = 0x2,
	MBIM_COMMAND_MSG = 0x3,
	MBIM_HOST_ERROR_MSG = 0x4,
	MBIM_OPEN_DONE = 0x80000001,
	MBIM_CLOSE_DONE = 0x80000002,
	MBIM_COMMAND_DONE = 0x80000003,
	MBIM_FUNCTION_ERROR_MSG = 0x80000004,
	MBIM_INDICATE_STATUS_MSG = 0x80000007,
};

/* MBIM v1.0, Section 9.1 */
struct mbim_message_header {
	__le32 type;
	__le32 len;
	__le32 tid;
} __attribute__ ((packed));

/* MBIM v1.0, Section 9.1 */
struct mbim_fragment_header {
	__le32 num_frags;
	__le32 cur_frag;
} __attribute__ ((packed));

struct mbim_message *_mbim_message_build(const void *header,
						struct iovec *frags,
						uint32_t n_frags);
struct mbim_message *_mbim_message_new_command_done(const uint8_t *uuid,
					uint32_t cid, uint32_t status);
uint32_t _mbim_information_buffer_offset(uint32_t type);
void _mbim_message_set_tid(struct mbim_message *message, uint32_t tid);
void *_mbim_message_to_bytearray(struct mbim_message *message, size_t *out_len);
void *_mbim_message_get_header(struct mbim_message *message, size_t *out_len);
struct iovec *_mbim_message_get_body(struct mbim_message *message,
					size_t *out_n_iov, size_t *out_len);

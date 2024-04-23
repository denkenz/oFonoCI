/*
 * oFono - Open Source Telephony
 * Copyright (C) 2024  Cruise, LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

enum wwan_port_type {
	WWAN_PORT_AT,
	WWAN_PORT_MBIM,
	WWAN_PORT_QMI,
	WWAN_PORT_QCDM,
	WWAN_PORT_FIREHOSE,
	WWAN_PORT_XMMRPC,
	WWAN_PORT_FASTBOOT,
};

struct metadata {
	uint64_t timestamp;
	char comm[16];
	char path[64];
	uint32_t pid;
	enum wwan_port_type type;
	uint16_t len;
	uint8_t rx;
} __attribute__ ((packed));

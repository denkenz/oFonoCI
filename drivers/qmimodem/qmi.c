/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <linux/qrtr.h>
#include <sys/socket.h>

#include <ell/ell.h>

#include <ofono/log.h>

#include "qmi.h"
#include "ctl.h"

#define DISCOVER_TIMEOUT 5

typedef void (*qmi_message_func_t)(uint16_t message, uint16_t length,
					const void *buffer, void *user_data);

struct discovery {
	qmi_destroy_func_t destroy;
};

struct qmi_service_info {
	uint32_t service_type;
	uint32_t qrtr_port;		/* Always 0 on qmux */
	uint32_t qrtr_node;		/* Always 0 on qmux */
	uint16_t major;
	uint16_t minor;			/* Always 0 on qrtr */
	uint32_t instance;		/* Always 0 on qmux */
};

struct qmi_request {
	uint16_t tid;
	unsigned int group_id;		/* Always 0 for control */
	unsigned int service_handle;	/* Always 0 for control */
	uint8_t client;			/* Always 0 for control and qrtr */
	struct qmi_service_info info;	/* Not used for control requests */
	qmi_message_func_t callback;
	void *user_data;
	uint16_t len;
	uint8_t data[];
};

struct qmi_device_ops {
	int (*write)(struct qmi_device *device, struct qmi_request *req);
	int (*discover)(struct qmi_device *device,
			qmi_discover_func_t discover_func,
			void *user, qmi_destroy_func_t destroy);
	int (*client_create)(struct qmi_device *device,
				uint16_t service_type,
				qmi_create_func_t func,
				void *user, qmi_destroy_func_t destroy);
	void (*client_release)(struct qmi_device *device,
				uint16_t service_type, uint16_t client_id);
	int (*shutdown)(struct qmi_device *device,
			qmi_shutdown_func_t shutdown_func,
			void *user, qmi_destroy_func_t destroy);
	void (*destroy)(struct qmi_device *device);
};

struct qmi_device {
	struct l_io *io;
	struct l_queue *req_queue;
	struct l_queue *service_queue;
	struct l_queue *discovery_queue;
	unsigned int next_group_id;	/* Matches requests with services */
	unsigned int next_service_handle;
	uint16_t next_service_tid;
	qmi_debug_func_t debug_func;
	void *debug_data;
	struct l_queue *service_infos;
	struct l_hashmap *family_list;
	const struct qmi_device_ops *ops;
	bool writer_active : 1;
	bool shutting_down : 1;
	bool destroyed : 1;
};

struct qmi_device_qmux {
	struct qmi_device super;
	uint16_t control_major;
	uint16_t control_minor;
	char *version_str;
	qmi_shutdown_func_t shutdown_func;
	void *shutdown_user_data;
	qmi_destroy_func_t shutdown_destroy;
	struct l_idle *shutdown_idle;
	unsigned int release_users;
	uint8_t next_control_tid;
	struct l_queue *control_queue;
	struct l_queue *pending_families;
};

struct service_family {
	int ref_count;
	struct qmi_device *device;
	struct qmi_service_info info;
	unsigned int group_id;
	uint8_t client_id;
	uint16_t next_notify_id;
	struct l_queue *notify_list;
};

struct qmi_service {
	unsigned int handle;	/* Uniquely identifies this client's reqs */
	struct service_family *family;
};

struct qmi_param {
	void *data;
	uint16_t length;
};

struct qmi_result {
	uint16_t message;
	uint16_t result;
	uint16_t error;
	const void *data;
	uint16_t length;
};

struct qmi_notify {
	uint16_t id;
	uint16_t message;
	unsigned int service_handle;
	qmi_result_func_t callback;
	void *user_data;
	qmi_destroy_func_t destroy;
};

struct qmi_mux_hdr {
	uint8_t  frame;		/* Always 0x01 */
	uint16_t length;	/* Packet size without frame byte */
	uint8_t  flags;		/* Either 0x00 or 0x80 */
	uint8_t  service;	/* Service type (0x00 for control) */
	uint8_t  client;	/* Client identifier (0x00 for control) */
} __attribute__ ((packed));
#define QMI_MUX_HDR_SIZE 6

struct qmi_control_hdr {
	uint8_t  type;		/* Bit 1 = response, Bit 2 = indication */
	uint8_t  transaction;	/* Transaction identifier */
} __attribute__ ((packed));
#define QMI_CONTROL_HDR_SIZE 2

struct qmi_service_hdr {
	uint8_t  type;		/* Bit 2 = response, Bit 3 = indication */
	uint16_t transaction;	/* Transaction identifier */
} __attribute__ ((packed));
#define QMI_SERVICE_HDR_SIZE 3

struct qmi_message_hdr {
	uint16_t message;	/* Message identifier */
	uint16_t length;	/* Message size without header */
	uint8_t data[0];
} __attribute__ ((packed));
#define QMI_MESSAGE_HDR_SIZE 4

struct qmi_tlv_hdr {
	uint8_t type;
	uint16_t length;
	uint8_t value[0];
} __attribute__ ((packed));
#define QMI_TLV_HDR_SIZE 3

void qmi_free(void *ptr)
{
	l_free(ptr);
}

static bool qmi_service_info_matches(const void *data, const void *user)
{
	const struct qmi_service_info *info = data;
	const struct qmi_service_info *match = user;

	if (info->service_type != match->service_type)
		return false;

	if (info->qrtr_node != match->qrtr_node)
		return false;

	if (info->qrtr_port != match->qrtr_port)
		return false;

	return true;
}

static void __qmi_service_appeared(struct qmi_device *device,
					const struct qmi_service_info *info)
{
	if (l_queue_find(device->service_infos, qmi_service_info_matches, info))
		return;

	l_queue_push_tail(device->service_infos,
				l_memdup(info, sizeof(struct qmi_service_info)));
}

static struct qmi_request *__request_alloc(uint32_t service_type,
				uint8_t client, uint16_t message,
				const void *data,
				uint16_t length, qmi_message_func_t func,
				void *user_data)
{
	struct qmi_request *req;
	struct qmi_mux_hdr *hdr;
	struct qmi_message_hdr *msg;
	uint16_t hdrlen = QMI_MUX_HDR_SIZE;
	uint16_t msglen;

	if (service_type == QMI_SERVICE_CONTROL)
		hdrlen += QMI_CONTROL_HDR_SIZE;
	else
		hdrlen += QMI_SERVICE_HDR_SIZE;

	msglen = hdrlen + QMI_MESSAGE_HDR_SIZE + length;
	req = l_malloc(sizeof(struct qmi_request) + msglen);
	req->tid = 0;
	req->group_id = 0;
	req->service_handle = 0;
	req->len = msglen;
	req->client = client;

	hdr = (struct qmi_mux_hdr *) req->data;

	hdr->frame = 0x01;
	hdr->length = L_CPU_TO_LE16(req->len - 1);
	hdr->flags = 0x00;
	hdr->service = service_type; /* qmux service types are 8 bits */
	hdr->client = client;

	msg = (struct qmi_message_hdr *) &req->data[hdrlen];

	msg->message = L_CPU_TO_LE16(message);
	msg->length = L_CPU_TO_LE16(length);

	if (data && length > 0)
		memcpy(req->data + hdrlen + QMI_MESSAGE_HDR_SIZE, data, length);

	req->callback = func;
	req->user_data = user_data;

	return req;
}

static struct qmi_request *__control_request_alloc(uint16_t message,
				const void *data, uint16_t length,
				qmi_message_func_t func, void *user_data)
{
	return __request_alloc(QMI_SERVICE_CONTROL, 0x00, message,
					data, length, func, user_data);
}

static struct qmi_request *__service_request_alloc(
				struct qmi_service_info *info,
				uint8_t client, uint16_t message,
				const void *data, uint16_t length,
				qmi_message_func_t func, void *user_data)
{
	struct qmi_request *req;

	req = __request_alloc(info->service_type, client, message,
						data, length, func, user_data);
	memcpy(&req->info, info, sizeof(req->info));

	return req;
}

static void __request_free(void *data)
{
	struct qmi_request *req = data;

	l_free(req);
}

static bool __request_compare(const void *a, const void *b)
{
	const struct qmi_request *req = a;
	uint16_t tid = L_PTR_TO_UINT(b);

	return req->tid == tid;
}

static void __discovery_free(void *data)
{
	struct discovery *d = data;
	qmi_destroy_func_t destroy = d->destroy;

	destroy(d);
}

static void __notify_free(void *data)
{
	struct qmi_notify *notify = data;

	if (notify->destroy)
		notify->destroy(notify->user_data);

	l_free(notify);
}

struct notify_compare_details {
	uint16_t id;
	unsigned int service_handle;
};

static bool __notify_compare(const void *data, const void *user_data)
{
	const struct qmi_notify *notify = data;
	const struct notify_compare_details *details = user_data;

	return notify->id == details->id &&
			notify->service_handle == details->service_handle;
}

static const char *__service_type_to_string(uint8_t type)
{
	switch (type) {
	case QMI_SERVICE_CONTROL:
		return "CTL";
	case QMI_SERVICE_WDS:
		return "WDS";
	case QMI_SERVICE_DMS:
		return "DMS";
	case QMI_SERVICE_NAS:
		return "NAS";
	case QMI_SERVICE_QOS:
		return "QOS";
	case QMI_SERVICE_WMS:
		return "WMS";
	case QMI_SERVICE_PDS:
		return "PDS";
	case QMI_SERVICE_AUTH:
		return "AUTH";
	case QMI_SERVICE_AT:
		return "AT";
	case QMI_SERVICE_VOICE:
		return "VOICE";
	case QMI_SERVICE_CAT:
		return "CAT";
	case QMI_SERVICE_UIM:
		return "UIM";
	case QMI_SERVICE_PBM:
		return "PBM";
	case QMI_SERVICE_QCHAT:
		return "QCHAT";
	case QMI_SERVICE_RMTFS:
		return "RMTFS";
	case QMI_SERVICE_TEST:
		return "TEST";
	case QMI_SERVICE_LOC:
		return "LOC";
	case QMI_SERVICE_SAR:
		return "SAR";
	case QMI_SERVICE_CSD:
		return "CSD";
	case QMI_SERVICE_EFS:
		return "EFS";
	case QMI_SERVICE_TS:
		return "TS";
	case QMI_SERVICE_TMD:
		return "TMD";
	case QMI_SERVICE_WDA:
		return "WDA";
	case QMI_SERVICE_CSVT:
		return "CSVT";
	case QMI_SERVICE_COEX:
		return "COEX";
	case QMI_SERVICE_PDC:
		return "PDC";
	case QMI_SERVICE_RFRPE:
		return "RFRPE";
	case QMI_SERVICE_DSD:
		return "DSD";
	case QMI_SERVICE_SSCTL:
		return "SSCTL";
	case QMI_SERVICE_CAT_OLD:
		return "CAT";
	case QMI_SERVICE_RMS:
		return "RMS";
	case QMI_SERVICE_OMA:
		return "OMA";
	}

	return NULL;
}

static const struct {
	uint16_t err;
	const char *str;
} __error_table[] = {
	{ 0x0000, "NONE"			},
	{ 0x0001, "MALFORMED_MSG"		},
	{ 0x0002, "NO_MEMORY"			},
	{ 0x0003, "INTERNAL"			},
	{ 0x0004, "ABORTED"			},
	{ 0x0005, "CLIENT_IDS_EXHAUSTED"	},
	{ 0x0006, "UNABORTABLE_TRANSACTION"	},
	{ 0x0007, "INVALID_CLIENT_ID"		},
	{ 0x0008, "NO_THRESHOLDS"		},
	{ 0x0009, "INVALID_HANDLE"		},
	{ 0x000a, "INVALID_PROFILE"		},
	{ 0x000b, "INVALID_PINID"		},
	{ 0x000c, "INCORRECT_PIN"		},
	{ 0x000d, "NO_NETWORK_FOUND"		},
	{ 0x000e, "CALL_FAILED"			},
	{ 0x000f, "OUT_OF_CALL"			},
	{ 0x0010, "NOT_PROVISIONED"		},
	{ 0x0011, "MISSING_ARG"			},
	{ 0x0013, "ARG_TOO_LONG"		},
	{ 0x0016, "INVALID_TX_ID"		},
	{ 0x0017, "DEVICE_IN_USE"		},
	{ 0x0018, "OP_NETWORK_UNSUPPORTED"	},
	{ 0x0019, "OP_DEVICE_UNSUPPORTED"	},
	{ 0x001a, "NO_EFFECT"			},
	{ 0x001b, "NO_FREE_PROFILE"		},
	{ 0x001c, "INVALID_PDP_TYPE"		},
	{ 0x001d, "INVALID_TECH_PREF"		},
	{ 0x001e, "INVALID_PROFILE_TYPE"	},
	{ 0x001f, "INVALID_SERVICE_TYPE"	},
	{ 0x0020, "INVALID_REGISTER_ACTION"	},
	{ 0x0021, "INVALID_PS_ATTACH_ACTION"	},
	{ 0x0022, "AUTHENTICATION_FAILED"	},
	{ 0x0023, "PIN_BLOCKED"			},
	{ 0x0024, "PIN_PERM_BLOCKED"		},
	{ 0x0025, "UIM_NOT_INITIALIZED"		},
	{ 0x0026, "MAX_QOS_REQUESTS_IN_USE"	},
	{ 0x0027, "INCORRECT_FLOW_FILTER"	},
	{ 0x0028, "NETWORK_QOS_UNAWARE"		},
	{ 0x0029, "INVALID_QOS_ID/INVALID_ID"	},
	{ 0x002a, "REQUESTED_NUM_UNSUPPORTED"	},
	{ 0x002b, "INTERFACE_NOT_FOUND"		},
	{ 0x002c, "FLOW_SUSPENDED"		},
	{ 0x002d, "INVALID_DATA_FORMAT"		},
	{ 0x002e, "GENERAL"			},
	{ 0x002f, "UNKNOWN"			},
	{ 0x0030, "INVALID_ARG"			},
	{ 0x0031, "INVALID_INDEX"		},
	{ 0x0032, "NO_ENTRY"			},
	{ 0x0033, "DEVICE_STORAGE_FULL"		},
	{ 0x0034, "DEVICE_NOT_READY"		},
	{ 0x0035, "NETWORK_NOT_READY"		},
	{ 0x0036, "CAUSE_CODE"			},
	{ 0x0037, "MESSAGE_NOT_SENT"		},
	{ 0x0038, "MESSAGE_DELIVERY_FAILURE"	},
	{ 0x0039, "INVALID_MESSAGE_ID"		},
	{ 0x003a, "ENCODING"			},
	{ 0x003b, "AUTHENTICATION_LOCK"		},
	{ 0x003c, "INVALID_TRANSACTION"		},
	{ 0x0041, "SESSION_INACTIVE"		},
	{ 0x0042, "SESSION_INVALID"		},
	{ 0x0043, "SESSION_OWNERSHIP"		},
	{ 0x0044, "INSUFFICIENT_RESOURCES"	},
	{ 0x0045, "DISABLED"			},
	{ 0x0046, "INVALID_OPERATION"		},
	{ 0x0047, "INVALID_QMI_CMD"		},
	{ 0x0048, "TPDU_TYPE"			},
	{ 0x0049, "SMSC_ADDR"			},
	{ 0x004a, "INFO_UNAVAILABLE"		},
	{ 0x004b, "SEGMENT_TOO_LONG"		},
	{ 0x004c, "SEGEMENT_ORDER"		},
	{ 0x004d, "BUNDLING_NOT_SUPPORTED"	},
	{ 0x004f, "POLICY_MISMATCH"		},
	{ 0x0050, "SIM_FILE_NOT_FOUND"		},
	{ 0x0051, "EXTENDED_INTERNAL"		},
	{ 0x0052, "ACCESS_DENIED"		},
	{ 0x0053, "HARDWARE_RESTRICTED"		},
	{ 0x0054, "ACK_NOT_SENT"		},
	{ 0x0055, "INJECT_TIMEOUT"		},
	{ 0x005c, "SUPS_FAILURE_CAUSE"		},
	{ }
};

static const char *__error_to_string(uint16_t error)
{
	int i;

	for (i = 0; __error_table[i].str; i++) {
		if (__error_table[i].err == error)
			return __error_table[i].str;
	}

	return NULL;
}

int qmi_error_to_ofono_cme(int qmi_error)
{
	switch (qmi_error) {
	case 0x0019:
		return 4; /* Not Supported */
	case 0x0052:
		return 32; /* Access Denied */
	default:
		return -1;
	}
}

static void __debug_msg(char dir, const struct qmi_message_hdr *msg,
			uint32_t service_type, uint8_t transaction_type,
			uint16_t tid, uint8_t client, uint16_t overall_length,
			qmi_debug_func_t function, void *user_data)
{
	const char *service;
	const void *ptr = msg + 1;
	uint16_t offset;
	char strbuf[72 + 16], *str;
	bool pending_print = false;
	const char *transaction_type_string;

	if (!function)
		return;

	str = strbuf;
	service = __service_type_to_string(service_type);
	if (service)
		str += sprintf(str, "%c   %s", dir, service);
	else
		str += sprintf(str, "%c   %d", dir, service_type);

	switch (transaction_type) {
	case 0x00:
		transaction_type_string = "_req";
		break;
	case 0x01:
		transaction_type_string = "_resp";
		break;
	case 0x02:
		transaction_type_string = "_ind";
		break;
	default:
		transaction_type_string = "";
		break;
	}

	str += sprintf(str, "%s msg=%d len=%d", transaction_type_string,
				L_LE16_TO_CPU(msg->message),
				L_LE16_TO_CPU(msg->length));

	str += sprintf(str, " [client=%d,type=%d,tid=%d,len=%d]",
				client, transaction_type, tid, overall_length);

	function(strbuf, user_data);

	if (!msg->length)
		return;

	str = strbuf;
	str += sprintf(str, "      ");
	offset = 0;

	while (offset + QMI_TLV_HDR_SIZE < L_LE16_TO_CPU(msg->length)) {
		const struct qmi_tlv_hdr *tlv = ptr + offset;
		uint16_t tlv_length = L_LE16_TO_CPU(tlv->length);

		if (tlv->type == 0x02 && tlv_length == QMI_RESULT_CODE_SIZE) {
			const struct qmi_result_code *result = ptr + offset +
							QMI_TLV_HDR_SIZE;
			uint16_t error = L_LE16_TO_CPU(result->error);
			const char *error_str;

			error_str = __error_to_string(error);
			if (error_str)
				str += sprintf(str, " {type=%d,error=%s}",
							tlv->type, error_str);
			else
				str += sprintf(str, " {type=%d,error=%d}",
							tlv->type, error);
		} else {
			str += sprintf(str, " {type=%d,len=%d}", tlv->type,
								tlv_length);
		}

		if (str - strbuf > 60) {
			function(strbuf, user_data);

			str = strbuf;
			str += sprintf(str, "      ");

			pending_print = false;
		} else
			pending_print = true;

		offset += QMI_TLV_HDR_SIZE + tlv_length;
	}

	if (pending_print)
		function(strbuf, user_data);
}

static void __qmux_debug_msg(const char dir, const void *buf, size_t len,
				qmi_debug_func_t function, void *user_data)
{
	const struct qmi_mux_hdr *hdr;
	const struct qmi_message_hdr *msg;
	uint8_t transaction_type;
	uint16_t tid;

	if (!len)
		return;

	hdr = buf;

	if (hdr->service == QMI_SERVICE_CONTROL) {
		const struct qmi_control_hdr *ctl;

		ctl = buf + QMI_MUX_HDR_SIZE;
		msg = buf + QMI_MUX_HDR_SIZE + QMI_CONTROL_HDR_SIZE;

		transaction_type = ctl->type;
		tid = ctl->transaction;
	} else {
		const struct qmi_service_hdr *srv;

		srv = buf + QMI_MUX_HDR_SIZE;
		msg = buf + QMI_MUX_HDR_SIZE + QMI_SERVICE_HDR_SIZE;

		transaction_type = srv->type >> 1;
		tid = L_LE16_TO_CPU(srv->transaction);
	}

	__debug_msg(dir, msg, hdr->service, transaction_type, tid, hdr->client,
			L_LE16_TO_CPU(hdr->length), function, user_data);
}

static void __qrtr_debug_msg(const char dir, const void *buf, size_t len,
				uint32_t service_type,
				qmi_debug_func_t function, void *user_data)
{
	const struct qmi_service_hdr *srv;
	const struct qmi_message_hdr *msg;
	uint16_t tid;

	if (!len)
		return;

	srv = buf;
	msg = buf + QMI_SERVICE_HDR_SIZE;

	tid = L_LE16_TO_CPU(srv->transaction);

	__debug_msg(dir, msg, service_type, srv->type >> 1, tid, 0, len,
						function, user_data);
}

static void __debug_device(struct qmi_device *device,
					const char *format, ...)
{
	char strbuf[72 + 16];
	va_list ap;

	if (!device->debug_func)
		return;

	va_start(ap, format);
	vsnprintf(strbuf, sizeof(strbuf), format, ap);
	va_end(ap);

	device->debug_func(strbuf, device->debug_data);
}

static bool can_write_data(struct l_io *io, void *user_data)
{
	struct qmi_device *device = user_data;
	struct qmi_request *req;
	int r;

	req = l_queue_pop_head(device->req_queue);
	if (!req)
		return false;

	r = device->ops->write(device, req);
	if (r < 0) {
		__request_free(req);
		return false;
	}

	if (l_queue_length(device->req_queue) > 0)
		return true;

	return false;
}

static void write_watch_destroy(void *user_data)
{
	struct qmi_device *device = user_data;

	device->writer_active = false;
}

static void wakeup_writer(struct qmi_device *device)
{
	if (device->writer_active)
		return;

	l_io_set_write_handler(device->io, can_write_data, device,
				write_watch_destroy);

	device->writer_active = true;
}

static uint16_t __service_request_submit(struct qmi_device *device,
						struct qmi_service *service,
						struct qmi_request *req)
{
	struct qmi_service_hdr *hdr =
		(struct qmi_service_hdr *) &req->data[QMI_MUX_HDR_SIZE];

	req->tid = device->next_service_tid++;

	if (device->next_service_tid < 256)
		device->next_service_tid = 256;

	req->group_id = service->family->group_id;
	req->service_handle = service->handle;

	hdr->type = 0x00;
	hdr->transaction = L_CPU_TO_LE16(req->tid);

	l_queue_push_tail(device->req_queue, req);
	wakeup_writer(device);

	return req->tid;
}

static void service_notify_if_message_matches(void *data, void *user_data)
{
	struct qmi_notify *notify = data;
	struct qmi_result *result = user_data;

	if (notify->message == result->message)
		notify->callback(result, notify->user_data);
}

static void service_notify(const void *key, void *value, void *user_data)
{
	struct service_family *family = value;
	struct qmi_result *result = user_data;

	l_queue_foreach(family->notify_list, service_notify_if_message_matches,
				result);
}

static unsigned int family_list_create_hash(uint16_t service_type,
							uint8_t client_id)
{
	return (service_type | (client_id << 16));
}

static void handle_indication(struct qmi_device *device,
			uint32_t service_type, uint8_t client_id,
			uint16_t message, uint16_t length, const void *data)
{
	struct service_family *family;
	struct qmi_result result;
	unsigned int hash_id;

	if (service_type == QMI_SERVICE_CONTROL)
		return;

	result.result = 0;
	result.error = 0;
	result.message = message;
	result.data = data;
	result.length = length;

	if (client_id == 0xff) {
		l_hashmap_foreach(device->family_list, service_notify,
					&result);
		return;
	}

	hash_id = family_list_create_hash(service_type, client_id);
	family = l_hashmap_lookup(device->family_list,
					L_UINT_TO_PTR(hash_id));

	if (!family)
		return;

	service_notify(NULL, family, &result);
}

static void __rx_message(struct qmi_device *device,
				uint32_t service_type, uint8_t client_id,
				const void *buf)
{
	const struct qmi_service_hdr *service = buf;
	const struct qmi_message_hdr *msg = buf + QMI_SERVICE_HDR_SIZE;
	const void *data = buf + QMI_SERVICE_HDR_SIZE + QMI_MESSAGE_HDR_SIZE;
	struct qmi_request *req;
	unsigned int tid;
	uint16_t message;
	uint16_t length;

	message = L_LE16_TO_CPU(msg->message);
	length = L_LE16_TO_CPU(msg->length);
	tid = L_LE16_TO_CPU(service->transaction);

	if (service->type == 0x04) {
		handle_indication(device, service_type, client_id,
					message, length, data);
		return;
	}

	req = l_queue_remove_if(device->service_queue, __request_compare,
						L_UINT_TO_PTR(tid));
	if (!req)
		return;

	if (req->callback)
		req->callback(message, length, data, req->user_data);

	__request_free(req);
}

static void __qmi_device_discovery_started(struct qmi_device *device,
						struct discovery *d)
{
	l_queue_push_tail(device->discovery_queue, d);
}

static void __qmi_device_discovery_complete(struct qmi_device *device,
						struct discovery *d)
{
	if (!l_queue_remove(device->discovery_queue, d))
		return;
}

/*
 * Prevents re-entrancy problems by removing the entry from the discovery_queue
 * before calling the callback.
 */
#define DISCOVERY_DONE(data, ...)\
do {\
	__qmi_device_discovery_complete(data->device, &data->super);\
\
	if (data->func)\
		data->func(__VA_ARGS__);\
\
	__discovery_free(&data->super);\
} while (0)

static void family_destroy(void *data)
{
	struct service_family *family = data;

	if (!family->device)
		return;

	family->device = NULL;
}

static int qmi_device_init(struct qmi_device *device, int fd,
					const struct qmi_device_ops *ops)
{
	long flags;

	__debug_device(device, "device %p new", device);

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags < 0)
		return -EIO;

	if (!(flags & O_NONBLOCK)) {
		int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);

		if (r < 0)
			return -errno;
	}

	device->io = l_io_new(fd);
	l_io_set_close_on_destroy(device->io, true);

	device->req_queue = l_queue_new();
	device->service_queue = l_queue_new();
	device->discovery_queue = l_queue_new();
	device->service_infos = l_queue_new();
	device->family_list = l_hashmap_new();

	device->next_service_tid = 256;

	device->ops = ops;

	return 0;
}

static void __qmi_device_shutdown_finished(struct qmi_device *device)
{
	if (device->destroyed)
		device->ops->destroy(device);
}

void qmi_device_free(struct qmi_device *device)
{
	if (!device)
		return;

	__debug_device(device, "device %p free", device);

	l_queue_destroy(device->service_queue, __request_free);
	l_queue_destroy(device->req_queue, __request_free);
	l_queue_destroy(device->discovery_queue, __discovery_free);

	l_io_destroy(device->io);

	l_hashmap_destroy(device->family_list, family_destroy);

	l_queue_destroy(device->service_infos, l_free);

	if (device->shutting_down)
		device->destroyed = true;
	else
		device->ops->destroy(device);
}

void qmi_device_set_debug(struct qmi_device *device,
				qmi_debug_func_t func, void *user_data)
{
	if (device == NULL)
		return;

	device->debug_func = func;
	device->debug_data = user_data;
}

void qmi_result_print_tlvs(struct qmi_result *result)
{
	const void *ptr = result->data;
	uint16_t len = result->length;

	while (len > QMI_TLV_HDR_SIZE) {
		const struct qmi_tlv_hdr *tlv = ptr;
		uint16_t tlv_length = L_LE16_TO_CPU(tlv->length);

		DBG("tlv: 0x%02x len 0x%04x", tlv->type, tlv->length);

		ptr += QMI_TLV_HDR_SIZE + tlv_length;
		len -= QMI_TLV_HDR_SIZE + tlv_length;
	}
}

static const void *tlv_get(const void *data, uint16_t size,
					uint8_t type, uint16_t *length)
{
	const void *ptr = data;
	uint16_t len = size;

	while (len > QMI_TLV_HDR_SIZE) {
		const struct qmi_tlv_hdr *tlv = ptr;
		uint16_t tlv_length = L_LE16_TO_CPU(tlv->length);

		if (tlv->type == type) {
			if (length)
				*length = tlv_length;

			return ptr + QMI_TLV_HDR_SIZE;
		}

		ptr += QMI_TLV_HDR_SIZE + tlv_length;
		len -= QMI_TLV_HDR_SIZE + tlv_length;
	}

	return NULL;
}

static const struct qmi_service_info *__find_service_info_by_type(
				struct qmi_device *device, uint16_t type)
{
	const struct qmi_service_info *info = NULL;
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(device->service_infos);
						entry; entry = entry->next) {
		struct qmi_service_info *data = entry->data;

		if (data->service_type == type) {
			info = data;
			break;
		}
	}

	return info;
}

bool qmi_device_get_service_version(struct qmi_device *device, uint16_t type,
					uint16_t *major, uint16_t *minor)
{
	const struct qmi_service_info *info;

	info = __find_service_info_by_type(device, type);
	if (!info)
		return false;

	*major = info->major;
	*minor = info->minor;
	return true;
}

bool qmi_device_has_service(struct qmi_device *device, uint16_t type)
{
	return __find_service_info_by_type(device, type);
}

struct discover_data {
	struct discovery super;
	struct qmi_device *device;
	qmi_discover_func_t func;
	void *user_data;
	qmi_destroy_func_t destroy;
	uint16_t tid;
	struct l_timeout *timeout;
};

static void discover_data_free(void *user_data)
{
	struct discover_data *data = user_data;

	if (data->timeout)
		l_timeout_remove(data->timeout);

	if (data->destroy)
		data->destroy(data->user_data);

	l_free(data);
}

int qmi_device_discover(struct qmi_device *device, qmi_discover_func_t func,
				void *user_data, qmi_destroy_func_t destroy)
{
	if (!device)
		return -EINVAL;

	if (!device->ops->discover)
		return -ENOTSUP;

	return device->ops->discover(device, func, user_data, destroy);
}

int qmi_device_shutdown(struct qmi_device *device, qmi_shutdown_func_t func,
				void *user_data, qmi_destroy_func_t destroy)
{
	if (!device)
		return -EINVAL;

	if (!device->ops->shutdown)
		return -ENOTSUP;

	return device->ops->shutdown(device, func, user_data, destroy);
}

static bool get_device_file_name(struct qmi_device *device,
					char *file_name, int size)
{
	pid_t pid;
	char temp[100];
	ssize_t result;
	int fd = l_io_get_fd(device->io);

	if (size <= 0)
		return false;

	pid = getpid();

	snprintf(temp, 100, "/proc/%d/fd/%d", (int) pid, fd);
	temp[99] = 0;

	result = readlink(temp, file_name, size - 1);

	if (result == -1 || result >= size - 1) {
		DBG("Error %d in readlink", errno);
		return false;
	}

	file_name[result] = 0;

	return true;
}

static char *get_first_dir_in_directory(char *dir_path)
{
	DIR *dir;
	struct dirent *dir_entry;
	char *dir_name = NULL;

	dir = opendir(dir_path);

	if (!dir)
		return NULL;

	dir_entry = readdir(dir);

	while ((dir_entry != NULL)) {
		if (dir_entry->d_type == DT_DIR &&
				strcmp(dir_entry->d_name, ".") != 0 &&
				strcmp(dir_entry->d_name, "..") != 0) {
			dir_name = l_strdup(dir_entry->d_name);
			break;
		}

		dir_entry = readdir(dir);
	}

	closedir(dir);
	return dir_name;
}

static char *get_device_interface(struct qmi_device *device)
{
	char * const driver_names[] = { "usbmisc", "usb" };
	unsigned int i;
	char file_path[PATH_MAX];
	const char *file_name;
	char *interface = NULL;

	if (!get_device_file_name(device, file_path, sizeof(file_path)))
		return NULL;

	file_name = l_basename(file_path);

	for (i = 0; i < L_ARRAY_SIZE(driver_names) && !interface; i++) {
		char *sysfs_path;

		sysfs_path = l_strdup_printf("/sys/class/%s/%s/device/net/",
						driver_names[i], file_name);
		interface = get_first_dir_in_directory(sysfs_path);
		l_free(sysfs_path);
	}

	return interface;
}

enum qmi_device_expected_data_format qmi_device_get_expected_data_format(
						struct qmi_device *device)
{
	char *sysfs_path = NULL;
	char *interface = NULL;
	int fd = -1;
	char value;
	enum qmi_device_expected_data_format expected =
					QMI_DEVICE_EXPECTED_DATA_FORMAT_UNKNOWN;

	if (!device)
		goto done;

	interface = get_device_interface(device);

	if (!interface) {
		DBG("Error while getting interface name");
		goto done;
	}

	/* Build sysfs file path and open it */
	sysfs_path = l_strdup_printf("/sys/class/net/%s/qmi/raw_ip", interface);

	fd = open(sysfs_path, O_RDONLY);
	if (fd < 0) {
		/* maybe not supported by kernel */
		DBG("Error %d in open(%s)", errno, sysfs_path);
		goto done;
	}

	if (read(fd, &value, 1) != 1) {
		DBG("Error %d in read(%s)", errno, sysfs_path);
		goto done;
	}

	if (value == 'Y')
		expected = QMI_DEVICE_EXPECTED_DATA_FORMAT_RAW_IP;
	else if (value == 'N')
		expected = QMI_DEVICE_EXPECTED_DATA_FORMAT_802_3;
	else
		DBG("Unexpected sysfs file contents");

done:
	if (fd >= 0)
		close(fd);

	if (sysfs_path)
		l_free(sysfs_path);

	if (interface)
		l_free(interface);

	return expected;
}

bool qmi_device_set_expected_data_format(struct qmi_device *device,
			enum qmi_device_expected_data_format format)
{
	bool res = false;
	char *sysfs_path = NULL;
	char *interface = NULL;
	int fd = -1;
	char value;

	if (!device)
		goto done;

	switch (format) {
	case QMI_DEVICE_EXPECTED_DATA_FORMAT_802_3:
		value = 'N';
		break;
	case QMI_DEVICE_EXPECTED_DATA_FORMAT_RAW_IP:
		value = 'Y';
		break;
	default:
		DBG("Unhandled format: %d", (int) format);
		goto done;
	}

	interface = get_device_interface(device);

	if (!interface) {
		DBG("Error while getting interface name");
		goto done;
	}

	/* Build sysfs file path and open it */
	sysfs_path = l_strdup_printf("/sys/class/net/%s/qmi/raw_ip", interface);

	fd = open(sysfs_path, O_WRONLY);
	if (fd < 0) {
		/* maybe not supported by kernel */
		DBG("Error %d in open(%s)", errno, sysfs_path);
		goto done;
	}

	if (write(fd, &value, 1) != 1) {
		DBG("Error %d in write(%s)", errno, sysfs_path);
		goto done;
	}

	res = true;

done:
	if (fd >= 0)
		close(fd);

	if (sysfs_path)
		l_free(sysfs_path);

	if (interface)
		l_free(interface);

	return res;
}

static int qmi_device_qmux_write(struct qmi_device *device,
					struct qmi_request *req)
{
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);
	struct qmi_mux_hdr *hdr;
	ssize_t bytes_written;

	bytes_written = write(l_io_get_fd(device->io), req->data, req->len);
	if (bytes_written < 0)
		return -errno;

	l_util_hexdump(false, req->data, bytes_written,
			device->debug_func, device->debug_data);

	__qmux_debug_msg(' ', req->data, bytes_written,
				device->debug_func, device->debug_data);

	hdr = (struct qmi_mux_hdr *) req->data;

	if (hdr->service == QMI_SERVICE_CONTROL)
		l_queue_push_tail(qmux->control_queue, req);
	else
		l_queue_push_tail(device->service_queue, req);

	return 0;
}

static void __rx_ctl_message(struct qmi_device_qmux *qmux,
				uint8_t service_type, uint8_t client_id,
				const void *buf)
{
	const struct qmi_control_hdr *control = buf;
	const struct qmi_message_hdr *msg = buf + QMI_CONTROL_HDR_SIZE;
	const void *data = buf + QMI_CONTROL_HDR_SIZE + QMI_MESSAGE_HDR_SIZE;
	struct qmi_request *req;
	uint16_t message;
	uint16_t length;

	/* Ignore control messages with client identifier */
	if (client_id != 0x00)
		return;

	message = L_LE16_TO_CPU(msg->message);
	length = L_LE16_TO_CPU(msg->length);

	if (control->type == 0x02 && control->transaction == 0x00) {
		handle_indication(&qmux->super, service_type, client_id,
					message, length, data);
		return;
	}

	req = l_queue_remove_if(qmux->control_queue, __request_compare,
					L_UINT_TO_PTR(control->transaction));
	if (!req)
		return;

	if (req->callback)
		req->callback(message, length, data, req->user_data);

	__request_free(req);
}

static bool received_qmux_data(struct l_io *io, void *user_data)
{
	struct qmi_device_qmux *qmux = user_data;
	struct qmi_mux_hdr *hdr;
	unsigned char buf[2048];
	ssize_t bytes_read;
	uint16_t offset;

	bytes_read = read(l_io_get_fd(qmux->super.io), buf, sizeof(buf));
	if (bytes_read < 0)
		return true;

	l_util_hexdump(true, buf, bytes_read,
			qmux->super.debug_func, qmux->super.debug_data);

	offset = 0;

	while (offset < bytes_read) {
		uint16_t len;
		const void *msg;

		/* Check if QMI mux header fits into packet */
		if (bytes_read - offset < QMI_MUX_HDR_SIZE)
			break;

		hdr = (void *) (buf + offset);

		/* Check for fixed frame and flags value */
		if (hdr->frame != 0x01 || hdr->flags != 0x80)
			break;

		len = L_LE16_TO_CPU(hdr->length) + 1;

		/* Check that packet size matches frame size */
		if (bytes_read - offset < len)
			break;

		__qmux_debug_msg(' ', buf + offset, len,
				qmux->super.debug_func, qmux->super.debug_data);

		msg = buf + offset + QMI_MUX_HDR_SIZE;

		if (hdr->service == QMI_SERVICE_CONTROL)
			__rx_ctl_message(qmux, hdr->service, hdr->client, msg);
		else
			__rx_message(&qmux->super,
					hdr->service, hdr->client, msg);

		offset += len;
	}

	return true;
}

static struct service_family *service_family_ref(struct service_family *family)
{
	family->ref_count++;

	return family;
}

static void service_family_unref(struct service_family *family)
{
	struct qmi_device *device;

	if (--family->ref_count)
		return;

	device = family->device;
	if (!device)
		goto done;

	if (family->client_id) {
		unsigned int hash_id =
			family_list_create_hash(family->info.service_type,
							family->client_id);
		l_hashmap_remove(device->family_list, L_UINT_TO_PTR(hash_id));
	}

	l_hashmap_remove(device->family_list,
				L_UINT_TO_PTR(family->info.service_type));

	if (device->ops->client_release)
		device->ops->client_release(device, family->info.service_type,
							family->client_id);

done:
	l_queue_destroy(family->notify_list, NULL);
	l_free(family);
}

struct service_create_shared_data {
	struct discovery super;
	uint16_t service_type;
	struct service_family *family;
	struct qmi_device *device;
	qmi_create_func_t func;
	void *user_data;
	qmi_destroy_func_t destroy;
	struct l_idle *idle;
};

static uint8_t __ctl_request_submit(struct qmi_device_qmux *qmux,
					struct qmi_request *req)
{
	struct qmi_control_hdr *hdr =
		(struct qmi_control_hdr *) &req->data[QMI_MUX_HDR_SIZE];

	hdr->type = 0x00;
	hdr->transaction = qmux->next_control_tid++;

	if (qmux->next_control_tid == 0)
		qmux->next_control_tid = 1;

	req->tid = hdr->transaction;

	l_queue_push_tail(qmux->super.req_queue, req);
	wakeup_writer(&qmux->super);

	return req->tid;
}

static struct service_family *service_family_create(struct qmi_device *device,
			const struct qmi_service_info *info, uint8_t client_id)
{
	struct service_family *family = l_new(struct service_family, 1);

	family->ref_count = 0;
	family->device = device;
	family->client_id = client_id;
	family->notify_list = l_queue_new();

	if (device->next_group_id == 0) /* 0 is reserved for control */
		device->next_group_id = 1;

	family->group_id = device->next_group_id++;

	memcpy(&family->info, info, sizeof(family->info));

	__debug_device(device, "service family created [client=%d,type=%d]",
					family->client_id,
					family->info.service_type);

	return family;
}

static struct qmi_service *service_create(struct service_family *family)
{
	struct qmi_device *device = family->device;
	struct qmi_service *service;

	if (device->next_service_handle == 0) /* 0 is reserved for control */
		device->next_service_handle = 1;

	service = l_new(struct qmi_service, 1);
	service->handle = device->next_service_handle++;
	service->family = service_family_ref(family);

	__debug_device(device, "service created [client=%d,type=%d]",
					family->client_id,
					family->info.service_type);

	return service;
}

static void service_create_shared_idle_cb(struct l_idle *idle, void *user_data)
{
	struct service_create_shared_data *data = user_data;
	struct qmi_service *service = service_create(data->family);

	DISCOVERY_DONE(data, service, data->user_data);
}

static void service_create_shared_reply(struct service_create_shared_data *data,
					struct service_family *family)
{
	struct qmi_service *service = NULL;

	if (family)
		service = service_create(family);

	DISCOVERY_DONE(data, service, data->user_data);
}

static bool pending_family_match(const void *data, const void *user_data)
{
	const struct service_create_shared_data *shared_data = data;
	uint16_t service_type = L_PTR_TO_UINT(user_data);

	return shared_data->service_type == service_type;
}

struct pending_family_reply_if_match_info {
	uint16_t service_type;
	struct service_family *family;
};

static bool pending_family_reply_if_match(void *data, void *user_data)
{
	struct service_create_shared_data *shared_data = data;
	const struct pending_family_reply_if_match_info *info = user_data;

	if (pending_family_match(data, L_UINT_TO_PTR(info->service_type))) {
		service_create_shared_reply(shared_data, info->family);
		return true;
	}

	return false;
}

static void service_create_shared_pending_reply(struct qmi_device_qmux *qmux,
						uint16_t service_type,
						struct service_family *family)
{	struct pending_family_reply_if_match_info info = {
		.service_type = service_type,
		.family = family,
	};

	l_queue_foreach_remove(qmux->pending_families,
					pending_family_reply_if_match, &info);
}

static void service_create_shared_data_free(void *user_data)
{
	struct service_create_shared_data *data = user_data;

	if (data->idle)
		l_idle_remove(data->idle);

	if (data->family)
		service_family_unref(data->family);

	if (data->destroy)
		data->destroy(data->user_data);

	l_free(data);
}

static struct qmi_request *find_control_request(struct qmi_device_qmux *qmux,
						uint16_t tid)
{
	struct qmi_request *req;

	if (!tid)
		return NULL;

	req = l_queue_remove_if(qmux->super.req_queue,
					__request_compare, L_UINT_TO_PTR(tid));
	if (req)
		return req;

	req = l_queue_remove_if(qmux->control_queue,
					__request_compare, L_UINT_TO_PTR(tid));
	return req;
}

static void qmux_sync_callback(uint16_t message, uint16_t length,
					const void *buffer, void *user_data)
{
	struct discover_data *data = user_data;

	DISCOVERY_DONE(data, data->user_data);
}

/* sync will release all previous clients */
static bool qmi_device_qmux_sync(struct qmi_device_qmux *qmux,
					struct discover_data *data)
{
	struct qmi_request *req;

	__debug_device(&qmux->super, "Sending sync to reset QMI");

	req = __control_request_alloc(QMI_CTL_SYNC, NULL, 0,
					qmux_sync_callback, data);

	__ctl_request_submit(qmux, req);

	return true;
}

static void qmux_discover_callback(uint16_t message, uint16_t length,
					const void *buffer, void *user_data)
{
	struct discover_data *data = user_data;
	struct qmi_device *device = data->device;
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);
	const struct qmi_result_code *result_code;
	const struct qmi_service_list *service_list;
	const void *ptr;
	uint16_t len;
	unsigned int i;

	result_code = tlv_get(buffer, length, 0x02, &len);
	if (!result_code)
		goto done;

	if (len != QMI_RESULT_CODE_SIZE)
		goto done;

	service_list = tlv_get(buffer, length, 0x01, &len);
	if (!service_list)
		goto done;

	if (len < QMI_SERVICE_LIST_SIZE)
		goto done;

	for (i = 0; i < service_list->count; i++) {
		uint16_t major =
			L_LE16_TO_CPU(service_list->services[i].major);
		uint16_t minor =
			L_LE16_TO_CPU(service_list->services[i].minor);
		uint8_t type = service_list->services[i].type;
		const char *name = __service_type_to_string(type);
		struct qmi_service_info info;

		if (name)
			__debug_device(device, "found service [%s %d.%d]",
					name, major, minor);
		else
			__debug_device(device, "found service [%d %d.%d]",
					type, major, minor);

		if (type == QMI_SERVICE_CONTROL) {
			qmux->control_major = major;
			qmux->control_minor = minor;
			continue;
		}

		memset(&info, 0, sizeof(info));
		info.service_type = type;
		info.major = major;
		info.minor = minor;

		__qmi_service_appeared(device, &info);
	}

	ptr = tlv_get(buffer, length, 0x10, &len);
	if (!ptr)
		goto done;

	qmux->version_str = l_strndup(ptr + 1, *((uint8_t *) ptr));
	__debug_device(device, "version string: %s", qmux->version_str);

done:
	/* if the device support the QMI call SYNC over the CTL interface */
	if ((qmux->control_major == 1 && qmux->control_minor >= 5) ||
			qmux->control_major > 1) {
		qmi_device_qmux_sync(qmux, data);
		return;
	}

	DISCOVERY_DONE(data, data->user_data);
}

static void qmux_discover_reply_timeout(struct l_timeout *timeout,
							void *user_data)
{
	struct discover_data *data = user_data;
	struct qmi_device *device = data->device;
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);
	struct qmi_request *req;

	l_timeout_remove(data->timeout);
	data->timeout = NULL;

	/* remove request from queues */
	req = find_control_request(qmux, data->tid);

	DISCOVERY_DONE(data, data->user_data);

	if (req)
		__request_free(req);
}

static int qmi_device_qmux_discover(struct qmi_device *device,
					qmi_discover_func_t func,
					void *user_data,
					qmi_destroy_func_t destroy)
{
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);
	struct discover_data *data;
	struct qmi_request *req;

	__debug_device(device, "device %p discover", device);

	if (l_queue_length(device->service_infos) > 0)
		return -EALREADY;

	data = l_new(struct discover_data, 1);

	data->super.destroy = discover_data_free;
	data->device = device;
	data->func = func;
	data->user_data = user_data;
	data->destroy = destroy;

	req = __control_request_alloc(QMI_CTL_GET_VERSION_INFO, NULL, 0,
						qmux_discover_callback, data);

	data->tid = __ctl_request_submit(qmux, req);
	data->timeout = l_timeout_create(DISCOVER_TIMEOUT,
						qmux_discover_reply_timeout,
						data, NULL);

	__qmi_device_discovery_started(device, &data->super);

	return 0;
}

struct qmux_client_create_data {
	struct discovery super;
	struct qmi_device *device;
	uint8_t type;
	uint16_t major;
	uint16_t minor;
	qmi_create_func_t func;
	struct l_timeout *timeout;
	uint16_t tid;
};

static void qmux_client_create_data_free(void *user_data)
{
	struct qmux_client_create_data *data = user_data;

	if (data->timeout)
		l_timeout_remove(data->timeout);

	l_free(data);
}

static void qmux_client_create_reply(struct l_timeout *timeout, void *user_data)
{
	struct qmux_client_create_data *data = user_data;
	struct qmi_device *device = data->device;
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);
	struct qmi_request *req;

	DBG("");

	service_create_shared_pending_reply(qmux, data->type, NULL);

	/* remove request from queues */
	req = find_control_request(qmux, data->tid);

	l_timeout_remove(data->timeout);
	data->timeout = NULL;

	DISCOVERY_DONE(data, NULL, NULL);

	if (req)
		__request_free(req);
}

static void qmux_client_create_callback(uint16_t message, uint16_t length,
					const void *buffer, void *user_data)
{
	struct qmux_client_create_data *data = user_data;
	struct qmi_device *device = data->device;
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);
	struct service_family *family = NULL;
	struct qmi_service_info info;
	const struct qmi_result_code *result_code;
	const struct qmi_client_id *client_id;
	uint16_t len;
	unsigned int hash_id;

	result_code = tlv_get(buffer, length, 0x02, &len);
	if (!result_code)
		goto done;

	if (len != QMI_RESULT_CODE_SIZE)
		goto done;

	client_id = tlv_get(buffer, length, 0x01, &len);
	if (!client_id)
		goto done;

	if (len != QMI_CLIENT_ID_SIZE)
		goto done;

	if (client_id->service != data->type)
		goto done;

	memset(&info, 0, sizeof(family->info));
	info.service_type = data->type;
	info.major = data->major;
	info.minor = data->minor;

	family = service_family_create(device, &info, client_id->client);
	family = service_family_ref(family);
	hash_id = family_list_create_hash(family->info.service_type,
							family->client_id);
	l_hashmap_insert(device->family_list, L_UINT_TO_PTR(hash_id), family);
	l_hashmap_insert(device->family_list,
				L_UINT_TO_PTR(family->info.service_type),
				family);
done:
	service_create_shared_pending_reply(qmux, data->type, family);
	if (family)
		service_family_unref(family);

	DISCOVERY_DONE(data, NULL, NULL);
}

static int qmi_device_qmux_client_create(struct qmi_device *device,
					uint16_t service_type,
					qmi_create_func_t func, void *user_data,
					qmi_destroy_func_t destroy)
{
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);
	unsigned char client_req[] = { 0x01, 0x01, 0x00, service_type };
	struct qmi_request *req;
	struct service_create_shared_data *shared_data;
	struct qmux_client_create_data *create_data;
	bool create_in_progress;

	if (!l_queue_length(device->service_infos))
		return -ENOENT;

	create_in_progress = l_queue_find(qmux->pending_families,
						pending_family_match,
						L_UINT_TO_PTR(service_type));

	shared_data = l_new(struct service_create_shared_data, 1);
	shared_data->super.destroy = service_create_shared_data_free;
	shared_data->service_type = service_type;
	shared_data->device = device;
	shared_data->func = func;
	shared_data->user_data = user_data;
	shared_data->destroy = destroy;
	l_queue_push_tail(qmux->pending_families, shared_data);

	if (create_in_progress)
		return 0;

	create_data = l_new(struct qmux_client_create_data, 1);
	create_data->super.destroy = qmux_client_create_data_free;
	create_data->device = device;
	create_data->type = service_type;

	__debug_device(device, "service create [type=%d]", service_type);

	qmi_device_get_service_version(device, create_data->type,
						&create_data->major,
						&create_data->minor);

	req = __control_request_alloc(QMI_CTL_GET_CLIENT_ID,
					client_req, sizeof(client_req),
					qmux_client_create_callback,
					create_data);

	create_data->tid = __ctl_request_submit(qmux, req);
	create_data->timeout = l_timeout_create(8, qmux_client_create_reply,
							create_data, NULL);

	__qmi_device_discovery_started(device, &create_data->super);

	return 0;
}

static void qmux_client_release_callback(uint16_t message, uint16_t length,
					const void *buffer, void *user_data)
{
	struct qmi_device_qmux *qmux = user_data;

	qmux->release_users--;
}

static void qmi_device_qmux_client_release(struct qmi_device *device,
						uint16_t service_type,
						uint16_t client_id)
{
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);
	uint8_t release_req[] = { 0x01, 0x02, 0x00, service_type, client_id };
	struct qmi_request *req;

	qmux->release_users++;

	req = __control_request_alloc(QMI_CTL_RELEASE_CLIENT_ID,
					release_req, sizeof(release_req),
					qmux_client_release_callback, qmux);

	__ctl_request_submit(qmux, req);
}

static void qmux_shutdown_destroy(void *user_data)
{
	struct qmi_device_qmux *qmux = user_data;

	if (qmux->shutdown_destroy)
		qmux->shutdown_destroy(qmux->shutdown_user_data);

	qmux->shutdown_idle = NULL;

	__qmi_device_shutdown_finished(&qmux->super);
}

static void qmux_shutdown_callback(struct l_idle *idle, void *user_data)
{
	struct qmi_device_qmux *qmux = user_data;

	if (qmux->release_users > 0)
		return;

	qmux->super.shutting_down = true;

	if (qmux->shutdown_func)
		qmux->shutdown_func(qmux->shutdown_user_data);

	qmux->super.shutting_down = false;

	l_idle_remove(qmux->shutdown_idle);
}

static int qmi_device_qmux_shutdown(struct qmi_device *device,
					qmi_shutdown_func_t func,
					void *user_data,
					qmi_destroy_func_t destroy)
{
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);

	if (qmux->shutdown_idle)
		return -EALREADY;

	__debug_device(&qmux->super, "device %p shutdown", &qmux->super);

	qmux->shutdown_idle = l_idle_create(qmux_shutdown_callback, qmux,
						qmux_shutdown_destroy);

	if (!qmux->shutdown_idle)
		return -EIO;

	qmux->shutdown_func = func;
	qmux->shutdown_user_data = user_data;
	qmux->shutdown_destroy = destroy;

	return 0;
}

static void qmi_device_qmux_destroy(struct qmi_device *device)
{
	struct qmi_device_qmux *qmux =
		l_container_of(device, struct qmi_device_qmux, super);

	l_queue_destroy(qmux->pending_families,
		(l_queue_destroy_func_t) service_create_shared_data_free);
	l_queue_destroy(qmux->control_queue, __request_free);

	if (qmux->shutdown_idle)
		l_idle_remove(qmux->shutdown_idle);

	l_free(qmux->version_str);
	l_free(qmux);
}

static const struct qmi_device_ops qmux_ops = {
	.write = qmi_device_qmux_write,
	.discover = qmi_device_qmux_discover,
	.client_create = qmi_device_qmux_client_create,
	.client_release = qmi_device_qmux_client_release,
	.shutdown = qmi_device_qmux_shutdown,
	.destroy = qmi_device_qmux_destroy,
};

struct qmi_device *qmi_device_new_qmux(const char *device)
{
	struct qmi_device_qmux *qmux;
	int fd;

	fd = open(device, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	qmux = l_new(struct qmi_device_qmux, 1);

	if (qmi_device_init(&qmux->super, fd, &qmux_ops) < 0) {
		close(fd);
		l_free(qmux);
		return NULL;
	}

	qmux->next_control_tid = 1;
	qmux->control_queue = l_queue_new();
	qmux->pending_families = l_queue_new();
	l_io_set_read_handler(qmux->super.io, received_qmux_data, qmux, NULL);

	return &qmux->super;
}

struct qmi_device_qrtr {
	struct qmi_device super;
};

static int qmi_device_qrtr_write(struct qmi_device *device,
					struct qmi_request *req)
{
	struct sockaddr_qrtr addr;
	uint8_t *data;
	uint16_t len;
	ssize_t bytes_written;
	int fd = l_io_get_fd(device->io);

	/* Skip the QMUX header */
	data = req->data + QMI_MUX_HDR_SIZE;
	len = req->len - QMI_MUX_HDR_SIZE;

	memset(&addr, 0, sizeof(addr));	/* Ensures internal padding is 0 */
	addr.sq_family = AF_QIPCRTR;
	addr.sq_node = req->info.qrtr_node;
	addr.sq_port = req->info.qrtr_port;

	bytes_written = sendto(fd, data, len, 0, (struct sockaddr *) &addr,
							sizeof(addr));
	if (bytes_written < 0) {
		DBG("Failure sending data: %s", strerror(errno));
		return -errno;
	}

	l_util_hexdump(false, data, bytes_written,
			device->debug_func, device->debug_data);

	__qrtr_debug_msg(' ', data, bytes_written,
			req->info.service_type, device->debug_func,
			device->debug_data);

	l_queue_push_tail(device->service_queue, req);

	return 0;
}

static void qrtr_debug_ctrl_request(const struct qrtr_ctrl_pkt *packet,
					qmi_debug_func_t function,
					void *user_data)
{
	char strbuf[72 + 16], *str;
	const char *type;

	if (!function)
		return;

	str = strbuf;
	str += sprintf(str, "    %s",
			__service_type_to_string(QMI_SERVICE_CONTROL));

	type = "_pkt";

	str += sprintf(str, "%s cmd=%d", type,
				L_LE32_TO_CPU(packet->cmd));

	function(strbuf, user_data);
}

static void qrtr_received_control_packet(struct qmi_device *device,
						const void *buf, size_t len)
{
	const struct qrtr_ctrl_pkt *packet = buf;
	struct discover_data *data;
	struct qmi_service_info info;
	uint32_t cmd;
	uint32_t type;
	uint32_t instance;
	uint32_t version;
	uint32_t node;
	uint32_t port;

	if (len < sizeof(*packet)) {
		DBG("qrtr packet is too small");
		return;
	}

	qrtr_debug_ctrl_request(packet, device->debug_func,
				device->debug_data);

	cmd = L_LE32_TO_CPU(packet->cmd);
	if (cmd != QRTR_TYPE_NEW_SERVER) {
		DBG("Unknown command: %d", cmd);
		return;
	}

	data = l_queue_peek_head(device->discovery_queue);

	if (!packet->server.service && !packet->server.instance &&
			!packet->server.node && !packet->server.port) {
		DBG("Initial service discovery has completed");

		if (data)
			DISCOVERY_DONE(data, data->user_data);
		else
			DBG("discovery_queue is empty"); /* likely a timeout */

		return;
	}

	type = L_LE32_TO_CPU(packet->server.service);
	version = L_LE32_TO_CPU(packet->server.instance) & 0xff;
	instance = L_LE32_TO_CPU(packet->server.instance) >> 8;

	node = L_LE32_TO_CPU(packet->server.node);
	port = L_LE32_TO_CPU(packet->server.port);

	DBG("New server: Type: %d Version: %d Instance: %d Node: %d Port: %d",
		type, version, instance, node, port);

	memset(&info, 0, sizeof(info));
	info.service_type = type;
	info.qrtr_port = port;
	info.qrtr_node = node;
	info.major = version;
	info.instance = instance;

	__qmi_service_appeared(device, &info);

	if (!data) {
		DBG("discovery_queue is empty"); /* likely a timeout */
		return;
	}

	l_timeout_modify(data->timeout, DISCOVER_TIMEOUT);
}

static void qrtr_received_service_message(struct qmi_device *device,
						uint32_t node, uint32_t port,
						const void *buf, size_t len)
{
	const struct l_queue_entry *entry;
	uint32_t service_type = 0;

	for (entry = l_queue_get_entries(device->service_infos);
				entry; entry = entry->next) {
		struct qmi_service_info *info = entry->data;

		if (info->qrtr_node == node && info->qrtr_port == port) {
			service_type = info->service_type;
			break;
		}
	}

	if (!service_type) {
		DBG("Received msg from unknown service on node: %d, port: %d",
			node, port);
		return;
	}

	__qrtr_debug_msg(' ', buf, len, service_type,
				device->debug_func, device->debug_data);

	__rx_message(device, service_type, 0, buf);
}

static bool qrtr_received_data(struct l_io *io, void *user_data)
{
	struct qmi_device_qrtr *qrtr = user_data;
	struct sockaddr_qrtr addr;
	unsigned char buf[2048];
	ssize_t bytes_read;
	socklen_t addr_size;

	addr_size = sizeof(addr);
	bytes_read = recvfrom(l_io_get_fd(qrtr->super.io), buf, sizeof(buf), 0,
				(struct sockaddr *) &addr, &addr_size);
	DBG("Received %zd bytes from Node: %d Port: %d", bytes_read,
		addr.sq_node, addr.sq_port);

	if (bytes_read < 0)
		return true;

	l_util_hexdump(true, buf, bytes_read, qrtr->super.debug_func,
			qrtr->super.debug_data);

	if (addr.sq_port == QRTR_PORT_CTRL)
		qrtr_received_control_packet(&qrtr->super, buf, bytes_read);
	else
		qrtr_received_service_message(&qrtr->super, addr.sq_node,
						addr.sq_port, buf, bytes_read);

	return true;
}

static void qrtr_discover_reply_timeout(struct l_timeout *timeout,
							void *user_data)
{
	struct discover_data *data = user_data;

	l_timeout_remove(data->timeout);
	data->timeout = NULL;

	DISCOVERY_DONE(data, data->user_data);
}

static int qmi_device_qrtr_discover(struct qmi_device *device,
					qmi_discover_func_t func,
					void *user_data,
					qmi_destroy_func_t destroy)
{
	struct discover_data *data;
	struct qrtr_ctrl_pkt packet;
	struct sockaddr_qrtr addr;
	socklen_t addr_len;
	int rc;
	ssize_t bytes_written;
	int fd;

	__debug_device(device, "device %p discover", device);

	if (l_queue_length(device->discovery_queue) > 0)
		return -EINPROGRESS;

	data = l_new(struct discover_data, 1);

	data->super.destroy = discover_data_free;
	data->device = device;
	data->func = func;
	data->user_data = user_data;
	data->destroy = destroy;

	fd = l_io_get_fd(device->io);

	/*
	 * The control node is configured by the system. Use getsockname to
	 * get its value.
	 */
	addr_len = sizeof(addr);
	rc = getsockname(fd, (struct sockaddr *) &addr, &addr_len);
	if (rc) {
		DBG("getsockname failed: %s", strerror(errno));
		rc = -errno;
		goto error;
	}

	if (addr.sq_family != AF_QIPCRTR || addr_len != sizeof(addr)) {
		DBG("Unexpected sockaddr from getsockname. family: %d size: %d",
			addr.sq_family, addr_len);
		rc = -EIO;
		goto error;
	}

	addr.sq_port = QRTR_PORT_CTRL;
	memset(&packet, 0, sizeof(packet));
	packet.cmd = L_CPU_TO_LE32(QRTR_TYPE_NEW_LOOKUP);

	bytes_written = sendto(fd, &packet,
				sizeof(packet), 0,
				(struct sockaddr *) &addr, addr_len);
	if (bytes_written < 0) {
		DBG("Failure sending data: %s", strerror(errno));
		rc = -errno;
		goto error;
	}

	l_util_hexdump(false, &packet, bytes_written,
			device->debug_func, device->debug_data);

	data->timeout = l_timeout_create(DISCOVER_TIMEOUT,
						qrtr_discover_reply_timeout,
						data, NULL);

	__qmi_device_discovery_started(device, &data->super);

	return 0;

error:
	__discovery_free(&data->super);

	return rc;
}

static void qmi_device_qrtr_destroy(struct qmi_device *device)
{
	struct qmi_device_qrtr *qrtr =
		l_container_of(device, struct qmi_device_qrtr, super);

	l_free(qrtr);
}

static const struct qmi_device_ops qrtr_ops = {
	.write = qmi_device_qrtr_write,
	.discover = qmi_device_qrtr_discover,
	.client_create = NULL,
	.client_release = NULL,
	.shutdown = NULL,
	.destroy = qmi_device_qrtr_destroy,
};

struct qmi_device *qmi_device_new_qrtr(void)
{
	struct qmi_device_qrtr *qrtr;
	int fd;

	fd = socket(AF_QIPCRTR, SOCK_DGRAM, 0);
	if (fd < 0)
		return NULL;

	qrtr = l_new(struct qmi_device_qrtr, 1);

	if (qmi_device_init(&qrtr->super, fd, &qrtr_ops) < 0) {
		close(fd);
		l_free(qrtr);
		return NULL;
	}

	l_io_set_read_handler(qrtr->super.io, qrtr_received_data, qrtr, NULL);

	return &qrtr->super;
}

struct qmi_param *qmi_param_new(void)
{
	return l_new(struct qmi_param, 1);
}

void qmi_param_free(struct qmi_param *param)
{
	if (!param)
		return;

	l_free(param->data);
	l_free(param);
}

bool qmi_param_append(struct qmi_param *param, uint8_t type,
					uint16_t length, const void *data)
{
	struct qmi_tlv_hdr *tlv;
	void *ptr;

	if (!param || !type)
		return false;

	if (!length)
		return true;

	if (!data)
		return false;

	if (param->data)
		ptr = l_realloc(param->data,
				param->length + QMI_TLV_HDR_SIZE + length);
	else
		ptr = l_malloc(QMI_TLV_HDR_SIZE + length);

	tlv = ptr + param->length;

	tlv->type = type;
	tlv->length = L_CPU_TO_LE16(length);
	memcpy(tlv->value, data, length);

	param->data = ptr;
	param->length += QMI_TLV_HDR_SIZE + length;

	return true;
}

bool qmi_param_append_uint8(struct qmi_param *param, uint8_t type,
							uint8_t value)
{
	unsigned char buf[1] = { value };

	return qmi_param_append(param, type, sizeof(buf), buf);
}

bool qmi_param_append_uint16(struct qmi_param *param, uint8_t type,
							uint16_t value)
{
	unsigned char buf[2] = { value & 0xff, (value & 0xff00) >> 8 };

	return qmi_param_append(param, type, sizeof(buf), buf);
}

bool qmi_param_append_uint32(struct qmi_param *param, uint8_t type,
							uint32_t value)
{
	unsigned char buf[4] = { value & 0xff, (value & 0xff00) >> 8,
					(value & 0xff0000) >> 16,
					(value & 0xff000000) >> 24 };

	return qmi_param_append(param, type, sizeof(buf), buf);
}

struct qmi_param *qmi_param_new_uint8(uint8_t type, uint8_t value)
{
	struct qmi_param *param;

	param = qmi_param_new();

	if (!qmi_param_append_uint8(param, type, value)) {
		qmi_param_free(param);
		return NULL;
	}

	return param;
}

struct qmi_param *qmi_param_new_uint16(uint8_t type, uint16_t value)
{
	struct qmi_param *param;

	param = qmi_param_new();

	if (!qmi_param_append_uint16(param, type, value)) {
		qmi_param_free(param);
		return NULL;
	}

	return param;
}

struct qmi_param *qmi_param_new_uint32(uint8_t type, uint32_t value)
{
	struct qmi_param *param;

	param = qmi_param_new();

	if (!qmi_param_append_uint32(param, type, value)) {
		qmi_param_free(param);
		return NULL;
	}

	return param;
}

bool qmi_result_set_error(struct qmi_result *result, uint16_t *error)
{
	if (!result) {
		if (error)
			*error = 0xffff;
		return true;
	}

	if (result->result == 0x0000)
		return false;

	if (error)
		*error = result->error;

	return true;
}

const char *qmi_result_get_error(struct qmi_result *result)
{
	if (!result)
		return NULL;

	if (result->result == 0x0000)
		return NULL;

	return __error_to_string(result->error);
}

const void *qmi_result_get(struct qmi_result *result, uint8_t type,
							uint16_t *length)
{
	if (!result || !type)
		return NULL;

	return tlv_get(result->data, result->length, type, length);
}

char *qmi_result_get_string(struct qmi_result *result, uint8_t type)
{
	const void *ptr;
	uint16_t len;

	if (!result || !type)
		return NULL;

	ptr = tlv_get(result->data, result->length, type, &len);
	if (!ptr)
		return NULL;

	return l_strndup(ptr, len);
}

bool qmi_result_get_uint8(struct qmi_result *result, uint8_t type,
							uint8_t *value)
{
	const unsigned char *ptr;
	uint16_t len;

	if (!result || !type)
		return false;

	ptr = tlv_get(result->data, result->length, type, &len);
	if (!ptr)
		return false;

	if (value)
		*value = *ptr;

	return true;
}

bool qmi_result_get_int16(struct qmi_result *result, uint8_t type,
							int16_t *value)
{
	const unsigned char *ptr;
	uint16_t len, tmp;

	if (!result || !type)
		return false;

	ptr = tlv_get(result->data, result->length, type, &len);
	if (!ptr)
		return false;

	memcpy(&tmp, ptr, 2);

	if (value)
		*value = L_LE16_TO_CPU(tmp);

	return true;
}

bool qmi_result_get_uint16(struct qmi_result *result, uint8_t type,
							uint16_t *value)
{
	const unsigned char *ptr;
	uint16_t len, tmp;

	if (!result || !type)
		return false;

	ptr = tlv_get(result->data, result->length, type, &len);
	if (!ptr)
		return false;

	memcpy(&tmp, ptr, 2);

	if (value)
		*value = L_LE16_TO_CPU(tmp);

	return true;
}

bool qmi_result_get_uint32(struct qmi_result *result, uint8_t type,
							uint32_t *value)
{
	const unsigned char *ptr;
	uint16_t len;
	uint32_t tmp;

	if (!result || !type)
		return false;

	ptr = tlv_get(result->data, result->length, type, &len);
	if (!ptr)
		return false;

	memcpy(&tmp, ptr, 4);

	if (value)
		*value = L_LE32_TO_CPU(tmp);

	return true;
}

bool qmi_result_get_uint64(struct qmi_result *result, uint8_t type,
							uint64_t *value)
{
	const unsigned char *ptr;
	uint16_t len;
	uint64_t tmp;

	if (!result || !type)
		return false;

	ptr = tlv_get(result->data, result->length, type, &len);
	if (!ptr)
		return false;

	memcpy(&tmp, ptr, 8);

	if (value)
		*value = L_LE64_TO_CPU(tmp);

	return true;
}

bool qmi_service_create_shared(struct qmi_device *device, uint16_t type,
			qmi_create_func_t func, void *user_data,
			qmi_destroy_func_t destroy)
{
	struct service_create_shared_data *data;
	struct service_family *family;

	if (!device || !func)
		return false;

	if (type == QMI_SERVICE_CONTROL)
		return false;

	family = l_hashmap_lookup(device->family_list, L_UINT_TO_PTR(type));
	if (!family) {
		const struct qmi_service_info *info;

		if (device->ops->client_create) {
			int r;

			r = device->ops->client_create(device, type, func,
							user_data, destroy);
			return r == 0;
		}

		info = __find_service_info_by_type(device, type);
		if (!info)
			return false;

		family = service_family_create(device, info, 0);
		l_hashmap_insert(device->family_list, L_UINT_TO_PTR(type),
							family);
	}

	data = l_new(struct service_create_shared_data, 1);

	data->super.destroy = service_create_shared_data_free;
	data->device = device;
	data->func = func;
	data->user_data = user_data;
	data->destroy = destroy;
	data->family = service_family_ref(family);
	data->idle = l_idle_create(service_create_shared_idle_cb, data, NULL);

	/* Not really discovery... just tracking the idle callback. */
	__qmi_device_discovery_started(device, &data->super);

	return true;
}

const char *qmi_service_get_identifier(struct qmi_service *service)
{
	if (!service)
		return NULL;

	return __service_type_to_string(service->family->info.service_type);
}

bool qmi_service_get_version(struct qmi_service *service,
					uint16_t *major, uint16_t *minor)
{
	if (!service)
		return false;

	if (major)
		*major = service->family->info.major;

	if (minor)
		*minor = service->family->info.minor;

	return true;
}

struct service_send_data {
	qmi_result_func_t func;
	void *user_data;
	qmi_destroy_func_t destroy;
};

static void service_send_free(struct service_send_data *data)
{
	if (data->destroy)
		data->destroy(data->user_data);

	l_free(data);
}

static void service_send_callback(uint16_t message, uint16_t length,
					const void *buffer, void *user_data)
{
	struct service_send_data *data = user_data;
	const struct qmi_result_code *result_code;
	uint16_t len;
	struct qmi_result result;

	result.message = message;
	result.data = buffer;
	result.length = length;

	result_code = tlv_get(buffer, length, 0x02, &len);
	if (!result_code)
		goto done;

	if (len != QMI_RESULT_CODE_SIZE)
		goto done;

	result.result = L_LE16_TO_CPU(result_code->result);
	result.error = L_LE16_TO_CPU(result_code->error);

done:
	if (data->func)
		data->func(&result, data->user_data);

	service_send_free(data);
}

uint16_t qmi_service_send(struct qmi_service *service,
				uint16_t message, struct qmi_param *param,
				qmi_result_func_t func,
				void *user_data, qmi_destroy_func_t destroy)
{
	struct qmi_device *device;
	struct service_family *family;
	struct service_send_data *data;
	struct qmi_request *req;
	uint16_t tid;

	if (!service)
		return 0;

	family = service->family;

	if (!family->group_id)
		return 0;

	device = family->device;
	if (!device)
		return 0;

	data = l_new(struct service_send_data, 1);

	data->func = func;
	data->user_data = user_data;
	data->destroy = destroy;

	req = __service_request_alloc(&family->info,
					family->client_id, message,
					param ? param->data : NULL,
					param ? param->length : 0,
					service_send_callback, data);

	qmi_param_free(param);

	tid = __service_request_submit(device, service, req);

	return tid;
}

bool qmi_service_cancel(struct qmi_service *service, uint16_t id)
{
	struct qmi_device *device;
	struct qmi_request *req;
	struct service_family *family;

	if (!service || !id)
		return false;

	family = service->family;

	if (!family->client_id)
		return false;

	device = family->device;
	if (!device)
		return false;

	req = l_queue_remove_if(device->req_queue, __request_compare,
					L_UINT_TO_PTR(id));
	if (!req) {
		req = l_queue_remove_if(device->service_queue,
						__request_compare,
						L_UINT_TO_PTR(id));
		if (!req)
			return false;
	}

	service_send_free(req->user_data);

	__request_free(req);

	return true;
}

static bool remove_req_if_match(void *data, void *user_data)
{
	struct qmi_request *req = data;
	unsigned int service_handle = L_PTR_TO_UINT(user_data);

	if (req->service_handle != service_handle)
		return false;

	service_send_free(req->user_data);
	__request_free(req);

	return true;
}

static void remove_client(struct l_queue *queue, unsigned int service_handle)
{
	l_queue_foreach_remove(queue, remove_req_if_match,
				L_UINT_TO_PTR(service_handle));
}

static bool qmi_service_cancel_all(struct qmi_service *service)
{
	struct qmi_device *device;

	if (!service)
		return false;

	if (!service->family->group_id)
		return false;

	device = service->family->device;
	if (!device)
		return false;

	remove_client(device->req_queue, service->handle);
	remove_client(device->service_queue, service->handle);

	return true;
}

uint16_t qmi_service_register(struct qmi_service *service,
				uint16_t message, qmi_result_func_t func,
				void *user_data, qmi_destroy_func_t destroy)
{
	struct qmi_notify *notify;
	struct service_family *family;

	if (!service || !func)
		return 0;

	family = service->family;

	notify = l_new(struct qmi_notify, 1);

	if (family->next_notify_id < 1)
		family->next_notify_id = 1;

	notify->id = family->next_notify_id++;
	notify->message = message;
	notify->service_handle = service->handle;
	notify->callback = func;
	notify->user_data = user_data;
	notify->destroy = destroy;

	l_queue_push_tail(family->notify_list, notify);

	return notify->id;
}

bool qmi_service_unregister(struct qmi_service *service, uint16_t id)
{
	struct qmi_notify *notify;
	struct notify_compare_details details;

	if (!service || !id)
		return false;

	details.id = id;
	details.service_handle = service->handle;

	notify = l_queue_remove_if(service->family->notify_list,
						__notify_compare, &details);

	if (!notify)
		return false;

	__notify_free(notify);

	return true;
}

static bool remove_notify_if_handle_match(void *data, void *user_data)
{
	struct qmi_notify *notify = data;
	unsigned int handle = L_PTR_TO_UINT(user_data);

	if (notify->service_handle != handle)
		return false;

	__notify_free(notify);

	return true;
}

static bool qmi_service_unregister_all(struct qmi_service *service)
{
	if (!service)
		return false;

	l_queue_foreach_remove(service->family->notify_list,
					remove_notify_if_handle_match,
					L_UINT_TO_PTR(service->handle));

	return true;
}

void qmi_service_free(struct qmi_service *service)
{
	if (!service)
		return;

	qmi_service_cancel_all(service);
	qmi_service_unregister_all(service);

	service_family_unref(service->family);

	l_free(service);
}

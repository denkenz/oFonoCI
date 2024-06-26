/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define QMI_CTL_SET_INSTANCE_ID		32	/* Set the unique link instance ID */
#define QMI_CTL_GET_VERSION_INFO	33	/* Get supported service version info */
#define QMI_CTL_GET_CLIENT_ID		34	/* Get a unique client ID */
#define QMI_CTL_RELEASE_CLIENT_ID	35	/* Release the unique client ID */
#define QMI_CTL_REVOKE_CLIENT_ID	36	/* Indication of client ID revocation */
#define QMI_CTL_INVALID_CLIENT_ID	37	/* Indication of invalid client ID */
#define QMI_CTL_SET_DATA_FORMAT		38	/* Set host driver data format */
#define QMI_CTL_SYNC			39	/* Synchronize client/server */
#define QMI_CTL_SET_EVENT		40	/* Set event report conditions */
#define QMI_CTL_SET_POWER_SAVE_CONFIG	41	/* Set power save config */
#define QMI_CTL_SET_POWER_SAVE_MODE	42	/* Set power save mode */
#define QMI_CTL_GET_POWER_SAVE_MODE	43	/* Get power save mode */

struct qmi_result_code {
	uint16_t result;
	uint16_t error;
} __attribute__ ((packed));
#define QMI_RESULT_CODE_SIZE 4

struct qmi_service_list {
	uint8_t count;
	struct {
		uint8_t type;
		uint16_t major;
		uint16_t minor;
	} __attribute__((__packed__)) services[0];
} __attribute__((__packed__));
#define QMI_SERVICE_LIST_SIZE 1

struct qmi_client_id {
	uint8_t service;
	uint8_t client;
} __attribute__ ((packed));
#define QMI_CLIENT_ID_SIZE 2

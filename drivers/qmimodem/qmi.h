/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <ell/cleanup.h>

#include <stdbool.h>
#include <stdint.h>

#define QMI_SERVICE_CONTROL	0	/* Control service */
#define QMI_SERVICE_WDS		1	/* Wireless data service */
#define QMI_SERVICE_DMS		2	/* Device management service */
#define QMI_SERVICE_NAS		3	/* Network access service */
#define QMI_SERVICE_QOS		4	/* Quality of service, error service */
#define QMI_SERVICE_WMS		5	/* Wireless messaging service */
#define QMI_SERVICE_PDS		6	/* Position determination service */
#define QMI_SERVICE_AUTH	7	/* Authentication service */
#define QMI_SERVICE_AT		8	/* AT command processor service */
#define QMI_SERVICE_VOICE	9	/* Voice service */
#define QMI_SERVICE_CAT		10	/* Card application toolkit service */
#define QMI_SERVICE_UIM		11	/* UIM service */
#define QMI_SERVICE_PBM		12	/* Phonebook service */
#define QMI_SERVICE_QCHAT	13
#define QMI_SERVICE_RMTFS	14	/* Remote file system service */
#define QMI_SERVICE_TEST	15
#define QMI_SERVICE_LOC		16	/* Location service */
#define QMI_SERVICE_SAR		17	/* Specific absorption rate service */
#define QMI_SERVICE_CSD		20	/* Core sound driver service */
#define QMI_SERVICE_EFS		21	/* Embedded file system service */
#define QMI_SERVICE_TS		23	/* Thermal sensors service */
#define QMI_SERVICE_TMD		24	/* Thermal mitigation device service */
#define QMI_SERVICE_WDA		26	/* Wireless data administrative service */
#define QMI_SERVICE_CSVT	29
#define QMI_SERVICE_COEX	34
#define QMI_SERVICE_PDC		36	/* Persistent device configuration service */
#define QMI_SERVICE_RFRPE	41
#define QMI_SERVICE_DSD		42
#define QMI_SERVICE_SSCTL	43
#define QMI_SERVICE_CAT_OLD	224	/* Card application toolkit service */
#define QMI_SERVICE_RMS		225	/* Remote management service */
#define QMI_SERVICE_OMA		226	/* OMA device management service */

enum qmi_data_endpoint_type {
	QMI_DATA_ENDPOINT_TYPE_UNKNOWN   = 0x00,
	QMI_DATA_ENDPOINT_TYPE_HSIC      = 0x01,
	QMI_DATA_ENDPOINT_TYPE_HSUSB     = 0x02,
	QMI_DATA_ENDPOINT_TYPE_PCIE      = 0x03,
	QMI_DATA_ENDPOINT_TYPE_EMBEDDED  = 0x04,
	QMI_DATA_ENDPOINT_TYPE_BAM_DMUX  = 0x05,
};

enum qmi_error {
	QMI_ERROR_INVALID_QMI_COMMAND				= 71,
};

/**
 *	This defines device-specific "quirks" that may alter the default
 *	behavior of the QMI driver for a specific, instantiated device.
 */
enum qmi_qmux_device_quirk {
	/**
	 *	The device has no "quirks".
	 */
	QMI_QMUX_DEVICE_QUIRK_NONE			= 0x00,

	/**
	 *	The device has a "quirk" where it can lock up and hang (not
	 *	responding to subsequent commands) due to high QMI service
	 *	request arrival rates.
	 */
	QMI_QMUX_DEVICE_QUIRK_REQ_RATE_LIMIT = 0x01
};

/**
 *	Defines options that may alter the default behavior of the QMI
 *	driver for a specific, instantiated device.
 */
struct qmi_qmux_device_options {
	/**
	 *	Device-specific "quirk".
	 */
	enum qmi_qmux_device_quirk quirks;

	/**
	 *	If quirks has #QMI_QMUX_DEVICE_QUIRK_REQ_RATE_LIMIT set, this
	 *	is the minimum period, in microseconds, in which back-to-back
	 *	QMI service requests may be sent to avoid triggering a
	 *	firmware lock up and hang.
	 */
	unsigned int min_req_period_us;
};

typedef void (*qmi_destroy_func_t)(void *user_data);

struct qmi_service;
struct qmi_result;

typedef void (*qmi_debug_func_t)(const char *str, void *user_data);
typedef void (*qmi_qmux_device_discover_func_t)(void *user_data);
typedef void (*qmi_qmux_device_create_client_func_t)(struct qmi_service *,
							void *user_data);
typedef void (*qmi_qmux_device_shutdown_func_t)(void *user_data);
typedef void (*qmi_qrtr_node_lookup_done_func_t)(void *);

typedef void (*qmi_service_result_func_t)(struct qmi_result *, void *);

struct qmi_qmux_device *qmi_qmux_device_new(const char *device,
				const struct qmi_qmux_device_options *options);
void qmi_qmux_device_free(struct qmi_qmux_device *qmux);
void qmi_qmux_device_set_debug(struct qmi_qmux_device *qmux,
				qmi_debug_func_t func, void *user_data);
void qmi_qmux_device_set_io_debug(struct qmi_qmux_device *qmux,
				qmi_debug_func_t func, void *user_data);
int qmi_qmux_device_discover(struct qmi_qmux_device *qmux,
				qmi_qmux_device_discover_func_t func,
				void *user_data, qmi_destroy_func_t destroy);
bool qmi_qmux_device_create_client(struct qmi_qmux_device *qmux,
				uint16_t service_type,
				qmi_qmux_device_create_client_func_t func,
				void *user_data, qmi_destroy_func_t destroy);
bool qmi_qmux_device_get_service_version(struct qmi_qmux_device *qmux,
					uint16_t type,
					uint16_t *major, uint16_t *minor);
bool qmi_qmux_device_has_service(struct qmi_qmux_device *qmux, uint16_t type);
int qmi_qmux_device_shutdown(struct qmi_qmux_device *qmux,
				qmi_qmux_device_shutdown_func_t func,
				void *user_data, qmi_destroy_func_t destroy);

struct qmi_qrtr_node *qmi_qrtr_node_new(uint32_t node);
void qmi_qrtr_node_free(struct qmi_qrtr_node *node);
void qmi_qrtr_node_set_debug(struct qmi_qrtr_node *node,
				qmi_debug_func_t func, void *user_data);
void qmi_qrtr_node_set_io_debug(struct qmi_qrtr_node *node,
				qmi_debug_func_t func, void *user_data);
int qmi_qrtr_node_lookup(struct qmi_qrtr_node *node,
			qmi_qrtr_node_lookup_done_func_t func,
			void *user_data, qmi_destroy_func_t destroy);
struct qmi_service *qmi_qrtr_node_get_service(struct qmi_qrtr_node *node,
						uint32_t type);
struct qmi_service *qmi_qrtr_node_get_dedicated_service(
						struct qmi_qrtr_node *node,
						uint16_t type);
bool qmi_qrtr_node_has_service(struct qmi_qrtr_node *node, uint16_t type);

struct qmi_param;

struct qmi_param *qmi_param_new(void);
void qmi_param_free(struct qmi_param *param);

DEFINE_CLEANUP_FUNC(qmi_param_free)

bool qmi_param_append(struct qmi_param *param, uint8_t type,
					uint16_t length, const void *data);
bool qmi_param_append_uint8(struct qmi_param *param, uint8_t type,
							uint8_t value);
bool qmi_param_append_uint16(struct qmi_param *param, uint8_t type,
							uint16_t value);
bool qmi_param_append_uint32(struct qmi_param *param, uint8_t type,
							uint32_t value);

struct qmi_param *qmi_param_new_uint8(uint8_t type, uint8_t value);
struct qmi_param *qmi_param_new_uint16(uint8_t type, uint16_t value);
struct qmi_param *qmi_param_new_uint32(uint8_t type, uint32_t value);

bool qmi_result_set_error(struct qmi_result *result, uint16_t *error);
const char *qmi_result_get_error(struct qmi_result *result);

const void *qmi_result_get(struct qmi_result *result, uint8_t type,
							uint16_t *length);
char *qmi_result_get_string(struct qmi_result *result, uint8_t type);
bool qmi_result_get_uint8(struct qmi_result *result, uint8_t type,
							uint8_t *value);
bool qmi_result_get_int16(struct qmi_result *result, uint8_t type,
							int16_t *value);
bool qmi_result_get_uint16(struct qmi_result *result, uint8_t type,
							uint16_t *value);
bool qmi_result_get_uint32(struct qmi_result *result, uint8_t type,
							uint32_t *value);
bool qmi_result_get_uint64(struct qmi_result *result, uint8_t type,
							uint64_t *value);
void qmi_result_print_tlvs(struct qmi_result *result);

int qmi_error_to_ofono_cme(int qmi_error);

struct qmi_service *qmi_service_clone(struct qmi_service *service);
void qmi_service_free(struct qmi_service *service);

DEFINE_CLEANUP_FUNC(qmi_service_free)

const char *qmi_service_get_identifier(struct qmi_service *service);
bool qmi_service_get_version(struct qmi_service *service, uint8_t *out_version);

uint16_t qmi_service_send(struct qmi_service *service,
				uint16_t message, struct qmi_param *param,
				qmi_service_result_func_t func,
				void *user_data, qmi_destroy_func_t destroy);
bool qmi_service_cancel(struct qmi_service *service, uint16_t id);

uint16_t qmi_service_register(struct qmi_service *service,
				uint16_t message, qmi_service_result_func_t func,
				void *user_data, qmi_destroy_func_t destroy);
bool qmi_service_unregister(struct qmi_service *service, uint16_t id);

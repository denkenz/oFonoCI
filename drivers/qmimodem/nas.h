/*
 * oFono - Open Source Telephony
 * Copyright (C) 2011-2012  Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdint.h>

#define QMI_NAS_NOTIFY_SIGNAL_STRENGTH		0x10
struct qmi_nas_signal_strength {
	int8_t dbm;
	uint8_t rat;
} __attribute__((__packed__));

#define QMI_NAS_NOTIFY_RF_INFO			0x11
struct qmi_nas_rf_info {
	uint8_t count;
	struct {
		uint8_t rat;
		uint16_t band;
		uint16_t channel;
	} __attribute__((__packed__)) info[0];
} __attribute__((__packed__));

/* Get the signal strength */
#define QMI_NAS_RESULT_SIGNAL_STRENGTH		0x01

/* Scan for visible network */
#define QMI_NAS_PARAM_NETWORK_MASK		0x10	/* uint8 bitmask */

#define QMI_NAS_NETWORK_MASK_GSM		(1 << 0)
#define QMI_NAS_NETWORK_MASK_UMTS		(1 << 1)
#define QMI_NAS_NETWORK_MASK_LTE		(1 << 2)
#define QMI_NAS_NETWORK_MASK_TDSCDMA		(1 << 3)

#define QMI_NAS_RESULT_NETWORK_LIST		0x10
struct qmi_nas_network_info {
	uint16_t mcc;
	uint16_t mnc;
	uint8_t status;
	uint8_t desc_len;
	char desc[0];
} __attribute__((__packed__));
struct qmi_nas_network_list {
	uint16_t count;
	struct qmi_nas_network_info info[0];
} __attribute__((__packed__));
#define QMI_NAS_RESULT_NETWORK_RAT		0x11
struct qmi_nas_network_rat {
	uint16_t count;
	struct {
		uint16_t mcc;
		uint16_t mnc;
		uint8_t rat;
	} __attribute__((__packed__)) info[0];
} __attribute__((__packed__));

#define QMI_NAS_NETWORK_RAT_NONE		0x00
#define QMI_NAS_NETWORK_RAT_GSM			0x04
#define QMI_NAS_NETWORK_RAT_UMTS		0x05
#define QMI_NAS_NETWORK_RAT_LTE			0x08
#define QMI_NAS_NETWORK_RAT_TDSCDMA		0x09
#define QMI_NAS_NETWORK_RAT_NO_CHANGE		0xff

/* Initiate a network registration */
#define QMI_NAS_PARAM_REGISTER_ACTION		0x01	/* uint8 */
#define QMI_NAS_PARAM_REGISTER_MANUAL_INFO	0x10
struct qmi_nas_param_register_manual_info {
	uint16_t mcc;
	uint16_t mnc;
	uint8_t rat;
} __attribute__((__packed__));

#define QMI_NAS_REGISTER_ACTION_AUTO		0x01
#define QMI_NAS_REGISTER_ACTION_MANUAL		0x02

/* Initiate an attach or detach action */
#define QMI_NAS_PARAM_ATTACH_ACTION		0x10	/* uint8 */

#define QMI_NAS_ATTACH_ACTION_ATTACH		0x01
#define QMI_NAS_ATTACH_ACTION_DETACH		0x02

/* Get info about current serving system */
#define QMI_NAS_RESULT_SERVING_SYSTEM		0x01
struct qmi_nas_serving_system {
	uint8_t status;
	uint8_t cs_state;
	uint8_t ps_state;
	uint8_t network;
	uint8_t radio_if_count;
	uint8_t radio_if[0];
} __attribute__((__packed__));
#define QMI_NAS_RESULT_ROAMING_STATUS		0x10	/* uint8 */

#define QMI_NAS_RESULT_CURRENT_PLMN		0x12
struct qmi_nas_current_plmn {
	uint16_t mcc;
	uint16_t mnc;
	uint8_t desc_len;
	char desc[0];
} __attribute__((__packed__));
#define QMI_NAS_RESULT_LOCATION_AREA_CODE	0x1d	/* uint16 */
#define QMI_NAS_RESULT_CELL_ID			0x1e	/* uint32 */

/* qmi_nas_serving_system.status */
#define QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED	0x00
#define QMI_NAS_REGISTRATION_STATE_REGISTERED		0x01
#define QMI_NAS_REGISTRATION_STATE_SEARCHING		0x02
#define QMI_NAS_REGISTRATION_STATE_DENIED		0x03
#define QMI_NAS_REGISTRATION_STATE_UNKNOWN		0x04

#define QMI_NAS_RESULT_3GGP_DST 0x1b
#define QMI_NAS_RESULT_3GPP_TIME 0x1c
struct qmi_nas_3gpp_time {
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	uint8_t timezone;
} __attribute__((__packed__));

/* cs_state/ps_state */
#define QMI_NAS_ATTACH_STATE_INVALID		0x00
#define QMI_NAS_ATTACH_STATE_ATTACHED		0x01
#define QMI_NAS_ATTACH_STATE_DETACHED		0x02

/* Get info about home network */
#define QMI_NAS_RESULT_HOME_NETWORK		0x01
struct qmi_nas_home_network {
	uint16_t mcc;
	uint16_t mnc;
	uint8_t desc_len;
	char desc[0];
} __attribute__((__packed__));

#define QMI_NAS_RAT_MODE_PREF_ANY		(-1)
#define QMI_NAS_RAT_MODE_PREF_GSM		(1 << 2)
#define QMI_NAS_RAT_MODE_PREF_UMTS		(1 << 3)
#define QMI_NAS_RAT_MODE_PREF_LTE		(1 << 4)

#define QMI_NAS_PARAM_SYSTEM_SELECTION_PREF_MODE	0x11

#define QMI_NAS_RESULT_SYSTEM_SELECTION_PREF_MODE	0x11

enum qmi_nas_data_capability {
	QMI_NAS_DATA_CAPABILITY_NONE				= 0x00,
	QMI_NAS_DATA_CAPABILITY_GPRS				= 0x01,
	QMI_NAS_DATA_CAPABILITY_EDGE				= 0x02,
	QMI_NAS_DATA_CAPABILITY_HSDPA				= 0x03,
	QMI_NAS_DATA_CAPABILITY_HSUPA				= 0x04,
	QMI_NAS_DATA_CAPABILITY_WCDMA				= 0x05,
	QMI_NAS_DATA_CAPABILITY_GSM				= 0x09,
	QMI_NAS_DATA_CAPABILITY_LTE				= 0x0B,
	QMI_NAS_DATA_CAPABILITY_HSDPA_PLUS			= 0x0C,
	QMI_NAS_DATA_CAPABILITY_DC_HSDPA_PLUS			= 0x0D,
};

enum qmi_nas_command {
	/* Reset NAS service state variables */
	QMI_NAS_RESET				= 0x00,
	/* Abort previously issued NAS command */
	QMI_NAS_ABORT				= 0x01,
	/* Connection state report indication */
	QMI_NAS_EVENT_REPORT			= 0x02,
	/* Set NAS state report conditions */
	QMI_NAS_SET_EVENT_REPORT		= 0x02,
	/* Set NAS registration report conditions */
	QMI_NAS_REGISTER_INDICATIONS		= 0x03,
	/* Get the signal strength */
	QMI_NAS_GET_SIGNAL_STRENGTH		= 0x20,
	/* Scan for visible network */
	QMI_NAS_NETWORK_SCAN			= 0x21,
	/* Initiate a network registration */
	QMI_NAS_NETWORK_REGISTER		= 0x22,
	/* Initiate an attach or detach action */
	QMI_NAS_ATTACH_DETACH			= 0x23,
	/* Get info about current serving system */
	QMI_NAS_GET_SERVING_SYSTEM		= 0x24,
	/* Current serving system info indication */
	QMI_NAS_SERVING_SYSTEM_INDICATION	= 0x24,
	/* Get info about home network */
	QMI_NAS_GET_HOME_NETWORK		= 0x25,
	QMI_NAS_GET_PREFERRED_NETWORK		= 0x26,
	QMI_NAS_SET_PREFERRED_NETWORK		= 0x27,
	QMI_NAS_SET_TECHNOLOGY_PREFERENCE	= 0x2A,
	QMI_NAS_GET_TECHNOLOGY_PREFERENCE	= 0x2B,
	QMI_NAS_GET_RF_BAND_INFORMATION		= 0x31,
	QMI_NAS_SET_SYSTEM_SELECTION_PREFERENCE	= 0x33,
	QMI_NAS_GET_SYSTEM_SELECTION_PREFERENCE	= 0x34,
	QMI_NAS_GET_OPERATOR_NAME		= 0x39,
	QMI_NAS_OPERATOR_NAME_INDICATION	= 0x3A,
	QMI_NAS_GET_CELL_LOCATION_INFO		= 0x43,
	QMI_NAS_GET_PLMN_NAME			= 0x44,
	QMI_NAS_NETWORK_TIME_INDICATION		= 0x4C,
	QMI_NAS_GET_SYSTEM_INFO			= 0x4D,
	QMI_NAS_SYSTEM_INFO_INDICATION		= 0x4E,
	QMI_NAS_GET_SIGNAL_INFO			= 0x4F,
	QMI_NAS_CONFIG_SIGNAL_INFO		= 0x50,
	QMI_NAS_SIGNAL_INFO_INDICATION		= 0x51,
	QMI_NAS_GET_TX_RX_INFO			= 0x5A,
	QMI_NAS_FORCE_NETWORK_SEARCH		= 0x67,
	QMI_NAS_NETWORK_REJECT_INDICATION	= 0x68,
	QMI_NAS_CONFIG_SIGNAL_INFO_V2		= 0x6C,
	QMI_NAS_GET_DRX				= 0x89,
	QMI_NAS_GET_LTE_CPHY_CA_INFO		= 0xAC,
};

int qmi_nas_rat_to_tech(uint8_t rat);

char **qmi_nas_data_capability_status_to_string_list(const void *tlv,
								uint16_t len);
int qmi_nas_cap_to_bearer_tech(int cap_tech);

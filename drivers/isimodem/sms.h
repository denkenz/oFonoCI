/*
 * oFono - Open Source Telephony
 * Copyright (C) 2009-2010  Nokia Corporation and/or its subsidiary(-ies)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __ISIMODEM_SMS_H
#define __ISIMODEM_SMS_H

#ifdef __cplusplus
extern "C" {
#endif

#define PN_SMS					0x02
#define CBS_TIMEOUT				5
#define SMS_TIMEOUT				5

enum sms_isi_cause {
	SMS_OK =				0x00,
	SMS_ERR_ROUTING_RELEASED =		0x01,
	SMS_ERR_INVALID_PARAMETER =		0x02,
	SMS_ERR_DEVICE_FAILURE =		0x03,
	SMS_ERR_PP_RESERVED =			0x04,
	SMS_ERR_ROUTE_NOT_AVAILABLE =		0x05,
	SMS_ERR_ROUTE_NOT_ALLOWED =		0x06,
	SMS_ERR_SERVICE_RESERVED =		0x07,
	SMS_ERR_INVALID_LOCATION =		0x08,
	SMS_ERR_NO_SIM =			0x09,
	SMS_ERR_SIM_NOT_READY =			0x0A,
	SMS_ERR_NO_NETW_RESPONSE =		0x0B,
	SMS_ERR_DEST_ADDR_FDN_RESTRICTED =	0x0C,
	SMS_ERR_SMSC_ADDR_FDN_RESTRICTED =	0x0D,
	SMS_ERR_RESEND_ALREADY_DONE =		0x0E,
	SMS_ERR_SMSC_ADDR_NOT_AVAILABLE =	0x0F,
	SMS_ERR_ROUTING_FAILED =		0x10,
	SMS_ERR_CS_INACTIVE =			0x11,
	SMS_ERR_SAT_MO_CONTROL_MODIFIED =	0x12,
	SMS_ERR_SAT_MO_CONTROL_REJECT =		0x13,
	SMS_ERR_TRACFONE_FAILED =		0x14,
};

enum sms_isi_cause_type {
	SMS_CAUSE_TYPE_COMMON =		0x00,
	SMS_CAUSE_TYPE_GSM =		0x01,
};

enum sms_gsm_cause {
	SMS_GSM_ERR_UNASSIGNED_NUMBER =				0x01,
	SMS_GSM_ERR_OPER_DETERMINED_BARR =			0x08,
	SMS_GSM_ERR_CALL_BARRED =				0x0A,
	SMS_GSM_ERR_RESERVED =					0x0B,
	SMS_GSM_ERR_MSG_TRANSFER_REJ =				0x15,
	SMS_GSM_ERR_MEMORY_CAPACITY_EXC =			0x16,
	SMS_GSM_ERR_DEST_OUT_OF_ORDER =				0x1B,
	SMS_GSM_ERR_UNDEFINED_SUBSCRIBER =			0x1C,
	SMS_GSM_ERR_FACILITY_REJECTED =				0x1D,
	SMS_GSM_ERR_UNKNOWN_SUBSCRIBER =			0x1E,
	SMS_GSM_ERR_NETW_OUT_OF_ORDER =				0x26,
	SMS_GSM_ERR_TEMPORARY_FAILURE =				0x29,
	SMS_GSM_ERR_CONGESTION =				0x2A,
	SMS_GSM_ERR_RESOURCE_UNAVAILABLE =			0x2F,
	SMS_GSM_ERR_REQ_FACILITY_NOT_SUB =			0x32,
	SMS_GSM_ERR_REQ_FACILITY_NOT_IMP =			0x45,
	SMS_GSM_ERR_INVALID_REFERENCE =				0x51,
	SMS_GSM_ERR_INCORRECT_MESSAGE =				0x5F,
	SMS_GSM_ERR_INVALID_MAND_INFO =				0x60,
	SMS_GSM_ERR_INVALID_MSG_TYPE =				0x61,
	SMS_GSM_ERR_MSG_NOT_COMP_WITH_ST =			0x62,
	SMS_GSM_ERR_INVALID_INFO_ELEMENT =			0x63,
	SMS_GSM_ERR_PROTOCOL_ERROR =				0x6F,
	SMS_GSM_ERR_INTERWORKING =				0x7F,
	SMS_GSM_ERR_NO_CAUSE =					0x80,
	SMS_GSM_ERR_IMSI_UNKNOWN_HLR =				0x82,
	SMS_GSM_ERR_ILLEGAL_MS =				0x83,
	SMS_GSM_ERR_IMSI_UNKNOWN_VLR =				0x84,
	SMS_GSM_ERR_IMEI_NOT_ACCEPTED =				0x85,
	SMS_GSM_ERR_ILLEGAL_ME =				0x86,
	SMS_GSM_ERR_PLMN_NOT_ALLOWED =				0x8B,
	SMS_GSM_ERR_LA_NOT_ALLOWED =				0x8C,
	SMS_GSM_ERR_ROAM_NOT_ALLOWED_LA =			0x8D,
	SMS_GSM_ERR_NO_SUITABLE_CELLS_LA =			0x8F,
	SMS_GSM_ERR_NETWORK_FAILURE =				0x91,
	SMS_GSM_ERR_MAC_FAILURE =				0x94,
	SMS_GSM_ERR_SYNC_FAILURE =				0x95,
	SMS_GSM_ERR_LOW_LAYER_CONGESTION =			0x96,
	SMS_GSM_ERR_AUTH_UNACCEPTABLE =				0x97,
	SMS_GSM_ERR_SERV_OPT_NOT_SUPPORTED =			0xA0,
	SMS_GSM_ERR_SERV_OPT_NOT_SUBSCRIBED =			0xA1,
	SMS_GSM_ERR_SERV_OPT_TEMP_OUT_OF_ORDER =		0xA2,
	SMS_GSM_ERR_CALL_CANNOT_BE_IDENTIFIED =			0xA6,
	SMS_GSM_ERR_SEMANTICALLY_INCORR_MSG =			0xDF,
	SMS_GSM_ERR_LOW_LAYER_INVALID_MAND_INFO =		0xE0,
	SMS_GSM_ERR_LOW_LAYER_INVALID_MSG_TYPE =		0xE1,
	SMS_GSM_ERR_LOW_LAYER_MSG_TYPE_NOT_COMP_WITH_ST =	0xE2,
	SMS_GSM_ERR_LOW_LAYER_INVALID_INFO_ELEMENT =		0xE3,
	SMS_GSM_ERR_CONDITIONAL_IE_ERROR =			0xE4,
	SMS_GSM_ERR_LOW_LAYER_MSG_NOT_COMP_WITH_ST =		0xE5,
	SMS_GSM_ERR_CS_BARRED =					0xE8,
	SMS_GSM_ERR_LOW_LAYER_PROTOCOL_ERROR =			0xEF,
};

enum sms_message_id {
	SMS_MESSAGE_SEND_REQ =			0x02,
	SMS_MESSAGE_SEND_RESP =			0x03,
	SMS_PP_ROUTING_REQ =			0x06,
	SMS_PP_ROUTING_RESP =			0x07,
	SMS_PP_ROUTING_NTF =			0x08,
	SMS_GSM_RECEIVED_PP_REPORT_REQ =	0x09,
	SMS_GSM_RECEIVED_PP_REPORT_RESP =	0x0A,
	SMS_GSM_CB_ROUTING_REQ =		0x0B,
	SMS_GSM_CB_ROUTING_RESP =		0x0C,
	SMS_GSM_CB_ROUTING_NTF =		0x0D,
	SMS_MESSAGE_SEND_STATUS_IND =		0x22,
	SMS_SETTINGS_UPDATE_REQ =		0x30,
	SMS_SETTINGS_UPDATE_RESP =		0x31,
	SMS_SETTINGS_READ_REQ =			0x32,
	SMS_SETTINGS_READ_RESP =		0x33,
	SMS_RECEIVED_MSG_REPORT_REQ =		0x3B,
	SMS_RECEIVED_MSG_REPORT_RESP =		0x3C,
	SMS_RECEIVE_MESSAGE_REQ =		0x41,
	SMS_RECEIVE_MESSAGE_RESP =		0x42,
	SMS_RECEIVED_MSG_IND =			0x43,
};

enum sms_subblock {
	SMS_GSM_DELIVER =		0x00,
	SMS_GSM_STATUS_REPORT =		0x01,
	SMS_GSM_SUBMIT =		0x02,
	SMS_GSM_COMMAND =		0x03,
	SMS_GSM_DELIVER_REPORT =	0x06,
	SMS_GSM_REPORT =		0x0C,
	SMS_GSM_ROUTING =		0x0D,
	SMS_GSM_CB_MESSAGE =		0x0E,
	SMS_GSM_TPDU =			0x11,
	SMS_SB_TPDU =			0x001C,
	SMS_SB_ROUTE_INFO =		0x0023,
	SMS_SB_SMS_PARAMETERS =		0x0031,
	SMS_COMMON_DATA =		0x80,
	SMS_ADDRESS =			0x82,
	SMS_SB_ADDRESS =		0x0082,
};

enum sms_routing_command {
	SMS_ROUTING_RELEASE =		0x00,
	SMS_ROUTING_SET =		0x01,
	SMS_ROUTING_SUSPEND =		0x02,
	SMS_ROUTING_RESUME =		0x03,
	SMS_ROUTING_UPDATE =		0x04,
};

enum sms_route_preference {
	SMS_ROUTE_ANY =			0x00,
	SMS_ROUTE_GPRS_PREF =		0x00,
	SMS_ROUTE_CS =			0x01,
	SMS_ROUTE_GPRS =		0x02,
	SMS_ROUTE_CS_PREF =		0x03,
	SMS_ROUTE_DEFAULT =		0x04,
};

enum sms_routing_mode {
	SMS_GSM_ROUTING_MODE_ALL =	0x0B,
	SMS_GSM_ROUTING_MODE_CB_DDL =	0x0C,
};

enum sms_routing_type {
	SMS_GSM_TPDU_ROUTING =		0x06,
};

enum sms_message_type {
	SMS_GSM_MT_ALL_TYPE =		0x06,
};

enum sms_address_type {
	SMS_UNICODE_ADDRESS =		0x00,
	SMS_GSM_0340_ADDRESS =		0x01,
	SMS_GSM_0411_ADDRESS =		0x02,
	SMS_SMSC_ADDRESS =		0x02,
};

enum sms_sender_type {
	SMS_SENDER_ANY =		0x00,
	SMS_SENDER_SIM_ATK =		0x01,
};

enum sms_content_type {
	SMS_TYPE_DEFAULT =		0x00,
	SMS_TYPE_TEXT_MESSAGE =		0x01,
};

enum sms_subject_list_type {
	SMS_CB_ALLOWED_IDS_LIST =	0x00,
	SMS_CB_NOT_ALLOWED_IDS_LIST =	0x01,
};

enum sms_reception_command {
	SMS_RECEPTION_ACTIVATE =	0x01,
	SMS_RECEPTION_DEACTIVATE =	0x02,
};

enum sms_reception_status {
	SMS_RECEPTION_ACTIVE =		0x01,
	SMS_RECEPTION_INACTIVE =	0x02,
};

enum sms_setting_type {
	SMS_SETTING_TYPE_ROUTE =	0x02,
};

enum sms_route_priority {
	SMS_ROUTE_NOT_AVAILABLE =	0x00,
	SMS_ROUTE_PRIORITY_1 =		0x01,
	SMS_ROUTE_PRIORITY_2 =		0x02,
};

enum sms_parameter_indicator {
	SMS_PI_DESTINATION_ADDRESS =	0x01,
	SMS_PI_SERVICE_CENTER_ADDRESS =	0x02,
	SMS_PI_PROTOCOL_ID =		0x04,
	SMS_PI_DATA_CODING_SCHEME =	0x08,
	SMS_PI_VALIDITY_PERIOD =	0x10,
};

enum sms_parameter_location {
	SMS_PARAMETER_LOCATION_DEFAULT =	0x00,
};

#ifdef __cplusplus
};
#endif

#endif /* __ISIMODEM_SMS_H */

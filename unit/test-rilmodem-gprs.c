/*
 * oFono - Open Source Telephony
 * Copyright (C) 2016 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <glib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <ofono/modem.h>
#include <ofono/types.h>
#include <ofono/gprs.h>
#include <gril.h>
#include <drivers/rilmodem/rilutil.h>

#include "common.h"
#include "ril_constants.h"
#include "rilmodem-test-engine.h"

static const struct ofono_gprs_driver *gprs_drv;

/* Declarations && Re-implementations of core functions. */
struct ofono_modem;

struct ofono_gprs {
	void *driver_data;
	GRil *ril;
	struct ofono_modem *modem;
	struct engine_data *engined;
};

struct ofono_modem {
	struct ofono_gprs *gprs;
};

void ofono_gprs_register(struct ofono_gprs *gprs)
{
	const struct rilmodem_test_step *step;

	step = rilmodem_test_engine_get_current_step(gprs->engined);

	g_assert(step->type == TST_EVENT_CALL);
	g_assert(step->call_func == (void (*)(void)) ofono_gprs_register);

	rilmodem_test_engine_next_step(gprs->engined);
}

void ofono_gprs_set_data(struct ofono_gprs *gprs, void *data)
{
	gprs->driver_data = data;
}

void *ofono_gprs_get_data(struct ofono_gprs *gprs)
{
	return gprs->driver_data;
}

void ofono_gprs_status_notify(struct ofono_gprs *gprs, int status)
{
	const struct rilmodem_test_step *step;

	step = rilmodem_test_engine_get_current_step(gprs->engined);

	g_assert(step->type == TST_EVENT_CALL);
	g_assert(step->call_func == (void (*)(void)) ofono_gprs_status_notify);

	if (step->check_func != NULL)
		((void (*)(struct ofono_gprs *, int)) step->check_func)(
								gprs, status);

	rilmodem_test_engine_next_step(gprs->engined);
}

void ofono_gprs_detached_notify(struct ofono_gprs *gprs)
{
	const struct rilmodem_test_step *step;

	step = rilmodem_test_engine_get_current_step(gprs->engined);

	g_assert(step->type == TST_EVENT_CALL);
	g_assert(step->call_func ==
				(void (*)(void)) ofono_gprs_detached_notify);

	rilmodem_test_engine_next_step(gprs->engined);
}

void ofono_gprs_bearer_notify(struct ofono_gprs *gprs, int bearer)
{
	const struct rilmodem_test_step *step;

	step = rilmodem_test_engine_get_current_step(gprs->engined);

	g_assert(step->type == TST_EVENT_CALL);
	g_assert(step->call_func == (void (*)(void)) ofono_gprs_bearer_notify);

	if (step->check_func != NULL)
		((void (*)(struct ofono_gprs *, int)) step->check_func)(
								gprs, bearer);

	rilmodem_test_engine_next_step(gprs->engined);
}

void ofono_gprs_set_cid_range(struct ofono_gprs *gprs,
				unsigned int min, unsigned int max)
{
	const struct rilmodem_test_step *step;

	step = rilmodem_test_engine_get_current_step(gprs->engined);

	g_assert(step->type == TST_EVENT_CALL);
	g_assert(step->call_func == (void (*)(void)) ofono_gprs_set_cid_range);

	if (step->check_func != NULL)
		((void (*)(struct ofono_gprs *, unsigned int, unsigned int))
					step->check_func)(gprs, min, max);

	rilmodem_test_engine_next_step(gprs->engined);
}

struct ofono_modem *ofono_gprs_get_modem(struct ofono_gprs *gprs)
{
	return gprs->modem;
}

int ofono_modem_set_integer(struct ofono_modem *modem,
				const char *key, int value)
{
	const struct rilmodem_test_step *step;

	step = rilmodem_test_engine_get_current_step(modem->gprs->engined);

	g_assert(step->type == TST_EVENT_CALL);
	g_assert(step->call_func == (void (*)(void)) ofono_modem_set_integer);

	if (step->check_func != NULL)
		((void (*)(struct ofono_modem *, const char *, int))
					step->check_func)(modem, key, value);

	rilmodem_test_engine_next_step(modem->gprs->engined);

	return 0;
}

void ofono_gprs_remove(struct ofono_gprs *gprs)
{
	const struct rilmodem_test_step *step;

	step = rilmodem_test_engine_get_current_step(gprs->engined);

	g_assert(step->type == TST_EVENT_CALL);
	g_assert(step->call_func == (void (*)(void)) ofono_gprs_remove);

	rilmodem_test_engine_next_step(gprs->engined);
}

/*
 * As all our architectures are little-endian except for
 * PowerPC, and the Binder wire-format differs slightly
 * depending on endian-ness, the following guards against test
 * failures when run on PowerPC.
 */
#if BYTE_ORDER == LITTLE_ENDIAN

/* REQUEST_DATA_CALL_LIST, seq 1 */
static const char parcel_req_data_call_list_1_1[] = {
	0x00, 0x00, 0x00, 0x08, 0x39, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};

/*
 * --- TEST 1 ---
 * Step 1: Driver sends REQUEST_DATA_CALL_LIST
 */
static const struct rilmodem_test_step steps_test_1[] = {
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_data_call_list_1_1,
		.parcel_size = sizeof(parcel_req_data_call_list_1_1)
	}
};

struct rilmodem_test_data test_1 = {
	.steps = steps_test_1,
	.num_steps = G_N_ELEMENTS(steps_test_1)
};

/* REQUEST_DATA_CALL_LIST, seq 1 */
static const char parcel_req_data_call_list_2_1[] = {
	0x00, 0x00, 0x00, 0x08, 0x39, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};

/* Response, no errors */
static const char parcel_rsp_data_call_list_2_2[] = {
	0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* REQUEST_DATA_REGISTRATION_STATE, seq 2 */
static const char parcel_req_data_registration_state_2_3[] = {
	0x00, 0x00, 0x00, 0x08, 0x15, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};

/* Responso, no error, {unregistered,0xb08,0x10e1,GPRS,(null),4} */
static const char parcel_rsp_data_registration_state_2_4[] = {
	0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x30, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x30, 0x00, 0x62, 0x00,
	0x30, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
	0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x31, 0x00, 0x30, 0x00,
	0x65, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x31, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
	0x34, 0x00, 0x00, 0x00
};

static void set_cid_range_check_2_5(struct ofono_gprs *gprs,
					unsigned int min, unsigned int max)
{
	g_assert(min == 1);
	g_assert(max == 2);
}

static void gprs_cb_2_8(const struct ofono_error *error, void *data)
{
	struct ofono_gprs *gprs = data;

	g_assert(error->type == OFONO_ERROR_TYPE_NO_ERROR);

	rilmodem_test_engine_next_step(gprs->engined);
}

static void call_set_attached_2_7(gpointer data)
{
	struct ofono_gprs *gprs = data;

	gprs_drv->set_attached(gprs, 0, gprs_cb_2_8, gprs);

	rilmodem_test_engine_next_step(gprs->engined);
}

/*
 * --- TEST 2 ---
 * Step 1: Driver sends REQUEST_DATA_CALL_LIST
 * Step 2: Harness answers with empty data call list
 * Step 3: Driver sends REQUEST_DATA_REGISTRATION_STATE
 * Step 4: Harness answers with status unregistered
 * Step 5: Driver calls ofono_gprs_set_cid_range
 * Step 6: Driver calls ofono_gprs_register
 * Step 7: Harness calls drv->set_attached(false)
 * Step 8: Driver calls the callback specified in step 7
 */
static const struct rilmodem_test_step steps_test_2[] = {
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_data_call_list_2_1,
		.parcel_size = sizeof(parcel_req_data_call_list_2_1)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_data_call_list_2_2,
		.parcel_size = sizeof(parcel_rsp_data_call_list_2_2)
	},
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_data_registration_state_2_3,
		.parcel_size = sizeof(parcel_req_data_registration_state_2_3)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_data_registration_state_2_4,
		.parcel_size = sizeof(parcel_rsp_data_registration_state_2_4)
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_set_cid_range,
		.check_func = (void (*)(void)) set_cid_range_check_2_5
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_register,
		.check_func = NULL
	},
	{
		.type = TST_ACTION_CALL,
		.call_action = call_set_attached_2_7,
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) gprs_cb_2_8,
		.check_func = NULL
	},
};

struct rilmodem_test_data test_2 = {
	.steps = steps_test_2,
	.num_steps = G_N_ELEMENTS(steps_test_2)
};

static void gprs_cb_3_8(const struct ofono_error *error, void *data)
{
	struct ofono_gprs *gprs = data;

	g_assert(error->type == OFONO_ERROR_TYPE_NO_ERROR);

	rilmodem_test_engine_next_step(gprs->engined);
}

static void call_set_attached_3_7(gpointer data)
{
	struct ofono_gprs *gprs = data;

	gprs_drv->set_attached(gprs, 1, gprs_cb_3_8, gprs);

	rilmodem_test_engine_next_step(gprs->engined);
}

/*
 * --- TEST 3 ---
 * Steps 1-6: Same as in test 2
 * Step 7: Harness calls drv->set_attached(true)
 * Step 8: Driver calls the callback specified in step 7
 */
static const struct rilmodem_test_step steps_test_3[] = {
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_data_call_list_2_1,
		.parcel_size = sizeof(parcel_req_data_call_list_2_1)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_data_call_list_2_2,
		.parcel_size = sizeof(parcel_rsp_data_call_list_2_2)
	},
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_data_registration_state_2_3,
		.parcel_size = sizeof(parcel_req_data_registration_state_2_3)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_data_registration_state_2_4,
		.parcel_size = sizeof(parcel_rsp_data_registration_state_2_4)
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_set_cid_range,
		.check_func = (void (*)(void)) set_cid_range_check_2_5
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_register,
		.check_func = NULL
	},
	{
		.type = TST_ACTION_CALL,
		.call_action = call_set_attached_3_7,
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) gprs_cb_3_8,
		.check_func = NULL
	},
};

struct rilmodem_test_data test_3 = {
	.steps = steps_test_3,
	.num_steps = G_N_ELEMENTS(steps_test_3)
};


/* REQUEST_DATA_REGISTRATION_STATE, seq 3 */
static const char parcel_req_registration_state_4_8[] = {
	0x00, 0x00, 0x00, 0x08, 0x15, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00
};

/* Response, no error, {registered,0xb08,0x10e1,GPRS,(null),4} */
static const char parcel_rsp_registration_state_4_9[] = {
	0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x31, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x30, 0x00, 0x62, 0x00,
	0x30, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
	0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x31, 0x00, 0x30, 0x00,
	0x65, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x31, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
	0x34, 0x00, 0x00, 0x00
};

static void reg_state_cb_4_12(const struct ofono_error *error,
							int status, void *data)
{
	struct ofono_gprs *gprs = data;
	const struct rilmodem_test_step *step;

	step = rilmodem_test_engine_get_current_step(gprs->engined);

	g_assert(step->type == TST_EVENT_CALL);
	g_assert(step->call_func == (void (*)(void)) reg_state_cb_4_12);

	g_assert(error->type == OFONO_ERROR_TYPE_NO_ERROR);
	/*
	 * Driver returns unregistered even though network state is attached
	 * because we did not set attach to true in this test case.
	 */
	g_assert(status == NETWORK_REGISTRATION_STATUS_NOT_REGISTERED);

	rilmodem_test_engine_next_step(gprs->engined);
}

static void call_registration_status_4_7(gpointer data)
{
	struct ofono_gprs *gprs = data;

	gprs_drv->attached_status(gprs, reg_state_cb_4_12, gprs);

	rilmodem_test_engine_next_step(gprs->engined);
}

static void set_integer_check_4_10(struct ofono_modem *modem,
						const char *key, int value)
{
	g_assert_cmpstr(key, ==, "RilDataRadioTechnology");
	g_assert(value == RADIO_TECH_GPRS);
}

static void gprs_bearer_check_4_11(struct ofono_gprs *gprs, int bearer)
{
	g_assert(bearer == PACKET_BEARER_GPRS);
}

/*
 * --- TEST 4 ---
 * Steps 1-6: Same as in test 2
 * Step 7: Harness calls drv->registration_status
 * Step 8: Driver sends REQUEST_DATA_REGISTRATION_STATE
 * Step 9: Harness answers saying status is registered
 * Step 10: Driver calls ofono_modem_set_integer
 * Step 11: Driver calls ofono_gprs_bearer_notify(PACKET_BEARER_GPRS)
 * Step 12: Driver calls the callback specified in step 7
 */
static const struct rilmodem_test_step steps_test_4[] = {
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_data_call_list_2_1,
		.parcel_size = sizeof(parcel_req_data_call_list_2_1)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_data_call_list_2_2,
		.parcel_size = sizeof(parcel_rsp_data_call_list_2_2)
	},
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_data_registration_state_2_3,
		.parcel_size = sizeof(parcel_req_data_registration_state_2_3)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_data_registration_state_2_4,
		.parcel_size = sizeof(parcel_rsp_data_registration_state_2_4)
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_set_cid_range,
		.check_func = (void (*)(void)) set_cid_range_check_2_5
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_register,
		.check_func = NULL
	},
	{
		.type = TST_ACTION_CALL,
		.call_action = call_registration_status_4_7,
	},
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_registration_state_4_8,
		.parcel_size = sizeof(parcel_req_registration_state_4_8)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_registration_state_4_9,
		.parcel_size = sizeof(parcel_rsp_registration_state_4_9)
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_modem_set_integer,
		.check_func = (void (*)(void)) set_integer_check_4_10
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_bearer_notify,
		.check_func = (void (*)(void)) gprs_bearer_check_4_11
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) reg_state_cb_4_12,
		.check_func = NULL
	},
};

struct rilmodem_test_data test_4 = {
	.steps = steps_test_4,
	.num_steps = G_N_ELEMENTS(steps_test_4)
};

/* UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED */
static const char parcel_ev_network_state_changed_5_9[] = {
	0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0xEA, 0x03, 0x00, 0x00
};

/* REQUEST_DATA_REGISTRATION_STATE, seq 3 */
static const char parcel_req_registration_state_5_10[] = {
	0x00, 0x00, 0x00, 0x08, 0x15, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00
};

/* Response, no error, {registered,0xb08,0x10e1,GPRS,(null),4} */
static const char parcel_rsp_registration_state_5_11[] = {
	0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x31, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x30, 0x00, 0x62, 0x00,
	0x30, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
	0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x31, 0x00, 0x30, 0x00,
	0x65, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x31, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
	0x34, 0x00, 0x00, 0x00
};

static void gprs_status_check_5_12(struct ofono_gprs *gprs, int status)
{
	g_assert(status == NETWORK_REGISTRATION_STATUS_REGISTERED);
}

static void set_integer_check_5_13(struct ofono_modem *modem,
						const char *key, int value)
{
	g_assert_cmpstr(key, ==, "RilDataRadioTechnology");
	g_assert(value == RADIO_TECH_GPRS);
}

static void gprs_bearer_check_5_14(struct ofono_gprs *gprs, int bearer)
{
	g_assert(bearer == PACKET_BEARER_GPRS);
}

/*
 * --- TEST 5 ---
 * Steps 1-8: Same as test 3
 * Step 9: Harness sends UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED
 * Step 10: Driver sends REQUEST_DATA_REGISTRATION_STATE
 * Step 11: Harness answers saying status is registered
 * Step 12: Driver calls ofono_gprs_status_notify(REGISTERED)
 * Step 13: Driver calls ofono_modem_set_integer
 * Step 14: Driver calls ofono_gprs_bearer_notify(PACKET_BEARER_GPRS)
 */
static const struct rilmodem_test_step steps_test_5[] = {
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_data_call_list_2_1,
		.parcel_size = sizeof(parcel_req_data_call_list_2_1)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_data_call_list_2_2,
		.parcel_size = sizeof(parcel_rsp_data_call_list_2_2)
	},
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_data_registration_state_2_3,
		.parcel_size = sizeof(parcel_req_data_registration_state_2_3)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_data_registration_state_2_4,
		.parcel_size = sizeof(parcel_rsp_data_registration_state_2_4)
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_set_cid_range,
		.check_func = (void (*)(void)) set_cid_range_check_2_5
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_register,
		.check_func = NULL
	},
	{
		.type = TST_ACTION_CALL,
		.call_action = call_set_attached_3_7,
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) gprs_cb_3_8,
		.check_func = NULL
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_ev_network_state_changed_5_9,
		.parcel_size = sizeof(parcel_ev_network_state_changed_5_9)
	},
	{
		.type = TST_EVENT_RECEIVE,
		.parcel_data = parcel_req_registration_state_5_10,
		.parcel_size = sizeof(parcel_req_registration_state_5_10)
	},
	{
		.type = TST_ACTION_SEND,
		.parcel_data = parcel_rsp_registration_state_5_11,
		.parcel_size = sizeof(parcel_rsp_registration_state_5_11)
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_status_notify,
		.check_func = (void (*)(void)) gprs_status_check_5_12
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_modem_set_integer,
		.check_func = (void (*)(void)) set_integer_check_5_13
	},
	{
		.type = TST_EVENT_CALL,
		.call_func = (void (*)(void)) ofono_gprs_bearer_notify,
		.check_func = (void (*)(void)) gprs_bearer_check_5_14
	},
};

struct rilmodem_test_data test_5 = {
	.steps = steps_test_5,
	.num_steps = G_N_ELEMENTS(steps_test_5)
};

extern struct ofono_driver_desc __start___gprs[];

static void server_connect_cb(gpointer data)
{
	struct ofono_gprs *gprs = data;
	int retval;

	/*
	 * This triggers the first event from the gprs atom, which is a request
	 * to retrieve currently active data calls. Test steps must start from
	 * there.
	 */
	gprs_drv = __start___gprs[0].driver;
	retval = gprs_drv->probe(gprs, OFONO_RIL_VENDOR_AOSP, gprs->ril);
	g_assert(retval == 0);
}

/*
 * This unit test:
 *  - does some test data setup
 *  - configures a dummy server socket
 *  - creates a new gril client instance
 *    - triggers a connect to the dummy
 *      server socket
 *  - starts the test engine
 */
static void test_function(gconstpointer data)
{
	const struct rilmodem_test_data *test_data = data;
	struct ofono_gprs *gprs;
	struct ofono_modem *modem;

	gprs = g_malloc0(sizeof(*gprs));
	modem = g_malloc0(sizeof(*modem));

	modem->gprs = gprs;
	gprs->modem = modem;

	gprs->engined = rilmodem_test_engine_create(&server_connect_cb,
							test_data, gprs);

	gprs->ril = g_ril_new(rilmodem_test_engine_get_socket_name(gprs->engined),
							OFONO_RIL_VENDOR_AOSP);
	g_assert(gprs->ril != NULL);

	/* Perform test */
	rilmodem_test_engine_start(gprs->engined);

	gprs_drv->remove(gprs);
	g_ril_unref(gprs->ril);
	g_free(modem);
	g_free(gprs);

	rilmodem_test_engine_remove(gprs->engined);
}

#endif

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

/*
 * As all our architectures are little-endian except for
 * PowerPC, and the Binder wire-format differs slightly
 * depending on endian-ness, the following guards against test
 * failures when run on PowerPC.
 */
#if BYTE_ORDER == LITTLE_ENDIAN
	g_test_add_data_func("/test-rilmodem-gprs/1", &test_1, test_function);
	g_test_add_data_func("/test-rilmodem-gprs/2", &test_2, test_function);
	g_test_add_data_func("/test-rilmodem-gprs/3", &test_3, test_function);
	g_test_add_data_func("/test-rilmodem-gprs/4", &test_4, test_function);
	g_test_add_data_func("/test-rilmodem-gprs/5", &test_5, test_function);
#endif
	return g_test_run();
}

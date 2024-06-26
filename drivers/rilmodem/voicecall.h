/*
 * oFono - Open Source Telephony
 * Copyright (C) 2014  Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

struct ril_voicecall_data {
	GSList *calls;
	/* Call local hangup indicator, one bit per call (1 << call_id) */
	unsigned int local_release;
	unsigned int clcc_source;
	GRil *ril;
	unsigned int vendor;
	unsigned char flags;
	ofono_voicecall_cb_t cb;
	void *data;
	gchar *tone_queue;
	gboolean tone_pending;
	gboolean suppress_clcc_poll;
};

int ril_voicecall_probe(struct ofono_voicecall *vc, unsigned int vendor,
			void *data);
void ril_voicecall_remove(struct ofono_voicecall *vc);
void ril_dial(struct ofono_voicecall *vc, const struct ofono_phone_number *ph,
		enum ofono_clir_option clir, ofono_voicecall_cb_t cb,
		void *data);
void ril_answer(struct ofono_voicecall *vc,
		ofono_voicecall_cb_t cb, void *data);
void ril_hangup_all(struct ofono_voicecall *vc, ofono_voicecall_cb_t cb,
			void *data);
void ril_hangup_specific(struct ofono_voicecall *vc,
				int id, ofono_voicecall_cb_t cb, void *data);
void ril_send_dtmf(struct ofono_voicecall *vc, const char *dtmf,
			ofono_voicecall_cb_t cb, void *data);
void ril_create_multiparty(struct ofono_voicecall *vc,
				ofono_voicecall_cb_t cb, void *data);
void ril_private_chat(struct ofono_voicecall *vc, int id,
			ofono_voicecall_cb_t cb, void *data);
void ril_swap_without_accept(struct ofono_voicecall *vc,
				ofono_voicecall_cb_t cb, void *data);
void ril_hold_all_active(struct ofono_voicecall *vc,
				ofono_voicecall_cb_t cb, void *data);
void ril_release_all_held(struct ofono_voicecall *vc,
				ofono_voicecall_cb_t cb, void *data);
void ril_set_udub(struct ofono_voicecall *vc,
			ofono_voicecall_cb_t cb, void *data);
void ril_release_all_active(struct ofono_voicecall *vc,
				ofono_voicecall_cb_t cb, void *data);

void ril_call_state_notify(struct ril_msg *message, gpointer user_data);
gboolean ril_poll_clcc(gpointer user_data);

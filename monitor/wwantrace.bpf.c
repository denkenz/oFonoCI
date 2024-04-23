/*
 * oFono - Open Source Telephony
 * Copyright (C) 2024  Cruise, LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <linux/types.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <linux/netlink.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "wwantrace.h"

char LICENSE[] SEC("license") = "GPL";

struct sock;
struct netlink_ext_ack;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct kobject {
	const char *name;
};

struct device {
	struct kobject kobj;
	const char *init_name;
};

struct usb_interface {
	struct device *usb_dev;
};

struct wdm_device {
	struct usb_interface *intf;
	enum wwan_port_type wwanp_type;
};

struct file {
	void *private_data;
};

struct capture_512 {
	struct metadata meta;
	uint8_t packet[512 - sizeof(struct metadata)];
} __attribute__ ((packed));

struct capture_1k {
	struct metadata meta;
	uint8_t packet[1024 - sizeof(struct metadata)];
} __attribute__ ((packed));

struct capture_4k {
	struct metadata meta;
	uint8_t packet[4096 - sizeof(struct metadata)];
} __attribute__ ((packed));

struct capture_8k {
	struct metadata meta;
	uint8_t packet[8192 - sizeof(struct metadata)];
} __attribute__ ((packed));

struct capture_16k {
	struct metadata meta;
	uint8_t packet[16384];
} __attribute__ ((packed));

static void metadata_fill(struct metadata *meta, uint16_t len, bool rx,
				enum wwan_port_type type, const char *name)
{
	meta->timestamp = bpf_ktime_get_boot_ns();
	meta->len = len;
	bpf_get_current_comm(meta->comm, sizeof(meta->comm));
	meta->type = type;
	memset(meta->path, 0, sizeof(meta->path));
	meta->rx = rx;
	meta->pid = bpf_get_current_pid_tgid() >> 32;

	bpf_probe_read_kernel_str(meta->path, sizeof(meta->path), name);
}

static int capture_common(bool rx, struct file *file,
					const char *data, size_t len)
{
	struct wdm_device *desc = BPF_CORE_READ(file, private_data);
	struct usb_interface *intf = BPF_CORE_READ(desc, intf);
	struct device *usb_dev = BPF_CORE_READ(intf, usb_dev);
	struct kobject *kobj = __builtin_preserve_access_index(&usb_dev->kobj);
	enum wwan_port_type type = 0xffffffff;
	const char *name = NULL;

	if (desc)
		type = BPF_CORE_READ(desc, wwanp_type);

	if (usb_dev)
		name = BPF_CORE_READ(usb_dev, init_name);

	if (!name && kobj)
		name = BPF_CORE_READ(kobj, name);

	/*
	 * bpf_ringbuf_reserve is currently limited to a known constant
	 * value, and cannot handle values that are not constant (even if
	 * bounded).  bpf_ringbuf_output might be suitable, but no metadata
	 * could be prepended if that is used.  Another alternative is to use
	 * a perf buffer, but it is per-CPU and might result in packets being
	 * processed out of order.  We trick the validator by using several
	 * well known structure sizes (512/1k/4k/8k/16k) in order to save on
	 * memory space, but the resultant program is larger than it would be
	 * if dynamic sizing was supported.
	 */
	if (len <= sizeof(struct capture_512) - sizeof(struct metadata)) {
		struct capture_512 *c512 = bpf_ringbuf_reserve(&rb,
					sizeof(struct capture_512), 0);

		if (!c512)
			return 0;

		metadata_fill(&c512->meta, len, rx, type, name);

		if (bpf_probe_read_user(c512->packet, len, data) < 0)
			bpf_ringbuf_discard(c512, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c512, 0);

		return 0;
	}

	if (len <= sizeof(struct capture_1k) - sizeof(struct metadata)) {
		struct capture_1k *c1k = bpf_ringbuf_reserve(&rb,
						sizeof(struct capture_1k), 0);

		if (!c1k)
			return 0;

		metadata_fill(&c1k->meta, len, rx, type, name);

		if (bpf_probe_read_user(c1k->packet, len, data) < 0)
			bpf_ringbuf_discard(c1k, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c1k, 0);

		return 0;
	}

	if (len <= sizeof(struct capture_4k) - sizeof(struct metadata)) {
		struct capture_4k *c4k = bpf_ringbuf_reserve(&rb,
						sizeof(struct capture_4k), 0);

		if (!c4k)
			return 0;

		metadata_fill(&c4k->meta, len, rx, type, name);

		if (bpf_probe_read_user(c4k->packet, len, data) < 0)
			bpf_ringbuf_discard(c4k, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c4k, 0);

		return 0;
	}

	if (len <= sizeof(struct capture_8k) - sizeof(struct metadata)) {
		struct capture_8k *c8k = bpf_ringbuf_reserve(&rb,
						sizeof(struct capture_8k), 0);

		if (!c8k)
			return 0;

		metadata_fill(&c8k->meta, len, rx, type, name);

		if (bpf_probe_read_user(c8k->packet, len, data) < 0)
			bpf_ringbuf_discard(c8k, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c8k, 0);

		return 0;
	}

	/* 16384 is the largest packet size for genl currently */
	if (len <= 16384) {
		struct capture_16k *c16k = bpf_ringbuf_reserve(&rb,
						sizeof(struct capture_16k), 0);

		if (!c16k)
			return 0;

		metadata_fill(&c16k->meta, len, rx, type, name);

		if (bpf_probe_read_user(c16k->packet, len, data) < 0)
			bpf_ringbuf_discard(c16k, BPF_RB_NO_WAKEUP);
		else
			bpf_ringbuf_submit(c16k, 0);

		return 0;
	}

	return 0;
}

SEC("fexit/wdm_write")
int BPF_PROG(trace_wdm_write, struct file *file, char *buffer,
		size_t count, loff_t *ppos, ssize_t ret)
{
	if (ret < 0)
		return 0;

	return capture_common(false, file, buffer, ret);
}

SEC("fexit/wdm_read")
int BPF_PROG(trace_wdm_read, struct file *file, const char *buffer,
		size_t count, loff_t *ppos, ssize_t ret)
{
	if (ret < 0)
		return 0;

	return capture_common(true, file, buffer, ret);
}

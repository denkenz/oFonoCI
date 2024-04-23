/*
 * oFono - Open Source Telephony
 * Copyright (C) 2024  Cruise, LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "wwantrace.h"
#include "wwantrace.skel.h"

#include <ell/ell.h>

static struct wwantrace_bpf *skel;
static struct ring_buffer *rb;
static struct l_io *io;

static inline void print_space(int n)
{
	printf("%*c", n, ' ');
}

static int libbpf_print_fn(enum libbpf_print_level level,
				const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void output(const char *str, void *user_data)
{
	const char *prefix = user_data;

	printf("%s%s\n", prefix, str);
}

static const char *wwan_port_to_str(enum wwan_port_type type)
{
	switch(type) {
	case WWAN_PORT_AT:
		return "AT";
	case WWAN_PORT_MBIM:
		return "MBIM";
	case WWAN_PORT_QMI:
		return "QMI";
	case WWAN_PORT_QCDM:
		return "QCDM";
	case WWAN_PORT_FIREHOSE:
		return "FIREHOSE";
	case WWAN_PORT_XMMRPC:
		return "XMMRPC";
	case WWAN_PORT_FASTBOOT:
		return "FASTBOOT";
	}

	return "UNKOWN";
}

static int handle_packet(void *ctx, void *data, size_t size)
{
	struct metadata *meta = data;
	struct timeval tv;
	char ts_str[64];
	char line[256];
	size_t ts_len;
	size_t line_len;
	size_t col = 80;

	data += sizeof(struct metadata);

	tv.tv_sec = meta->timestamp / L_NSEC_PER_SEC;
	tv.tv_usec = (meta->timestamp % L_NSEC_PER_SEC) / L_NSEC_PER_USEC;

	ts_len = sprintf(ts_str, " %" PRIu64 ".%06" PRIu64,
			(uint64_t) tv.tv_sec, (uint64_t) tv.tv_usec);

	line_len = sprintf(line, "%c len: %hu %s[%u] %s %s",
				meta->rx ? '<' : '>', meta->len,
				meta->comm, meta->pid,
				wwan_port_to_str(meta->type), meta->path);

	printf("%s", line);
	if (line_len < col)
		print_space(col - line_len - ts_len - 1);
	printf("%s\n", ts_str);

	l_util_hexdump(meta->rx, data, meta->len, output, "\t");

	return 0;
}

static bool ringbuf_receive(struct l_io *io, void *user_data)
{
	ring_buffer__poll(rb, 0);

	return true;
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_main_quit();
		break;
	}
}

static void usage(void)
{
	printf("wwantrace - WWAN monitor using eBPF\n"
		"Usage:\n");
	printf("\twwantrace [options]\n");
	printf("Options:\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "version",   no_argument,       NULL, 'v' },
	{ "help",      no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	int exit_status = EXIT_FAILURE;
	int err;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "vh",
						main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = wwantrace_bpf__open_and_load();
	if (!skel)
		return EXIT_FAILURE;

	fprintf(stdout, "WWAN monitor (eBPF) ver %s\n", VERSION);

	if (!l_main_init())
		goto init_failed;

	err = wwantrace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Unable to attach eBPF program\n");
		goto attach_failed;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
					handle_packet, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ringbuffer\n");
		goto rb_failed;
	}

	io = l_io_new(bpf_map__fd(skel->maps.rb));
	l_io_set_close_on_destroy(io, false);
	l_io_set_read_handler(io, ringbuf_receive, NULL, NULL);

	exit_status = l_main_run_with_signal(signal_handler, NULL);

	l_io_destroy(io);
rb_failed:
	ring_buffer__free(rb);
attach_failed:
	l_main_exit();
init_failed:
	wwantrace_bpf__destroy(skel);

	return exit_status;
}

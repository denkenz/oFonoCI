/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2024  Cruise LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "drivers/qmimodem/qmi.h"

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <linux/qrtr.h>
#include <ell/ell.h>

#include <ofono/types.h>
#include <src/ofono.h>

#include <sys/socket.h>
#include <sys/param.h>

#define CONTROL_NODE 42
#define SERVICE_NODE 43

struct sendto_record {
	int sockfd;
	int flags;
	struct sockaddr_qrtr sockaddr;
	size_t len;
	uint8_t data[];
};

struct recvfrom_entry {
	struct sockaddr_qrtr sockaddr;
	size_t len;
	uint8_t data[];
};

static const struct sockaddr_qrtr control_addr = {
	.sq_family = AF_QIPCRTR,
	.sq_node = CONTROL_NODE,
	.sq_port = QRTR_PORT_CTRL,
};

struct test_info {
	struct qmi_device *device;
	int test_socket;
	int client_socket; /* Used by qmi_device to send/receive */
	struct l_queue *sendto;
	struct l_queue *recvfrom;
	bool discovery_callback_called : 1;
};

static struct test_info *info;

ssize_t __wrap_sendto(int sockfd, const void *buf, size_t len, int flags,
			const struct sockaddr *dest_addr, socklen_t addrlen)
{
	struct sendto_record *record;

	if (addrlen != sizeof(struct sockaddr_qrtr)) {
		errno = EINVAL;
		return -1;
	}

	record = l_malloc(sizeof(struct sendto_record) + len);
	record->sockfd = sockfd;
	record->flags = flags;
	memcpy(&record->sockaddr, dest_addr, addrlen);
	record->len = len;
	memcpy(record->data, buf, len);

	l_queue_push_tail(info->sendto, record);

	return len;
}

static void wakeup_client_read_handler(void)
{
	char c = ' ';

	write(info->test_socket, &c, sizeof(char));
}

static void stop_client_read_handler(void)
{
	char c;

	if (l_queue_isempty(info->recvfrom))
		read(info->client_socket, &c, sizeof(c));
}

static void allow_client_to_read_all(void)
{
	int max_loops = l_queue_length(info->recvfrom) + 10;

	wakeup_client_read_handler();
	while (!l_queue_isempty(info->recvfrom)) {
		l_main_iterate(0);

		max_loops--;
		assert(max_loops > 0);
	}
}

ssize_t __wrap_recvfrom(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen)
{
	struct recvfrom_entry *entry;
	size_t data_bytes_to_copy;
	socklen_t addr_bytes_to_copy;

	if (l_queue_isempty(info->recvfrom)) {
		errno = EAGAIN;
		return -1;
	}

	entry = l_queue_pop_head(info->recvfrom);

	/*
	 * This does not handle the case where the client passes in a buffer
	 * that is too small.
	 */
	data_bytes_to_copy = MIN(len, entry->len);
	memcpy(buf, entry->data, data_bytes_to_copy);

	addr_bytes_to_copy = MIN(*addrlen, sizeof(struct sockaddr_qrtr));
	memcpy(src_addr, &entry->sockaddr, addr_bytes_to_copy);
	*addrlen = addr_bytes_to_copy;

	l_free(entry);

	stop_client_read_handler();

	return data_bytes_to_copy;
}

struct qmi_device *qmi_device_new_qrtr_private(int fd, uint32_t control_node);

static void debug_log(const char *str, void *user_data)
{
	printf("%s\n", str);
}

static void test_setup(void)
{
	int sockets[2];

	l_main_init();

	info = l_new(struct test_info, 1);
	info->sendto = l_queue_new();
	info->recvfrom = l_queue_new();

	socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets);
	info->test_socket = sockets[0];
	info->client_socket = sockets[1];

	info->device = qmi_device_new_qrtr_private(info->client_socket,
							CONTROL_NODE);
	assert(info->device);

	/* Enable ofono logging */
	qmi_device_set_debug(info->device, debug_log, NULL);
}

static void test_cleanup(void)
{
	l_queue_destroy(info->recvfrom, l_free);
	l_queue_destroy(info->sendto, l_free);

	close(info->test_socket);
	qmi_device_free(info->device);

	l_free(info);
	info = NULL;

	l_main_exit();
}

static void create_qrtr_device(const void *data)
{
	test_setup();
	test_cleanup();
}

static void discovery_complete_cb(void *user_data)
{
	assert(user_data == info);
	info->discovery_callback_called = true;
}

static void enqueue_new_server_packet(uint32_t service, uint8_t version,
					uint32_t instance, uint32_t node,
					uint32_t port)
{
	struct recvfrom_entry *entry = l_malloc(
				sizeof(struct recvfrom_entry) +
				sizeof(struct qrtr_ctrl_pkt));
	struct qrtr_ctrl_pkt *new_server =
				(struct qrtr_ctrl_pkt *) entry->data;

	memcpy(&entry->sockaddr, &control_addr, sizeof(struct sockaddr_qrtr));

	entry->len = sizeof(struct qrtr_ctrl_pkt);
	new_server->cmd = L_CPU_TO_LE32(QRTR_TYPE_NEW_SERVER);
	new_server->server.service = L_CPU_TO_LE32(service);
	new_server->server.instance = L_CPU_TO_LE32(instance << 8 | version);
	new_server->server.node = L_CPU_TO_LE32(node);
	new_server->server.port = L_CPU_TO_LE32(port);

	l_queue_push_tail(info->recvfrom, entry);
}

static void initiate_discovery(const void *data)
{
	int rc;
	struct sendto_record *record;
	const struct qrtr_ctrl_pkt *packet;

	test_setup();

	rc = qmi_device_discover(info->device, discovery_complete_cb, info,
								NULL);
	assert(rc == 0);

	assert(l_queue_length(info->sendto) == 1);
	record = l_queue_pop_head(info->sendto);

	assert(record->sockfd == info->client_socket);
	assert(record->flags == 0);
	assert(record->sockaddr.sq_family == AF_QIPCRTR);
	assert(record->sockaddr.sq_node == CONTROL_NODE);
	assert(record->sockaddr.sq_port == QRTR_PORT_CTRL);

	assert(record->len == sizeof(struct qrtr_ctrl_pkt));
	packet = (const struct qrtr_ctrl_pkt *) record->data;
	assert(packet->cmd == QRTR_TYPE_NEW_LOOKUP);

	l_free(record);

	test_cleanup();
}

static void send_servers(const void *data)
{
	int i;
	int rc;

	test_setup();

	rc = qmi_device_discover(info->device, discovery_complete_cb, info,
								NULL);
	assert(rc == 0);

	for (i = 1; i <= 2; i++)
		enqueue_new_server_packet(i, i + 10, 1, SERVICE_NODE, i + 20);

	enqueue_new_server_packet(0, 0, 0, 0, 0);

	allow_client_to_read_all();
	assert(info->discovery_callback_called);

	for (i = 1; i <= 2; i++) {
		uint16_t major, minor;

		assert(qmi_device_has_service(info->device, i));

		assert(qmi_device_get_service_version(info->device, i,
							&major, &minor));
		assert(major == i + 10);
		assert(minor == 0);
	}

	assert(!qmi_device_has_service(info->device, i));

	test_cleanup();
}

int main(int argc, char **argv)
{
	/* Enable all DBG logging */
	__ofono_log_init(argv[0], "*", FALSE);

	l_test_init(&argc, &argv);

	l_test_add("QRTR device creation", create_qrtr_device, NULL);
	l_test_add("QRTR discovery sends NEW_LOOKUP", initiate_discovery, NULL);
	l_test_add("QRTR discovery reads NEW_SERVERs", send_servers, NULL);

	return l_test_run();
}

#include "libvisca.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef VISCA_WIN
#include <winsock.h>
#else
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#endif

// #define DEBUG_UDP
#ifdef DEBUG_UDP
const char *b2s(const uint8_t *buf, int length)
{
	if (length <= 0)
		return "";
	// Ignoring to free since memory will be automatically freed at exit.
	char *sz = malloc(length * 3 + 1);
	for (int i = 0; i < length; i++)
		snprintf(sz + i * 3, 4, "%02X ", buf[i]);
	sz[length * 3 - 1] = 0;
	return sz;
}
#define debug_udp(fmt, ...) fprintf(stderr, "Debug: " fmt "\n", __VA_ARGS__)
#else
#define debug_udp(...)
#endif // DEBUG_UDP

typedef struct _VISCA_udp_ctx {
#ifdef VISCA_WIN
	SOCKET sockfd;
#else
	int sockfd;
#endif

	struct sockaddr_in addr;

	uint32_t seq_sent;
	uint32_t seq_ack;

	// sending buffer
	uint8_t buf_send[64];
	int buf_send_n;

	// receiving buffer
	uint8_t buf_recv[64];
	int buf_recv_n, buf_recv_pl_n, buf_recv_pl_i;
} VISCA_udp_ctx_t;

inline static int is_payload_device_setting(const uint8_t *buf)
{
	// IF_Clear
	if (buf[1] == 0x01 && buf[2] == 0x00 && buf[3] == 0x01 && buf[4] == 0xFF)
		return 1;

	// CAM_VersionInq
	if (buf[1] == 0x09 && buf[2] == 0x00 && buf[3] == 0x02 && buf[4] == 0xFF)
		return 1;

	return 0;
}

inline static void set_timeout_ms(VISCA_udp_ctx_t *ctx, int timeout)
{
	struct timeval tv;
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;
	if (setsockopt(ctx->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, sizeof(tv)) < 0)
		fprintf(stderr, "Error: setsockopt(SO_RCVTIMEO) failed");
}

static int visca_udp_send_packet_buf(VISCA_udp_ctx_t *ctx)
{
	debug_udp("udp: send header=%s payload length=%d buf=%s", b2s(ctx->buf_send, 8), ctx->buf_send_n - 8,
		  b2s(ctx->buf_send + 8, ctx->buf_send_n - 8));
	int ret = sendto(ctx->sockfd, ctx->buf_send, ctx->buf_send_n, 0, (struct sockaddr *)&ctx->addr,
			 sizeof(ctx->addr));
	if (ret >= 8)
		return ret - 8;
	else
		return -1;
}

static int visca_udp_send_packet(VISCA_udp_ctx_t *ctx, uint16_t type, const void *buf, int length)
{
	uint8_t *buf_udp = ctx->buf_send;
	ctx->buf_send_n = length + 8;

	buf_udp[0] = (type >> 8) & 0xFF;
	buf_udp[1] = (type >> 0) & 0xFF;
	buf_udp[2] = (length >> 8) & 0xFF;
	buf_udp[3] = (length >> 0) & 0xFF;
	buf_udp[4] = (ctx->seq_sent >> 24) & 0xFF;
	buf_udp[5] = (ctx->seq_sent >> 16) & 0xFF;
	buf_udp[6] = (ctx->seq_sent >> 8) & 0xFF;
	buf_udp[7] = (ctx->seq_sent >> 0) & 0xFF;
	memcpy(buf_udp + 8, buf, length);

	set_timeout_ms(ctx, 100);
	return visca_udp_send_packet_buf(ctx);
}

static int visca_udp_cb_write(VISCAInterface_t *iface, const void *buf, int length)
{
	VISCA_udp_ctx_t *ctx = iface->ctx;
	const uint8_t *buf_int = buf;
	uint16_t type = 0;

	if (is_payload_device_setting(buf_int))
		type = 0x0120;
	else if (buf_int[1] == VISCA_COMMAND)
		type = 0x0100;
	else if (buf_int[1] == VISCA_INQUIRY)
		type = 0x0110;

	ctx->seq_sent++;

	return visca_udp_send_packet(ctx, type, buf, length);
}

inline static int visca_udp_recv_packet_buf(VISCA_udp_ctx_t *ctx)
{
	int length = recv(ctx->sockfd, ctx->buf_recv, sizeof(ctx->buf_recv), 0);
	if (length >= 0) {
		ctx->buf_recv_n = length;
		debug_udp("udp: recv header=%s payload length=%d buf=%s", b2s(ctx->buf_recv, 8), length - 8,
			  b2s(ctx->buf_recv + 8, length - 8));
	}
	return length;
}

inline static int visca_udp_recv_packet(VISCA_udp_ctx_t *ctx)
{
	uint8_t *buf = ctx->buf_recv;
	do {
		int ret = visca_udp_recv_packet_buf(ctx);
		if (ret < 0 && (errno == ETIMEDOUT || errno == EAGAIN)) {
			if (ctx->seq_ack != ctx->seq_sent) {
				set_timeout_ms(ctx, 1000);
				visca_udp_send_packet_buf(ctx);
			}
			continue;
		} else if (ret < 0 || ret < 8) {
			fprintf(stderr, "Error: libvisca_udp: recv ret=%d errno=%d\n", ret, errno);
			return 1;
		}

		ctx->seq_ack = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
	} while (ctx->seq_ack != ctx->seq_sent);

	if (buf[0] == 0x01 && buf[1] == 0x00) {
		// VISCA command: do nothing
		return 0;
	} else if (buf[0] == 0x01 && buf[1] == 0x10) {
		// VISCA inquiry: do nothing
		return 0;
	} else if (buf[0] == 0x01 && buf[1] == 0x11) {
		// VISCA reply
		ctx->buf_recv_pl_i = 8;
		ctx->buf_recv_pl_n = ctx->buf_recv_n;
		return 0;
	} else if (buf[0] == 0x01 && buf[1] == 0x20) {
		// VISCA device setting: do nothing
		return 0;
	} else if (buf[0] == 0x02 && buf[1] == 0x00) {
		// Control command: do nothing
		if (buf[3] == 2 && buf[8] == 0x0F) {
			const char *msg;
			/* clang-format off */
			switch (buf[9]) {
				case 0x01: msg = "sequence number"; break;
				case 0x02: msg = "message type"; break;
				default: msg = "unknown error"; break;
			}
			/* clang-format on */
			fprintf(stderr, "Error: Control command error %X %s\n", buf[9], msg);
		}
		return 0;
	} else if (buf[0] == 0x02 && buf[1] == 0x01) {
		// Control reply: do nothing
		return 0;
	}

	fprintf(stderr, "Error: libvisca_udp: invalid byte-0/1 0x%X 0x%X\n", buf[0], buf[1]);
	return 1;
}

static int visca_udp_cb_read(VISCAInterface_t *iface, void *buf, int length)
{
	if (length <= 0)
		return 0;

	VISCA_udp_ctx_t *ctx = iface->ctx;

	while (ctx->buf_recv_pl_i >= ctx->buf_recv_pl_n) {
		if (visca_udp_recv_packet(ctx))
			return -1;
	}

	int ret = 0;
	uint8_t *buf_int = buf;
	while (length > 0 && ctx->buf_recv_pl_i != ctx->buf_recv_pl_n) {
		*buf_int++ = ctx->buf_recv[ctx->buf_recv_pl_i++];
		length--;
		ret++;
	}

	return ret;
}

static int visca_udp_cb_close(VISCAInterface_t *iface)
{
	if (!iface || !iface->ctx)
		return VISCA_FAILURE;
	VISCA_udp_ctx_t *ctx = iface->ctx;

	if (ctx->sockfd != -1) {
#ifdef VISCA_WIN
		closesocket(ctx->sockfd);
#else
		close(ctx->sockfd);
#endif
		free(ctx);
		iface->ctx = NULL;
		return VISCA_SUCCESS;
	} else
		return VISCA_FAILURE;
}

static const VISCA_callback_t visca_udp_cb = {
	.write = visca_udp_cb_write,
	.read = visca_udp_cb_read,
	.close = visca_udp_cb_close,
};

static int resolve_hostname(struct sockaddr_in *dst, const char *hostname)
{
	struct hostent *servhost = gethostbyname(hostname);
	if (servhost) {
		dst->sin_family = AF_INET;
		memcpy(&dst->sin_addr, servhost->h_addr, servhost->h_length);
		return 0;
	}

	u_long addr = inet_addr(hostname);
	servhost = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);
	if (servhost) {
		dst->sin_family = AF_INET;
		memcpy(&dst->sin_addr, servhost->h_addr, servhost->h_length);
		return 0;
	}

	return 1;
}

static int initialize_socket(VISCA_udp_ctx_t *ctx, const char *hostname, int port, const char *bind_address)
{
	if (resolve_hostname(&ctx->addr, hostname)) {
		fprintf(stderr, "Error: cannot get server address for \"%s\"\n", hostname);
		return 1;
	}

	ctx->addr.sin_port = htons(port);

	ctx->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctx->sockfd < 0) {
		fprintf(stderr, "Error: cannot create socket\n");
		return 1;
	}

	struct sockaddr_in server = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};

	if (bind_address)
		resolve_hostname(&server, bind_address);

	if (bind(ctx->sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		fprintf(stderr, "Error: cannot bind UDP port %d %s\n", port, bind_address ? bind_address : "");
		return 1;
	}

	if (setsockopt(ctx->sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&(int){1}, sizeof(int)) < 0)
		fprintf(stderr, "Error: setsockopt(SO_REUSEADDR) failed");

	set_timeout_ms(ctx, 100);

	return 0;
}

inline static int visca_udp_control_reset(VISCA_udp_ctx_t *ctx)
{
	uint8_t buf[1] = {0x01};
	int length = 1;
	int type = 0x0200;
	ctx->seq_sent = 0;
	ctx->seq_ack = -1;

	if (visca_udp_send_packet(ctx, type, buf, length) != length)
		return 1;

	if (visca_udp_recv_packet(ctx))
		return 1;

	return 0;
}

uint32_t VISCA_open_udp(VISCAInterface_t *iface, const char *hostname, int port)
{
	return VISCA_open_udp4(iface, hostname, port, NULL);
}

uint32_t VISCA_open_udp4(VISCAInterface_t *iface, const char *hostname, int port, const char *bind_address)
{
	VISCA_udp_ctx_t *ctx = calloc(1, sizeof(VISCA_udp_ctx_t));

	if (initialize_socket(ctx, hostname, port, bind_address)) {
		free(ctx);
		return VISCA_FAILURE;
	}

	iface->callback = &visca_udp_cb;
	iface->ctx = ctx;
	iface->address = 0;
	iface->broadcast = 0;

	if (visca_udp_control_reset(ctx))
		return VISCA_FAILURE;

	return VISCA_SUCCESS;
}

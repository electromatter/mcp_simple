#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <string.h>

#include <unistd.h>
#include <sys/errno.h>

#include <ev.h>

#include "fbuf.h"
#include "base.h"

#include "../src/config.h"
#include "../src/net.h"

char *g_motd;

enum client_state {
	HANDSHAKE = 0,
	STATUS = 1,
	DONE = 3
};

struct client {
	enum client_state state;
	struct fbuf in_buf, out_buf;
	struct ev_io w;
	struct ev_timer timeout;
	int protocol_version;
	int can_read;
};

static struct fbuf *fbuf_temp(void)
{
	static struct fbuf temp = {NULL, 0, FBUF_MAX, 0, 0};
	fbuf_clear(&temp);
	return &temp;
}

static int set_watchers(struct client *c);
static void free_client(struct client *c);
static int handle_new_data(struct client *c);
static int handle_packet(struct client *c, union mcr_any *packet);

static void io_trampoline(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct client *c = w->data;
	ssize_t ret;
	assert((revents & ~(EV_READ | EV_WRITE)) == 0);
	(void)loop;
	
	if (revents & EV_WRITE) {
		if (fbuf_write(&c->out_buf, c->w.fd, -1) < 0 && errno != EAGAIN) {
			free_client(c);
			return;
		}
	}
	
	if (revents & EV_READ) {
		ret = fbuf_read(&c->in_buf, c->w.fd, SPLICE_SIZE);
		if (ret < 0 && errno != EAGAIN) {
			free_client(c);
			return;
		}
		
		if (ret == 0)
			c->can_read = 0;
		
		if (handle_new_data(c) < 0) {
			free_client(c);
			return;
		}
	}
	
	if (set_watchers(c) < 0) {
		free_client(c);
		return;
	}
}

static int send_packet(struct client *c, int mode, union mcr_any *packet)
{
	int err = 0;
	struct fbuf *temp = fbuf_temp();
	
	err |= mcg_varint(temp, packet->id);
	err |= mcr_server_pack(temp, mode, packet);
	
	if (err)
		return -1;
	
	if (mcg_varint(&c->out_buf, fbuf_avail(temp)))
		return -1;
	
	if (fbuf_copy(&c->out_buf, fbuf_ptr(temp), fbuf_avail(temp)))
		return -1;
	
	return 0;
}

static int json_escape(char *dest, int max, const char *src)
{
	int i;
	
	if (src == NULL)
		return json_escape(dest, max, "");
	
	if (max < 2)
		return -1;
	
	dest[0] = '"';
	
	for (i = 1; *src && i < max - 2; i++, src++) {
		switch (*src) {
		case '"':
			if (i == max - 3)
				goto END;
			
			dest[i++] = '\\';
		default:
			dest[i] = *src;
		}
	}
	
END:
	
	dest[i++] = '"';
	dest[i++] = 0;
	
	for (; *src; i++, src++)
		if (*src == '"')
			i++;
		
	return i;
}

static int send_disconnect(struct client *c, const char *message)
{
	char escaped[512];
	char response[1024];
	union mcr_any packet;
	
	json_escape(escaped, sizeof(escaped), message);
	sprintf(response, "{\"text\":%s}", escaped);
	
	packet.id = MCR_LOGIN_DISCONNECT;
	packet.login_disconnect.reason = response;
	packet.login_disconnect.reason_length = strlen(response);
	
	return send_packet(c, MCR_LOGIN, &packet);
}

static int send_pong(struct client *c, uint64_t time)
{
	union mcr_any packet;
	
	packet.id = MCR_STATUS_PING;
	packet.status_ping.time = time;
	
	return send_packet(c, MCR_STATUS, &packet);
}

static int send_motd(struct client *c, const char *motd)
{
	char escaped[512];
	char response[1024];
	union mcr_any packet;
	
	json_escape(escaped, sizeof(escaped), motd);
	sprintf(response, "{\"version\":{\"name\":\"ec10k\",\"protocol\":%i},\"players\":{\"max\":0,\"online\":0},\"description\":%s}", c->protocol_version, escaped);
	
	packet.id = MCR_STATUS_RESPONSE;
	packet.status_response.motd = response;
	packet.status_response.motd_length = strlen(response);
	
	return send_packet(c, MCR_STATUS, &packet);
}

static int handle_packet(struct client *c, union mcr_any *packet)
{
	switch (c->state) {
	case HANDSHAKE:
		if (packet->id != MCR_HANDSHAKE_START)
			return -1;
		
		c->protocol_version = packet->handshake_start.version;
		
		switch (packet->handshake_start.next_state) {
		case 1:
			c->state = STATUS;
			break;
			
		case 2:
			
			if (send_disconnect(c, MCP_DISCONNECT_MESSAGE) < 0)
				return -1;
			
			c->can_read = 0;
			c->state = DONE;
			
			return 0;
			
		default:
			return -1;
		}
		
		break;
	
	case STATUS:
		switch (packet->id) {
		case MCR_STATUS_PING:
			
			if (send_pong(c, packet->status_ping.time) < 0)
				return -1;
			
			c->can_read = 0;
			
			break;
		
		case MCR_STATUS_REQUEST:
			
			if (send_motd(c, g_motd) < 0)
				return -1;
			
			break;
		
		default:
			return -1;
		}
		
		break;
	
	default:
		assert(0);
		return -1;
	}
	return 1;
}

static int mc47_frame_parser(struct mcp_parse *src, struct mcp_parse *p)
{
	uint64_t size;
	uint64_t id;
	
	size = mcp_varint(src);
	mcp_start(p, mcp_raw(src, size), size);
	
	if (!mcp_ok(src))
		return -1;
	
	id = mcp_varint(p);
	
	if (!mcp_ok(p)) {
		src->error = p->error;
		return -1;
	}
	
	if (id > INT_MAX) {
		src->error = MCP_EINVAL;
		p->error = MCP_EINVAL;
		return -1;
	}
	
	return id;
}

static int handle_new_data(struct client *c)
{
	int id, ret;
	struct mcp_parse raw;
	struct mcp_parse frame;
	union mcr_any packet;
	
	mcp_start(&raw, fbuf_ptr(&c->in_buf), fbuf_avail(&c->in_buf));
	
	id = mc47_frame_parser(&raw, &frame);
	
	while (mcp_error(&raw) != MCP_EAGAIN) {
		if (id < 0 || !mcp_ok(&raw))
			return -1;
		
		mcr_server_parse(&packet, c->state == HANDSHAKE ? MCR_HANDSHAKE : MCR_STATUS, id, &frame);
		if (!mcp_ok(&frame))
			return -1;
		
		ret = handle_packet(c, &packet);
		
		if (ret < 0)
			return -1;
		
		if (ret == 0)
			break;
		
		id = mc47_frame_parser(&raw, &frame);
	}
	
	fbuf_consume(&c->in_buf, mcp_consumed(&raw));
	return 0;
}

static void timeout_trampoline(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct client *c = w->data;
	assert(revents == EV_TIMER);
	(void)loop; (void)revents;
	
	free_client(c);
}

static void free_client(struct client *c)
{
	assert(c);
	fbuf_free(&c->in_buf);
	fbuf_free(&c->out_buf);
	ev_io_stop(ev_default_loop(0), &c->w);
	ev_timer_stop(ev_default_loop(0), &c->timeout);
	if (c->w.fd >= 0)
		close(c->w.fd);
	free(c);
	printf("%i client closed\n", c->w.fd);
}

void sock_accepted(int fd, struct sockaddr *addr, socklen_t len)
{
	char name[64];
	struct client *c = malloc(sizeof(*c));
	
	if (c == NULL) {
		printf("out of memory!\n");
		close(fd);
		return;
	}
	
	c->state = HANDSHAKE;
	c->can_read = 1;
	
	fbuf_init(&c->in_buf, MAX_HANDSHAKE);
	fbuf_init(&c->out_buf, FBUF_MAX);
	
	ev_io_init(&c->w, io_trampoline, fd, 0);
	ev_timer_init(&c->timeout, timeout_trampoline, MOTD_TIMEOUT, MOTD_TIMEOUT);
	c->w.data = c;
	c->timeout.data = c;
	
	ev_timer_start(ev_default_loop(0), &c->timeout);
	
	if (set_watchers(c) < 0) {
		free_client(c);
		return;
	}
	
	if (format_addr(name, addr, len) < 0)
		name[0] = 0;
	
	printf("%i accepted %s\n", fd, name);
}

static int set_watchers(struct client *c)
{
	int events = 0;
	
	if (c->can_read)
		events |= EV_READ;
	
	if (fbuf_avail(&c->out_buf) > 0)
		events |= EV_WRITE;
	
	ev_io_stop(ev_default_loop(0), &c->w);
	
	if (events == 0)
		return -1;
	
	ev_io_set(&c->w, c->w.fd, events);
	ev_io_start(ev_default_loop(0), &c->w);
	
	return 0;
}

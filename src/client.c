#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <sys/errno.h>

#include <ev.h>

#include "fbuf.h"
#include "base.h"

#include "config.h"

#include "net.h"
#include "client.h"

enum client_state {
	CLIENT_HANDSHAKE = 0,
	PEER_HANDSHAKE = 1,
	DONE = 2
};

struct client
{
	enum client_state state;
	struct ev_io w;
	struct ev_io peer;
	struct ev_timer timer;
	struct fbuf buf;
	int can_read, peer_can_read;
	struct fbuf from_client_buf, from_peer_buf;
};

static void free_client(struct client *c);
static int set_watchers(struct client *c);
static int do_handshake(struct client *c);
static int handshake_ok(struct client *c, struct mcr_handshake_start *hs);

static void client_trampoline(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct client *c = w->data;
	ssize_t ret;
	(void)loop;
	assert((revents & ~(EV_READ | EV_WRITE)) == 0);
	
	switch (c->state) {
	case CLIENT_HANDSHAKE:
		assert((revents & ~(EV_READ)) == 0);
		ret = fbuf_read(&c->buf, w->fd, -1);
		if (ret < 0 && errno == EAGAIN)
			return;

		if (ret <= 0) {
			free_client(c);
			return;
		}

		if (do_handshake(c) < 0) {
			free_client(c);
			return;
		}
		
		break;
	
	case DONE:
		ev_timer_again(loop, &c->timer);
		
		if (revents & EV_READ) {
			ret = fbuf_read(&c->from_client_buf, c->w.fd, -1);
			
			if (ret < 0) {
				free_client(c);
				return;
			}
			
			if (ret == 0)
				c->can_read = 0;
		}
		
		if (revents & EV_WRITE) {
			ret = fbuf_write(&c->from_peer_buf, c->w.fd, -1);
			
			if (ret < 0) {
				free_client(c);
				return;
			}
			
			if (fbuf_avail(&c->from_peer_buf) == 0 && ! c->peer_can_read)
				shutdown(c->w.fd, SHUT_WR);
		}
		
		if (set_watchers(c) < 0) {
			free_client(c);
			return;
		}
		break;
	
	default:
		assert(0);
		free_client(c);
		return;
	}
}

static void peer_trampoline(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct client *c = w->data;
	ssize_t ret;
	(void)loop;
	assert((revents & ~(EV_READ | EV_WRITE)) == 0);
	
	switch (c->state) {
	case PEER_HANDSHAKE:
		assert((revents & ~(EV_WRITE)) == 0);
		if (fbuf_avail(&c->buf) == 0) {
			c->state = DONE;
			if (set_watchers(c) < 0) {
				free_client(c);
				return;
			}
			return;
		}
		
		if (fbuf_write(&c->buf, c->peer.fd, -1) < 0) {
			free_client(c);
			return;
		}
		break;
	
	case DONE:
		ev_timer_again(loop, &c->timer);
		
		if (revents & EV_READ) {
			ret = fbuf_read(&c->from_peer_buf, c->peer.fd, -1);
			
			if (ret < 0) {
				free_client(c);
				return;
			}
			
			if (ret == 0)
				c->peer_can_read = 0;
		}
		
		if (revents & EV_WRITE) {
			ret = fbuf_write(&c->from_client_buf, c->peer.fd, -1);
			
			if (ret < 0) {
				free_client(c);
				return;
			}
			
			if (fbuf_avail(&c->from_client_buf) == 0 && ! c->can_read)
				shutdown(c->peer.fd, SHUT_WR);
		}
		
		if (set_watchers(c) < 0) {
			free_client(c);
			return;
		}
		break;
	
	default:
		assert(0);
		free_client(c);
		return;
	}
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

static int do_handshake(struct client *c)
{
	union mcr_any hs;
	struct mcp_parse buf, frame;
	int id;
	
	mcp_start(&buf, fbuf_ptr(&c->buf), fbuf_avail(&c->buf));
	
	id = mc47_frame_parser(&buf, &frame);
	
	if (mcp_error(&buf) == MCP_EAGAIN)
		return 0;
	
	if (!mcp_ok(&buf))
		return -1;
	
	mcr_server_parse_handshake(&hs, id, &frame);
	
	if (!mcp_ok(&frame))
		return -1;
	
	return handshake_ok(c, &hs.handshake_start);
}

const char *map_host(const char *host)
{
	const char *target = table_lookup(g_map_table, host);
	
	if (target)
		return target;
	
	return table_lookup(g_map_table, "*");
}

static int handshake_ok(struct client *c, struct mcr_handshake_start *hs)
{
	char hostname[256];
	const char *target;
	
	if (hs->hostname_length >= sizeof(hostname))
		return -1;
	
	memcpy(hostname, hs->hostname, hs->hostname_length);
	hostname[hs->hostname_length] = 0;
	
	canonicalize_hostname(hostname);
	target = map_host(hostname);
	
	printf("%i query %s\n", c->w.fd, hostname);
	
	if (target == NULL)
		return -1;
	
	ev_io_set(&c->peer, connect_peer(target, DEAFULT_PEER_PORT), 0);
	if (c->peer.fd < 0)
		return -1;
	
	printf("%i => %s\n", c->w.fd, target);
	
	c->state = PEER_HANDSHAKE;
	if (set_watchers(c) < 0)
		free_client(c);
	
	return 0;
}

static void timer_trampoline(struct ev_loop *loop, struct ev_io *w, int revent)
{
	struct client *c = w->data;
	(void)loop;
	assert(revent == EV_TIMER);
	
	printf("%i timedout\n", c->w.fd);
	
	free_client(c);
}

static void free_client(struct client *c)
{
	assert(c);
	
	printf("%i closed\n", c->w.fd);
	
	fbuf_free(&c->buf);
	fbuf_free(&c->from_client_buf);
	fbuf_free(&c->from_peer_buf);
	
	ev_io_stop(ev_default_loop(0), &c->w);
	if (c->w.fd >= 0)
		close(c->w.fd);
	
	ev_io_stop(ev_default_loop(0), &c->peer);
	if (c->peer.fd >= 0)
		close(c->peer.fd);
	
	ev_timer_stop(ev_default_loop(0), &c->timer);
	
	free(c);
}

void sock_accepted(int fd, struct sockaddr *addr, socklen_t len)
{
	char name[64];
	struct client *c = malloc(sizeof(*c));
	
	if (!c) {
		printf("out of memory!");
		close(fd);
		return;
	}
	
	fbuf_init(&c->buf, MAX_HANDSHAKE);
	fbuf_init(&c->from_client_buf, SPLICE_SIZE);
	fbuf_init(&c->from_peer_buf, SPLICE_SIZE);
	
	c->can_read = 1;
	c->peer_can_read = 1;
	
	ev_io_init(&c->w, client_trampoline, fd, 0);
	ev_io_init(&c->peer, peer_trampoline, -1, 0);
	c->w.data = c;
	c->peer.data = c;
	
	ev_timer_init(&c->timer, timer_trampoline, HANDSHAKE_TIMEOUT, HANDSHAKE_TIMEOUT);
	c->timer.data = c;
	ev_timer_start(ev_default_loop(0), &c->timer);
	
	c->state = CLIENT_HANDSHAKE;
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
	int events;
	ev_io_stop(ev_default_loop(0), &c->w);
	ev_io_stop(ev_default_loop(0), &c->peer);
	
	switch (c->state) {
	case CLIENT_HANDSHAKE:
		ev_io_set(&c->w, c->w.fd, EV_READ);
		ev_io_start(ev_default_loop(0), &c->w);
		break;
	
	case PEER_HANDSHAKE:
		ev_io_set(&c->peer, c->peer.fd, EV_WRITE);
		ev_io_start(ev_default_loop(0), &c->peer);
		break;
	
	case DONE:
		if (!c->can_read && !c->peer_can_read && fbuf_avail(&c->from_peer_buf) == 0 && fbuf_avail(&c->from_client_buf) == 0)
			return -1;
		
		events = 0;
		fbuf_expand(&c->from_client_buf, 1);
		if (c->can_read && fbuf_wavail(&c->from_client_buf) > 0)
			events |= EV_READ;
		if (fbuf_avail(&c->from_peer_buf) > 0)
			events |= EV_WRITE;
		ev_io_set(&c->w, c->w.fd, events);
		
		events = 0;
		fbuf_expand(&c->from_peer_buf, 1);
		if (c->peer_can_read && fbuf_wavail(&c->from_peer_buf) > 0)
			events |= EV_READ;
		if (fbuf_avail(&c->from_client_buf) > 0)
			events |= EV_WRITE;
		ev_io_set(&c->peer, c->peer.fd, events);
		
		ev_io_start(ev_default_loop(0), &c->w);
		ev_io_start(ev_default_loop(0), &c->peer);
		break;
	
	default:
		assert(0);
		return -1;
	}
	
	return 0;
}

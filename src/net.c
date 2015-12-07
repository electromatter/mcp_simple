#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "config.h"
#include "net.h"

int format_addr(char *dest, struct sockaddr *addr, socklen_t len)
{
	char ip[32];
	struct sockaddr_in *sin = (void*)addr;
	
	if (len < sizeof(*sin))
		return -1;
	
	if (sin->sin_family != AF_INET)
		return -1;
	
	if (!inet_ntop(sin->sin_family, &sin->sin_addr, ip, sizeof(ip)))
		return -1;
	
	sprintf(dest, "%s:%i", ip, ntohs(sin->sin_port));
	
	return 0;
}

int parse_addr(const char *name, int default_port, struct sockaddr *addr, socklen_t *len)
{
	char ip[32] = "";
	char *end;
	int i;
	long port;
	struct sockaddr_in *sin = (void*)addr;
	
	if (*len < sizeof(*sin))
		return -1;
	
	if (name == NULL) {
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(INADDR_ANY);
		sin->sin_port = htons(default_port);
		return 0;
	}
	
	for (i = 0; *name && *name != ':'; name++)
		ip[i++] = *name;
	ip[i++] = 0;
	
	if (*name == ':')
		name++;
	
	port = strtol(name, &end, 10);
	
	while (*name)
		name++;
	
	if (errno == ERANGE || port < 0 || port > 65535)
		return -1;
	
	if (end != name)
		return -1;
	
	if (port == 0)
		port = default_port;
	
	if (ip[0] == 0) {
		sin->sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		if (inet_pton(AF_INET, ip, &sin->sin_addr) <= 0)
			return -1;
	}
	
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	
	return 0;
}

int create_listener(const char *addr, int default_port)
{
	struct sockaddr saddr;
	socklen_t len = sizeof(saddr);
	int fd;
	const int one = 1;
	
	if (parse_addr(addr, default_port, &saddr, &len) < 0)
		return -1;
	
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -1;
	
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
		close(fd);
		return -1;
	}
	
	if (bind(fd, (void*)&saddr, sizeof(saddr)) < 0) {
		close(fd);
		return -1;
	}
	
	if (listen(fd, SOMAXCONN) < 0) {
		close(fd);
		return -1;
	}
	
	return fd;
}

int connect_peer(const char *addr, int default_port)
{
	struct sockaddr saddr;
	const int one = 1;
	socklen_t len = sizeof(saddr);
	int fd;
	
	if (parse_addr(addr, default_port, &saddr, &len) < 0)
		return -1;
	
	fd = socket(saddr.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -1;
	
	if (connect(fd, &saddr, len) < 0 && errno != EINPROGRESS) {
		close(fd);
		return -1;
	}
	
	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
		close(fd);
		return -1;
	}
	
	return fd;
}

int accept_connect(int from_fd, struct sockaddr *addr, socklen_t *len)
{
	const int one = 1;
	struct sockaddr saddr;
	socklen_t slen = sizeof(saddr);
	int fd;
	
	if (addr == NULL) {
		addr = &saddr;
		len = &slen;
	}
	
	fd = accept4(from_fd, addr, len, SOCK_NONBLOCK);
	if (fd < 0)
		return -1;
	
	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
		close(fd);
		return -1;
	}
	
	return fd;
}

static inline size_t fbuf_max_wavail(struct fbuf *buf)
{
	return buf->max_size - fbuf_avail(buf);
}

ssize_t fbuf_read(struct fbuf *buf, int fd, ssize_t size)
{
	void *ptr = NULL;
	ssize_t ret;
	
	if (size < 0 || fbuf_max_wavail(buf) < (size_t)size)
		size = fbuf_max_wavail(buf);

	while (ptr == NULL) {
		if (size == 0)
			return 0;
	
		ptr = fbuf_wptr(buf, size);
		
		if (ptr == NULL)
			size = fbuf_wavail(buf);
	}
	
	ret = read(fd, ptr, size);
	if (ret <= 0)
		return ret;
	
	fbuf_produce(buf, ret);
	return ret;
}

ssize_t fbuf_write(struct fbuf *buf, int fd, ssize_t size)
{
	ssize_t ret;
	
	if (size < 0 || (size_t)size < fbuf_avail(buf))
		size = fbuf_avail(buf);
	
	if (size == 0)
		return 0;
	
	ret = write(fd, fbuf_ptr(buf), size);
	if (ret <= 0)
		return ret;
	
	fbuf_consume(buf, ret);
	return ret;
}

void canonicalize_hostname(char *str)
{
	for (; *str; str++)
		*str = tolower(*str);
}

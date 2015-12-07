#ifndef NET_H
#define NET_H

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "fbuf.h"

int format_addr(char *dest, struct sockaddr *addr, socklen_t len);
int parse_addr(const char *name, int default_port, struct sockaddr *addr, socklen_t *len);
int create_listener(const char *addr, int default_port);
int connect_peer(const char *addr, int default_port);
int accept_connect(int from_fd, struct sockaddr *addr, socklen_t *len);
ssize_t fbuf_read(struct fbuf *buf, int fd, ssize_t size);
ssize_t fbuf_write(struct fbuf *buf, int fd, ssize_t size);

void canonicalize_hostname(char *str);

#endif

#ifndef CLIENT_H
#define CLIENT_H

#include "table.h"
#include "net.h"

struct table *g_map_table;

void sock_accepted(int fd, struct sockaddr *addr, socklen_t len);

#endif

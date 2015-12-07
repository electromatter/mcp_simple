#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <ev.h>

#include "config.h"

#include "net.h"
#include "table.h"
#include "client.h"

static void reload_table(void);

struct table *g_map_table = NULL;

static void accept_trampoline(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct sockaddr addr;
	socklen_t len = sizeof(addr);
	int fd;
	assert(revents == EV_READ);
	(void)loop;
	
	fd = accept_connect(w->fd, &addr, &len);
	if (fd < 0)
		return;
	
	sock_accepted(fd, &addr, len);
}

static void signal_trampoline(struct ev_loop *loop, struct ev_signal *w, int revents)
{
	(void)loop; (void)w; (void)revents;
	assert(revents == EV_SIGNAL);
	reload_table();
}

static void reload_table(void)
{
	char *path = getenv("MCP_TABLE_FILE");
	struct table *new_table;
	
	if (path == NULL)
		path = MCP_TABLE_FILE;
	
	new_table = load_table(path);
	
	if (new_table == NULL) {
		printf("-1 failed to load table (%s)\n", path);
		return;
	}
	
	free_table(g_map_table);
	g_map_table = new_table;
	
	printf("-1 table loaded (%s)\n", path);
}

int main(int argc, char **argv)
{
	int fd;
	struct ev_io iow;
	struct ev_signal sw;
	
	(void)argc; (void)argv;
	
	fd = create_listener(NULL, 25565);
	if (fd < 0) {
		perror("-1 failed to listen");
		return 1;
	}
	
	reload_table();
	
	ev_io_init(&iow, accept_trampoline, fd, EV_READ);
	ev_io_start(ev_default_loop(0), &iow);
	
	ev_signal_init(&sw, signal_trampoline, SIGUSR1);
	ev_signal_start(ev_default_loop(0), &sw);
	
	signal(SIGPIPE, SIG_IGN);
	
	ev_run(ev_default_loop(0), 0);
	
	return 0;
}

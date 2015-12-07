#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <ev.h>

#include "../src/config.h"

#include "../src/net.h"
#include "../src/table.h"

void sock_accepted(int fd, struct sockaddr *addr, socklen_t len);
static void reload_motd(void);

char *g_motd = NULL;

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
	reload_motd();
}

static void reload_motd(void)
{
	char *path = getenv("MCP_MOTD_FILE");
	char *new_motd;
	
	if (path == NULL)
		path = MCP_MOTD_FILE;
	
	new_motd = load_file(path);
	
	if (new_motd == NULL) {
		printf("-1 failed to motd (%s)\n", path);
		return;
	}
	
	free(g_motd);
	g_motd = new_motd;
	
	printf("-1 motd loaded (%s)\n", path);
}

int main(int argc, char **argv)
{
	int fd;
	struct ev_io iow;
	struct ev_signal sw;
	
	(void)argc; (void)argv;
	
	fd = create_listener(getenv("MCP_LISTENER"), 25565);
	if (fd < 0) {
		perror("-1 failed to listen");
		return 1;
	}
	
	g_motd = NULL;
	
	reload_motd();
	
	ev_io_init(&iow, accept_trampoline, fd, EV_READ);
	ev_io_start(ev_default_loop(0), &iow);
	
	ev_signal_init(&sw, signal_trampoline, SIGUSR1);
	ev_signal_start(ev_default_loop(0), &sw);
	
	signal(SIGPIPE, SIG_IGN);
	
	ev_run(ev_default_loop(0), 0);
	
	return 0;
}

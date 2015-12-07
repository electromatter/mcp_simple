#ifndef CONFIG_H
#define CONFIG_H

/* main config */
#define LISTEN_ADDRESS			NULL
#define DEFAULT_LISTEN_PORT		(25565)
#define MCP_TABLE_FILE			"/etc/mcp_map"

/* hash table config */
#define DEFAULT_TABLE_SIZE		(1024)
#define LOAD_FACTOR				(0.7)
#define EXPAND_FACTOR			(2)

/* client config */
#define MAX_HANDSHAKE		(1024)
#define SPLICE_SIZE			(65535)
#define	HANDSHAKE_TIMEOUT	(30)
#define DEAFULT_PEER_PORT	(25565)

#endif

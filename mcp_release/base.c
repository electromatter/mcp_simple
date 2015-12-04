/* mcp_release/base.c
 *
 * Copyright (c) 2015 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "base.h"

/* Server */
void mcr_server_parse(union mcr_any *dest, enum mcr_mode mode, enum mcr_id id, struct mcp_parse *src)
{
	if (!mcp_ok(src))
		return;
	
	switch (mode) {
	case MCR_HANDSHAKE:
		mcr_server_parse_handshake(dest, id, src);
		return;
	case MCR_STATUS:
		mcr_server_parse_status(dest, id, src);
		return;
	case MCR_LOGIN:
		mcr_server_parse_login(dest, id, src);
		return;
	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcr_server_pack(struct fbuf *dest, enum mcr_mode mode, const union mcr_any *src)
{
	switch (mode) {
	case MCR_STATUS:
		return mcr_server_pack_status(dest, src);
	case MCR_LOGIN:
		return mcr_server_pack_login(dest, src);
	default:
		return 1;
	}
}

/* Client*/
void mcr_client_parse(union mcr_any *dest, enum mcr_mode mode, enum mcr_id id, struct mcp_parse *src)
{
	if (!mcp_ok(src))
		return;
	
	switch (mode) {
	case MCR_STATUS:
		mcr_client_parse_status(dest, id, src);
		return;
	case MCR_LOGIN:
		mcr_client_parse_login(dest, id, src);
		return;
	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcr_client_pack(struct fbuf *dest, enum mcr_mode mode, const union mcr_any *src)
{
	switch (mode) {
	case MCR_HANDSHAKE:
		return mcr_client_pack_hanshake(dest, src);
	case MCR_STATUS:
		return mcr_client_pack_status(dest, src);
	case MCR_LOGIN:
		return mcr_client_pack_login(dest, src);
	default:
		return 1;
	}
}

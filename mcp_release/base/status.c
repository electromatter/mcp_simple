/* mcp_release/base/status.c
 *
 * Copyright (c) 2015 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "../base.h"

#include <assert.h>

void mcr_server_parse_status(union mcr_any *dest, enum mcr_id id, struct mcp_parse *src)
{
	/* pass errors */
	if (!mcp_ok(src))
		return;

	dest->id = id;
	switch (id) {
	case MCR_STATUS_REQUEST:
		return;

	case MCR_STATUS_PING:
		dest->status_ping.time = mcp_ulong(src);
		return;

	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcr_server_pack_status(struct fbuf *dest, const union mcr_any *src)
{
	int err = 0;

	switch (src->id) {
	case MCR_STATUS_RESPONSE:
		err |= mcg_bytes(dest, src->status_response.motd, src->status_response.motd_length);
		return err;

	case MCR_STATUS_PING:
		err |= mcg_ulong(dest, src->status_ping.time);
		return err;

	default:
		assert(0 && "Invalid packet id");
		return 1;
	}
}

void mcr_client_parse_status(union mcr_any *dest, enum mcr_id id, struct mcp_parse *src)
{
	/* pass errors */
	if (!mcp_ok(src))
		return;

	dest->id = id;
	switch (id) {
	case MCR_STATUS_RESPONSE:
		dest->status_response.motd = mcp_bytes(src,
				&dest->status_response.motd_length);
		return;

	case MCR_STATUS_PING:
		dest->status_ping.time = mcp_ulong(src);
		return;

	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcr_client_pack_status(struct fbuf *dest, const union mcr_any *src)
{
	int err = 0;
	switch (src->id) {
	case MCR_STATUS_REQUEST:
		return err;

	case MCR_STATUS_PING:
		err |= mcg_ulong(dest, src->status_ping.time);
		return err;

	default:
		assert(0 && "Invalid packet id");
		return 1;
	}
}

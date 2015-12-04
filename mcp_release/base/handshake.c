/* mcp_release/base/handshake.c
 *
 * Copyright (c) 2015 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "../base.h"

#include <assert.h>

void mcr_server_parse_handshake(union mcr_any *dest, enum mcr_id id, struct mcp_parse *src)
{
	/* pass errors */
	if (!mcp_ok(src))
		return;

	dest->id = id;
	switch (id) {
	case MCR_HANDSHAKE_START:
		dest->handshake_start.version = mcp_varint(src);
		dest->handshake_start.hostname = mcp_bytes(src,
				&dest->handshake_start.hostname_length);
		dest->handshake_start.port = mcp_ushort(src);
		dest->handshake_start.next_state = mcp_varint(src);
		return;

	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcr_client_pack_hanshake(struct fbuf *dest, const union mcr_any *src)
{
	int err = 0;
	switch (src->id) {
	case MCR_HANDSHAKE_START:
		err |= mcg_varint(dest, src->handshake_start.version);
		err |= mcg_bytes(dest, src->handshake_start.hostname,
				src->handshake_start.hostname_length);
		err |= mcg_ushort(dest, src->handshake_start.port);
		err |= mcg_varint(dest, src->handshake_start.next_state);
		return err;

	default:
		assert(0 && "Invalid packet id");
		return 1;
	}
}


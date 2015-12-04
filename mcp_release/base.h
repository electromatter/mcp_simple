/* mcp_release/base.h
 *
 * Copyright (c) 2015 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#ifndef MCP_RELEASE_BASE_H
#define MCP_RELEASE_BASE_H

#include "mcp.h"

enum mcr_mode {
	MCR_HANDSHAKE				= 0,
	MCR_STATUS					= 1,
	MCR_LOGIN					= 2,
};

enum mcr_id {
	/* Handshake server-bound */
	MCR_HANDSHAKE_START		= 0x00,

	/* Status server-bound */
	MCR_STATUS_REQUEST			= 0x00,

	/* Status client-bound */
	MCR_STATUS_RESPONSE		= 0x00,

	/* Status bidirectional */
	MCR_STATUS_PING			= 0x01,

	/* Login server-bound */
	MCR_LOGIN_START			= 0x00,
	MCR_LOGIN_RESPONSE			= 0x01,
	/* Login client-bound */
	MCR_LOGIN_DISCONNECT		= 0x00,
	MCR_LOGIN_REQUEST			= 0x01,
	MCR_LOGIN_SUCCESS			= 0x02,
	MCR_LOGIN_SET_COMPRESSION	= 0x03
};

/* Handshake server-bound */
struct mcr_handshake_start {
	enum mcr_id id;
	mcp_varint_t version;
	size_t hostname_length;
	const char *hostname;
	uint16_t port;
	mcp_varint_t next_state;
};

/* Status client-bound */
struct mcr_status_response {
	enum mcr_id id;
	size_t motd_length;
	const char *motd;
};

/* Status bidirectional */
struct mcr_status_ping {
	enum mcr_id id;
	uint64_t time;
};

/* Login server-bound */
struct mcr_login_start {
	enum mcr_id id;
	size_t name_length;
	const char *name;
};

struct mcr_login_response {
	enum mcr_id id;
	size_t shared_length;
	const void *shared;
	size_t verify_length;
	const void *verify;
};

/* Login client-bound */
struct mcr_login_disconnect {
	enum mcr_id id;
	size_t reason_length;
	const char *reason;
};

struct mcr_login_request {
	enum mcr_id id;
	size_t serverid_length;
	const char *serverid;
	size_t pubkey_length;
	const void *pubkey;
	size_t verify_length;
	const void *verify;
};

struct mcr_login_success {
	enum mcr_id id;
	size_t uuid_length;
	const char *uuid;
	size_t name_length;
	const char *name;
};

struct mcr_login_set_compression {
	enum mcr_id id;
	mcp_varint_t threshold;
};

/* Polymorphic types */
union mcr_any {
	enum mcr_id id;
	struct mcr_handshake_start handshake_start;
	struct mcr_status_response status_response;
	struct mcr_status_ping status_ping;
	struct mcr_login_start login_start;
	struct mcr_login_response login_response;
	struct mcr_login_disconnect login_disconnect;
	struct mcr_login_request login_request;
	struct mcr_login_success login_success;
	struct mcr_login_set_compression login_set_compression;
};

/* -*- DIRECT INTERFACE -*- */
void mcr_server_parse_handshake(union mcr_any *dest, enum mcr_id id, struct mcp_parse *src);

void mcr_server_parse_status(union mcr_any *dest, enum mcr_id id, struct mcp_parse *src);
int mcr_server_pack_status(struct fbuf *dest, const union mcr_any *src);

void mcr_server_parse_login(union mcr_any *dest, enum mcr_id id, struct mcp_parse *src);
int mcr_server_pack_login(struct fbuf *dest, const union mcr_any *src);

int mcr_client_pack_hanshake(struct fbuf *dest, const union mcr_any *src);

void mcr_client_parse_status(union mcr_any *dest, enum mcr_id id, struct mcp_parse *src);
int mcr_client_pack_status(struct fbuf *dest, const union mcr_any *src);

void mcr_client_parse_login(union mcr_any *dest,	enum mcr_id id, struct mcp_parse *src);
int mcr_client_pack_login(struct fbuf *dest, const union mcr_any *src);

/* -*- PUBLIC INTERFACE -*- */
void mcr_server_parse(union mcr_any *dest, enum mcr_mode mode, enum mcr_id id, struct mcp_parse *src);
int mcr_server_pack(struct fbuf *dest, enum mcr_mode mode, const union mcr_any *src);

void mcr_client_parse(union mcr_any *dest, enum mcr_mode mode, enum mcr_id id, struct mcp_parse *src);
int mcr_client_pack(struct fbuf *dest, enum mcr_mode mode, const union mcr_any *src);

#endif

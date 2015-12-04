project(mcp_release)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "-std=c99 -Wall -Wextra -pedantic")

add_library(mcp_release_base base.c base/handshake.c
		base/login.c base/status.c)

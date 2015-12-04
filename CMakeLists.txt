project(mcp)
cmake_minimum_required(VERSION 2.8)

enable_testing()

include_directories(mcp_base/ mcp_modern/ mcp_net/)

add_subdirectory(mcp_base/)
add_subdirectory(mcp_release)
add_subdirectory(mcp_extra/)


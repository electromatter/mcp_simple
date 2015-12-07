project(mcp)
cmake_minimum_required(VERSION 2.8)

enable_testing()

include_directories(mcp_base/ mcp_release/)

add_subdirectory(mcp_base/)
add_subdirectory(mcp_release)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/)
find_package(EV REQUIRED)

set(CMAKE_C_FLAGS "-Wall -Wextra -pedantic -std=c99")

add_executable(mcp_simple src/main.c src/table.c src/client.c src/net.c)
target_link_libraries(mcp_simple mcp_release_base mcp_base ${EV_LIBRARY})

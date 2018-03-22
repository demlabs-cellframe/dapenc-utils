project(dapenc-utils C)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)
set (CMAKE_CXX_STANDARD 11)

#set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /opt/local/lib)
#set(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} /opt/local/include)
add_subdirectory(libdap)

include_directories("${INCLUDE_DIRECTORIES} ${dap_core_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_crypto_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${monero_crypto_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap-chain_INCLUDE_DIRS}")
add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_crypto_DEFINITIONS}")
add_definitions ("${monero_crypto_DEFINITIONS}")
add_definitions ("${dap-chain_DEFINITIONS}")


#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ")
add_executable(${PROJECT_NAME} "sources/dapenc-utils.c" )
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap-chain monero_crypto m pthread)


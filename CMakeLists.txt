project(dapenc-utils C)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)
set (CMAKE_CXX_STANDARD 11)

#set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /opt/local/lib)
#set(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} /opt/local/include)
add_subdirectory(libdap)

include_directories("${INCLUDE_DIRECTORIES} ${libdap_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_core_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_crypto_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${monero_crypto_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap-chain_INCLUDE_DIRS}")

add_definitions ("${libdap_DEFINITIONS}")
add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_crypto_DEFINITIONS}")
add_definitions ("${monero_crypto_DEFINITIONS}")
add_definitions ("${dap-chain_DEFINITIONS}")


#add_library(${PROJECT_NAME} STATIC IMPORTED libdap.c )

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ")
#add_executable(${PROJECT_NAME} "sources/dapenc-utils.c" )
add_library(${PROJECT_NAME} "sources/dapenc-utils.c" )
#target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap-chain monero_crypto m pthread)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)

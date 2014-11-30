cmake_minimum_required(VERSION 2.8.9)

project(avim_bot)

##############################################
#  OPTION
##############################################
option(PROTO_ENABLE "enable proto test" OFF)
option(SOCI_ENABLE "soci-postgresql test" OFF)
option(OPENSSL_ENABLE "openssl test" OFF)

##############################################
#  ENV
##############################################

find_package(Boost 1.54 COMPONENTS program_options filesystem system thread regex REQUIRED)

####proto
if(PROTO_ENABLE)
find_package(Protobuf REQUIRED)
add_definitions(-DENABLE_PROTO_TEST)
include_directories(${PROTOBUF_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/avim_proto)
endif()

#### SOCI-POSTGRESQL
if(SOCI_ENABLE)
find_package(PostgreSQL REQUIRED)
find_library(SOCI_LIBRARY NAMES soci_core HINTS /usr/local/lib /usr/local/lib64 /usr/lib64 /usr/lib /usr/local/lib /usr/lib/soci/lib)
find_library(SOCI_PG_LIBRARY NAMES soci_postgresql HINTS /usr/local/lib /usr/local/lib64 /usr/lib64 /usr/lib /usr/lib/soci/lib)
if(NOT SOCI_LIBRARY)
message(FATAL_ERROR "SOCI library NOT FOUND!" )
endif()
if(NOT SOCI_PG_LIBRARY)
message(FATAL_ERROR "SOCI do not have postgresql backend!" )
endif()
include_directories(${PostgreSQL_INCLUDE_DIRS})
find_path( SOCI_INCLUDE_DIRS connection-pool.h PATHS /usr/include/soci /usr/local/include/soci /opt/soci/include/soci)
include_directories(${SOCI_INCLUDE_DIRS})
link_libraries(${SOCI_LIBRARY} ${SOCI_PG_LIBRARY} ${PostgreSQL_LIBRARIES})
add_definitions(-DENABLE_SOCI_TEST)
endif()

#### OPENSSL
if(OPENSSL_ENABLE)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_libraries(${OPENSSL_LIBRARIES})
add_definitions(-DENABLE_OPENSSL_TEST)
endif()

#local include
include_directories(include)
#boost include
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y")
include_directories(${Boost_INCLUDE_DIRS})
link_libraries(${Boost_LIBRARIES})

##############################################
#  TARGET
##############################################
if(PROTO_ENABLE)
add_subdirectory(avim_proto_doc)
endif()

add_subdirectory(src bin)


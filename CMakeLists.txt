cmake_minimum_required(VERSION 2.8.11)

project(avim)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
	set(CMAKE_COMPILER_IS_CLANGXX 1)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
	if(UNIX)
		set(CMAKE_COMPILER_IS_UNIX_ICC 1)
	else()
		# CMAKE_COMPILER_IS_WIN_ICC 的 c++11 模式命令行参数不一样
		set(CMAKE_COMPILER_IS_WIN_ICC 1)
	endif()
endif()

if(MSVC)
	add_definitions(-DNOMINMAX)
    add_definitions("/wd4819")
	set(Boost_USE_MULTITHREADED TRUE)
	set(Boost_USE_STATIC_LIBS TRUE)

	if(NOT DEFINED PROTOBUF_SRC_ROOT_FOLDER)
		if(DEFINED ENV{PROTOBUF_SRC_ROOT_FOLDER})
			set(PROTOBUF_SRC_ROOT_FOLDER $ENV{PROTOBUF_SRC_ROOT_FOLDER})
		else()
			set(PROTOBUF_SRC_ROOT_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/third_party/protobuf-2.6.1/)

			if( NOT EXISTS third_party/protobuf-2.6.1/Debug)
				message(FATAL_ERROR "please compile protobuf in VC -- open and press F7")
			endif()
		endif()
	endif()
endif()

option(RUN_PROTOC "run protoc to generate protobuf protocol parser" ON)
option(BUILD_C_WRAPPER "build a libavproto that exports C interface" OFF)
option(BUILD_GUI "build gui" OFF)

find_package(Threads REQUIRED)
find_package(Boost 1.54 REQUIRED COMPONENTS thread system program_options coroutine context regex date_time chrono filesystem )
find_package(Protobuf REQUIRED)
find_package(OpenSSL REQUIRED)
check_library_exists(rt clock_gettime "" HAVE_CLOCK_GETTIME)
if(HAVE_CLOCK_GETTIME)
        link_libraries(-lrt)
endif(HAVE_CLOCK_GETTIME)

add_subdirectory(avim)

add_subdirectory(src)

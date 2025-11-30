# CMake configuration
cmake_minimum_required(VERSION 3.5.2)

# Project information
project(yara-l 
    VERSION 0.0.1 
    LANGUAGES CXX
)

# Build settings
set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries")

# Threading support
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_PTHREADS_INIT 2)

# External dependencies
include(cmake/lua_library.cmake)
add_subdirectory(libraries/sol2 ${CMAKE_BINARY_DIR}/libraries/sol2)
add_subdirectory(libraries/fmt ${CMAKE_BINARY_DIR}/libraries/fmt)


# Add project sources
add_subdirectory(sources)

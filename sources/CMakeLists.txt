cmake_minimum_required(VERSION 3.16)
project(yaral VERSION 0.0.1 LANGUAGES CXX)

# Global settings
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build options
option(FLAGS_OPTIMIZATIONS "Enable compiler optimizations" ON)

# Library versioning
set(LIB_SOVERSION 0)

# Include external configuration (e.g., dependencies)
include(../include/CMakeLists.txt)

# Dependencies list (shared between lib and executable if needed)
set(YARAL_DEPEN
    liblua
    yara
    sol2
    fmt
)

# === Source files ===
file(GLOB_RECURSE YARA_L
    sources/*.cxx
    sources/yara/*.cxx
    sources/lua/*.cxx
    *.cxx
)

# === Build Shared Library ===
add_library(yaral SHARED ${YARA_L})

set_target_properties(yaral PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${LIB_SOVERSION}
    OUTPUT_NAME yaral
)
target_link_libraries(yaral PUBLIC ${YARAL_DEPEN})
set_target_properties(yaral PROPERTIES PREFIX "")
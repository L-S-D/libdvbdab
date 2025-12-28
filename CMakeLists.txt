cmake_minimum_required(VERSION 3.20)

project(libdvbdab VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include directories for the library structure
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Find required dependencies
find_package(PkgConfig REQUIRED)
find_package(ZLIB REQUIRED)
pkg_check_modules(LIBAV REQUIRED libavformat libavcodec libavutil)
pkg_check_modules(FDKAAC REQUIRED fdk-aac)

# ============================================================================
# Main libdvbdab static library
# ============================================================================
add_library(dvbdab STATIC
    src/parsers/gse_parser.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/parsers/eti_na_detector.cpp
    src/sources/gse_ts_source.cpp
    src/sources/bbf_ts_source.cpp
    src/sources/mpe_ts_source.cpp
    src/ensemble_manager.cpp
    src/dab_parser.cpp
    src/discover.cpp
    src/output/ts_muxer.cpp
    src/output/ts_packetizer.cpp
    src/output/ts_streamer.cpp
    src/output/dabplus_decoder.cpp
    src/output/dab_mp2_decoder.cpp
    src/output/pad_decoder.cpp
    src/output/ffmpeg_ts_muxer.cpp
    src/ts_scanner.cpp
    src/dvbdab_c.cpp
    src/etina_pipeline.cpp
)

target_include_directories(dvbdab PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBAV_INCLUDE_DIRS}
    ${FDKAAC_INCLUDE_DIRS}
)

target_link_libraries(dvbdab
    pthread
    ZLIB::ZLIB
    ${LIBAV_LIBRARIES}
    ${LIBAV_LDFLAGS}
    ${FDKAAC_LIBRARIES}
)

target_link_directories(dvbdab PUBLIC
    ${LIBAV_LIBRARY_DIRS}
    ${FDKAAC_LIBRARY_DIRS}
)

# Export library for use by parent projects
set_target_properties(dvbdab PROPERTIES
    PUBLIC_HEADER "include/dvbdab/dvbdab.hpp;include/dvbdab/dvbdab_c.h;include/dvbdab/ts_scanner.hpp;include/dvbdab/input_source.hpp"
)

# Installation rules
install(TARGETS dvbdab
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/dvbdab
)

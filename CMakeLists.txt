cmake_minimum_required(VERSION 3.20)

# Only set compiler if this is the top-level project
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_C_COMPILER /usr/local/gcc-15/bin/gcc)
    set(CMAKE_CXX_COMPILER /usr/local/gcc-15/bin/g++)
endif()

project(libdvbdab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include directories for the new library structure
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Find required libraries
find_package(PkgConfig REQUIRED)
pkg_check_modules(PUGIXML REQUIRED pugixml)

# ============================================================================
# Main libdvbdab static library
# ============================================================================
add_library(dvbdab STATIC
    src/parsers/gse_parser.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/parsers/packet_decoder.cpp
    src/parsers/spi_parser.cpp
    src/parsers/ehb_parser.cpp
    src/parsers/pf_reassembler.cpp
    src/parsers/mpe_section_accumulator.cpp
    src/sources/gse_ts_source.cpp
    src/sources/bbf_ts_source.cpp
    src/sources/mpe_ts_source.cpp
    src/ensemble_manager.cpp
    src/dab_parser.cpp
    src/dab_stream_parser.cpp
    src/discover.cpp
    src/logging.cpp
    src/output/ts_streamer.cpp
    src/output/dabplus_decoder.cpp
    src/output/dab_mp2_decoder.cpp
    src/output/pad_decoder.cpp
    src/output/ts_muxer.cpp
    src/output/dab_stream_processor.cpp
    src/ts_scanner.cpp
    src/dvbdab_c.cpp
    src/etina_pipeline.cpp
)
target_include_directories(dvbdab PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PUGIXML_INCLUDE_DIRS}
)
find_package(ZLIB REQUIRED)
target_link_libraries(dvbdab pthread ZLIB::ZLIB ${PUGIXML_LIBRARIES})
target_link_directories(dvbdab PUBLIC ${PUGIXML_LIBRARY_DIRS})

# ============================================================================
# Standalone tools (only build when this is the top-level project)
# ============================================================================
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)

# pts2bbf - extracts BBF from pseudo TS
add_executable(pts2bbf src/pts2bbf.cpp)

# bbf2udp_test - extracts UDP packets from BBF and shows stream summary
add_executable(bbf2udp_test
    src/bbf2udp_test.cpp
    src/bbf2udp.cpp
    src/udp2edi.cpp
    src/edi_parser.cpp
)

# complete_test - full pipeline from TS to service labels with completeness
add_executable(complete_test
    src/complete_test.cpp
    src/bbf2udp.cpp
    src/udp2edi.cpp
    src/edi_parser.cpp
)

# New library parsers
add_library(dvbdab_parsers STATIC
    src/parsers/gse_parser.cpp
    src/parsers/udp_extractor.cpp
)

# Test GSE parser with live_gse_capture.bin
add_executable(test_gse_parser
    tests/test_gse_parser.cpp
    src/sources/gse_ts_source.cpp
    src/parsers/gse_parser.cpp
    src/parsers/udp_extractor.cpp
)

# Test BBF parser with nrk_gse_capture.ts
add_executable(test_bbf_parser
    tests/test_bbf_parser.cpp
    src/sources/bbf_ts_source.cpp
    src/parsers/gse_parser.cpp
    src/parsers/udp_extractor.cpp
)

# Test MPE parser with astra1-wdr.ts
add_executable(test_mpe_parser
    tests/test_mpe_parser.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
)

# Test ensemble discovery (full pipeline)
add_executable(test_ensemble_discovery
    tests/test_ensemble_discovery.cpp
    src/sources/gse_ts_source.cpp
    src/sources/bbf_ts_source.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/gse_parser.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/parsers/pf_reassembler.cpp
    src/parsers/mpe_section_accumulator.cpp
    src/ensemble_manager.cpp
    src/dab_parser.cpp
    src/dab_stream_parser.cpp
    src/logging.cpp
)

# Test DabStreamProcessor (full pipeline)
add_executable(test_stream_processor
    tests/test_stream_processor.cpp
    src/output/ts_muxer.cpp
    src/output/dab_stream_processor.cpp
    src/output/dabplus_decoder.cpp
    src/output/dab_mp2_decoder.cpp
    src/output/pad_decoder.cpp
    src/sources/gse_ts_source.cpp
    src/sources/bbf_ts_source.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/gse_parser.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/parsers/packet_decoder.cpp
    src/parsers/ehb_parser.cpp
    src/parsers/pf_reassembler.cpp
    src/parsers/mpe_section_accumulator.cpp
    src/ensemble_manager.cpp
    src/dab_parser.cpp
    src/dab_stream_parser.cpp
    src/logging.cpp
)
target_link_libraries(test_stream_processor ZLIB::ZLIB)

# Test packet mode extraction (EPG/data services)
add_executable(test_packet_mode
    tests/test_packet_mode.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/parsers/packet_decoder.cpp
    src/parsers/pf_reassembler.cpp
    src/parsers/mpe_section_accumulator.cpp
    src/ensemble_manager.cpp
    src/dab_parser.cpp
    src/dab_stream_parser.cpp
    src/logging.cpp
)
target_link_libraries(test_packet_mode ZLIB::ZLIB)

# Test FCT gap analysis - standalone (exact copy from check_fct_direct.cpp)
add_executable(test_fct_gaps
    tests/test_fct_gaps.cpp
)

# Test library MpeTsSource produces same results as standalone
add_executable(test_library_mpe
    tests/test_library_mpe.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
)

# Test full library pipeline: MpeTsSource → UdpExtractor → EdiParser → ETI frames
add_executable(test_eti_output
    tests/test_eti_output.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/edi_parser.cpp
)

# Test superframe sync detection and firecode verification
add_executable(test_superframe_sync
    tests/test_superframe_sync.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/edi_parser.cpp
)

# Test audio extraction from DAB/DAB+ subchannels
add_executable(test_audio_extract
    tests/test_audio_extract.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/edi_parser.cpp
    src/output/dabplus_decoder.cpp
    src/output/pad_decoder.cpp
    src/output/dab_mp2_decoder.cpp
    src/logging.cpp
)
target_link_libraries(test_audio_extract ZLIB::ZLIB)

# Detect subchannel type (DAB+ vs DAB/MP2 vs DATA)
add_executable(test_subch_type
    tests/test_subch_type.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/edi_parser.cpp
)

# Test discoverEnsembles library function
add_executable(test_discover
    tests/test_discover.cpp
)
target_link_libraries(test_discover dvbdab)

# Test TsScanner - auto-detect DAB ensembles from raw TS
add_executable(test_ts_scanner
    tests/test_ts_scanner.cpp
)
target_link_libraries(test_ts_scanner dvbdab)

# Test ETI-NA pipeline - modular E1 to ETI-NI conversion
add_executable(test_etina_pipeline
    tests/test_etina_pipeline.cpp
    src/etina_pipeline.cpp
)

# Test ETI-NA C API streamer
add_executable(test_etina_streamer
    tests/test_etina_streamer.cpp
)
target_link_libraries(test_etina_streamer dvbdab)

# Test TSNI C API streamer
add_executable(test_tsni_streamer
    tests/test_tsni_streamer.cpp
)
target_link_libraries(test_tsni_streamer dvbdab)

# Test SPI parser (EPG schedule extraction)
add_executable(test_spi_parser
    tests/test_spi_parser.cpp
)
target_link_libraries(test_spi_parser dvbdab)

# Test EHB parser (DAB EPG binary format)
add_executable(test_ehb_parser
    tests/test_ehb_parser.cpp
)
target_link_libraries(test_ehb_parser dvbdab)

# Test EHB file parsing (standalone file test)
add_executable(test_ehb_file
    tests/test_ehb_file.cpp
)
target_link_libraries(test_ehb_file dvbdab)

# Test EHB to EIT injection
add_executable(test_ehb_eit
    tests/test_ehb_eit.cpp
)
target_link_libraries(test_ehb_eit dvbdab)

# edi_info - Analyze EDI streams and show subchannel info
add_executable(edi_info
    src/edi_info.cpp
    src/sources/bbf_ts_source.cpp
    src/sources/gse_ts_source.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/gse_parser.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/parsers/pf_reassembler.cpp
    src/logging.cpp
)

# edi_extract - Extract audio from EDI streams without FIC
add_executable(edi_extract
    src/edi_extract.cpp
    src/sources/bbf_ts_source.cpp
    src/sources/gse_ts_source.cpp
    src/sources/mpe_ts_source.cpp
    src/parsers/gse_parser.cpp
    src/parsers/mpe_parser.cpp
    src/parsers/udp_extractor.cpp
    src/parsers/pf_reassembler.cpp
    src/logging.cpp
)

endif() # CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR

# ============================================================================
# Install targets
# ============================================================================
include(GNUInstallDirs)

install(TARGETS dvbdab
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/dvbdab
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

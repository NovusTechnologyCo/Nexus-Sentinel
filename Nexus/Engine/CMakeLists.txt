cmake_minimum_required(VERSION 3.20)
project(NexusEngine VERSION 0.9.0 LANGUAGES CXX C)

# C++23 standard (per migration plan policy)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Windows-specific settings
if(WIN32)
    # Target Windows 10+
    add_definitions(-D_WIN32_WINNT=0x0A00)
    add_definitions(-DWINVER=0x0A00)
    add_definitions(-DUNICODE -D_UNICODE)
endif()

# Engine library sources (our code)
# Note: thread.cpp and handle.cpp are excluded because their functions are already
# implemented in process.cpp. They contain enhanced implementations that could
# replace the process.cpp versions in the future.
set(ENGINE_SOURCES
    src/nexus.cpp
    src/process.cpp
    src/process_thread.cpp
    src/memory.cpp
    src/memory_typed.cpp
    src/memory_cache.cpp
    # src/thread.cpp - functions in process.cpp
    # src/handle.cpp - functions in process.cpp
    src/pe.cpp
    src/pe_exports.cpp
    src/snapshot.cpp
    src/scanner.cpp
    src/scanner_scan.cpp
    src/project.cpp
    src/project_json.cpp
    src/debugger.cpp
    src/debugger_module.cpp
    src/pointerscan.cpp
    src/pointerscan_scan.cpp
    src/injection.cpp
    src/injection_manualmap.cpp
    src/table.cpp
    src/table_script.cpp
    src/speedhack.cpp
    src/speedhack_hook.cpp
    src/ldisasm.cpp
    src/assembler.cpp
    src/assembler_engine.cpp
    src/assembler_script.cpp
    src/signature.cpp
    src/signature_scan.cpp
    src/stackwalk.cpp
    src/stackwalk_walk.cpp
    src/trace.cpp
    src/trace_classify.cpp
    src/addressfile.cpp
    src/addressfile_cea.cpp
    src/trainer.cpp
    src/trainer_persist.cpp
    src/trainer_codegen.cpp
    src/dissect.cpp
    src/dissect_persist.cpp
    src/dissect_enum.cpp
    src/disasm.cpp
    src/disasm_flow.cpp
    src/symbol.cpp
    src/symbol_user.cpp
    src/advscanner.cpp
    src/advscanner_scan.cpp
    # src/kernel.cpp - removed, will be rewritten as separate kernel module
    src/etw_core.cpp
    src/etw_provider.cpp
    src/etw_event.cpp
    src/etw_parse.cpp
    src/etw_filter.cpp
    src/etw_json.cpp
    src/cfg.cpp
    src/cfg_analyze.cpp
    src/value.cpp
    src/utility.cpp
    src/utility_scan.cpp
    # New x64dbg/TitanEngine-style modules
    src/dumper.cpp
    src/pemanip.cpp
    src/relocation.cpp
    src/resource.cpp
    src/tlsmanip.cpp
    src/importexport.cpp
    src/hookdetect.cpp
    src/hookdetect_scan.cpp
    src/staticanalysis.cpp
    src/avx512.cpp
    src/network.cpp
    src/windowheap.cpp
    src/sourcemap.cpp
    src/pageprotect.cpp
    src/codecave.cpp
    src/codecave_scan.cpp
)

# Third-party sources (external code, warnings disabled)
set(THIRD_PARTY_SOURCES
    third_party/amalgamated-dist/Zydis.c
)

# Public headers
set(ENGINE_HEADERS
    include/nexus_api.h
)

# Third-party code: enable warnings but disable specific ones that are unavoidable
# C4201: nameless struct/union - valid C11/C++11 but MSVC warns
if(MSVC)
    set_source_files_properties(${THIRD_PARTY_SOURCES} PROPERTIES COMPILE_FLAGS "/W4 /wd4201")
else()
    set_source_files_properties(${THIRD_PARTY_SOURCES} PROPERTIES COMPILE_FLAGS "-Wall -Wextra -Wno-gnu-anonymous-struct")
endif()

# Build engine as shared library (DLL)
add_library(NexusEngine SHARED ${ENGINE_SOURCES} ${THIRD_PARTY_SOURCES} ${ENGINE_HEADERS})

# Set output name to 'engine' (produces engine.dll)
# Output to shared bin folder under Nexus/
set_target_properties(NexusEngine PROPERTIES
    OUTPUT_NAME "engine"
    PREFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/../bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/../bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../bin"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/../bin"
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/../bin"
)

# Include directories
target_include_directories(NexusEngine
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/amalgamated-dist
)

# Link Windows libraries
target_link_libraries(NexusEngine PRIVATE
    psapi
    dbghelp
    tdh      # ETW Trace Data Helper
    advapi32 # ETW event tracing
    iphlpapi # Network connection enumeration
    ws2_32   # Winsock for address utilities
)

# Export macro for DLL
target_compile_definitions(NexusEngine PRIVATE NEXUS_ENGINE_EXPORTS)

# Zydis static build (we embed it in the engine DLL)
target_compile_definitions(NexusEngine PRIVATE ZYDIS_STATIC_BUILD)

# Compiler warnings - treat as errors
if(MSVC)
    target_compile_options(NexusEngine PRIVATE /W4 /WX)
else()
    target_compile_options(NexusEngine PRIVATE -Wall -Wextra -Werror)
endif()

# Test harness executable
add_executable(NexusTestHarness test/test_harness.cpp)
target_link_libraries(NexusTestHarness PRIVATE NexusEngine)

# Output test harness to shared bin folder
set_target_properties(NexusTestHarness PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/../bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/../bin"
)

# Install rules
install(TARGETS NexusEngine
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${ENGINE_HEADERS} DESTINATION include/nexus)

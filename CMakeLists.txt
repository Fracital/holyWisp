cmake_minimum_required(VERSION 3.20)
project(holyWisp VERSION 0.1.0 LANGUAGES C)

# Options ------------------------------------------------------------------------------------
option(HW_WERROR "Treat warnings as errors" ON)
option(HW_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(HW_BUILD_TESTS "Build the test binaries" ON)
set(HW_VERSION_SUFFIX "" CACHE STRING "Appended to the reported version, e.g. +<commit>")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Threads REQUIRED)

# Warnings: STYLE.md "Language and portability". -------------------------------------------
add_library(hw_flags INTERFACE)
target_compile_definitions(hw_flags INTERFACE _GNU_SOURCE)
target_compile_options(hw_flags INTERFACE
  -Wall -Wextra -Wpedantic
  -Wshadow -Wvla -Wstrict-prototypes -Wmissing-prototypes
  -Wpointer-arith -Wwrite-strings -Wundef
  -Wno-unused-parameter
  -fno-common
)
if(HW_WERROR)
  target_compile_options(hw_flags INTERFACE -Werror)
endif()
if(HW_VERSION_SUFFIX)
  target_compile_definitions(hw_flags INTERFACE HW_VERSION_SUFFIX="${HW_VERSION_SUFFIX}")
endif()
if(HW_SANITIZE)
  target_compile_options(hw_flags INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(hw_flags INTERFACE -fsanitize=address,undefined)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_compile_options(hw_flags INTERFACE -O2)
endif()

# libholywisp: everything the server, client and tests share. ------------------------------
add_library(holywisp STATIC
  src/common/base64.c
  src/common/buf.c
  src/common/dns.c
  src/common/filter.c
  src/common/limits.c
  src/common/log.c
  src/common/loop.c
  src/common/map.c
  src/common/net.c
  src/common/reputation.c
  src/common/resolver.c
  src/common/sha1.c
  src/common/smap.c
  src/common/wisp.c
  src/common/ws.c
)
target_include_directories(holywisp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(holywisp PUBLIC hw_flags Threads::Threads)

# libholywisp-server: the server as a library (the binary and the e2e test both link it). ---
# Embed the browser client (examples/wisp-webclient.html) into the server so it can be served on
# GET / with no on-disk asset. Regenerated whenever the HTML changes.
set(HW_WEBCLIENT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/examples/wisp-webclient.html)
set(HW_WEBCLIENT_HDR ${CMAKE_CURRENT_BINARY_DIR}/generated/holywisp_webclient.h)
add_custom_command(
  OUTPUT ${HW_WEBCLIENT_HDR}
  COMMAND ${CMAKE_COMMAND} -DINPUT=${HW_WEBCLIENT_SRC} -DOUTPUT=${HW_WEBCLIENT_HDR}
          -DSYMBOL=hw_webclient_html -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_file.cmake
  DEPENDS ${HW_WEBCLIENT_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_file.cmake
  COMMENT "Embedding wisp-webclient.html"
  VERBATIM)

add_library(holywisp-server STATIC
  src/server/config.c
  src/server/conn.c
  src/server/egress.c
  src/server/proxy.c
  src/server/server.c
  src/server/stream.c
  src/server/twisp.c
  ${HW_WEBCLIENT_HDR}
)
target_link_libraries(holywisp-server PUBLIC holywisp)
# crypt(3) for password hashes; forkpty(3) for Twisp terminal streams.
target_link_libraries(holywisp-server PUBLIC crypt util)
target_include_directories(holywisp-server PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)

add_executable(holywisp-bin src/server/main.c)
set_target_properties(holywisp-bin PROPERTIES OUTPUT_NAME holywisp)
target_link_libraries(holywisp-bin PRIVATE holywisp-server)

# libholywisp-client + CLI ------------------------------------------------------------------
add_library(holywisp-client STATIC src/client/client.c)
target_link_libraries(holywisp-client PUBLIC holywisp)

add_executable(holywisp-client-bin src/client/main.c)
set_target_properties(holywisp-client-bin PROPERTIES OUTPUT_NAME holywisp-client)
target_link_libraries(holywisp-client-bin PRIVATE holywisp-client)

# Tests --------------------------------------------------------------------------------------
if(HW_BUILD_TESTS)
  enable_testing()
  function(hw_test name)
    add_executable(${name} tests/${name}.c)
    target_link_libraries(${name} PRIVATE holywisp-server holywisp-client)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 120)
    # The end-to-end suites run a whole server plus client, echo and proxy threads in one process.
    # Under a parallel `ctest -j`, CPU contention starves those threads and their internal timeouts
    # flake. RUN_SERIAL keeps them from competing with the rest of the suite.
    if(${name} STREQUAL test_e2e OR ${name} STREQUAL test_security)
      set_tests_properties(${name} PROPERTIES RUN_SERIAL ON)
    endif()
  endfunction()
  hw_test(test_buf)
  hw_test(test_crypto)
  hw_test(test_map)
  hw_test(test_smap)
  hw_test(test_net)
  hw_test(test_wisp)
  hw_test(test_ws)
  hw_test(test_loop)
  hw_test(test_limits)
  hw_test(test_filter)
  hw_test(test_dns)
  hw_test(test_reputation)
  hw_test(test_e2e)
  hw_test(test_security)
endif()

install(TARGETS holywisp-bin holywisp-client-bin RUNTIME DESTINATION bin)

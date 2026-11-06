cmake_minimum_required(VERSION 3.20)
project(holyWisp VERSION 0.1.0 LANGUAGES C)

# Options ------------------------------------------------------------------------------------
option(HW_WERROR "Treat warnings as errors" ON)
option(HW_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(HW_BUILD_TESTS "Build the test binaries" ON)

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
  src/common/log.c
  src/common/loop.c
  src/common/map.c
  src/common/net.c
  src/common/resolver.c
  src/common/sha1.c
  src/common/wisp.c
  src/common/ws.c
)
target_include_directories(holywisp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(holywisp PUBLIC hw_flags Threads::Threads)

# libholywisp-server: the server as a library (the binary and the e2e test both link it). ---
add_library(holywisp-server STATIC
  src/server/config.c
  src/server/conn.c
  src/server/egress.c
  src/server/server.c
  src/server/stream.c
)
target_link_libraries(holywisp-server PUBLIC holywisp)

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
  endfunction()
  hw_test(test_buf)
  hw_test(test_crypto)
  hw_test(test_map)
  hw_test(test_net)
  hw_test(test_wisp)
  hw_test(test_ws)
  hw_test(test_loop)
  hw_test(test_e2e)
endif()

install(TARGETS holywisp-bin holywisp-client-bin RUNTIME DESTINATION bin)

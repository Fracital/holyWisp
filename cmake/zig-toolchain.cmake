# Cross-compile with `zig cc`, for the prebuilt binaries the npm package carries (node/).
#   cmake -S . -B build/npm/linux-arm64 -DCMAKE_TOOLCHAIN_FILE=cmake/zig-toolchain.cmake \
#         -DHW_ZIG_TARGET=aarch64-linux-musl
# HW_ZIG is the zig executable (default `zig`; `python-zig` when it came from PyPI's ziglang).
# Zig bundles a libc for every target, so one host builds every platform and a musl target links
# fully static: the binary runs on any distribution, glibc or musl, with nothing installed.
if(NOT HW_ZIG_TARGET)
  message(FATAL_ERROR "zig-toolchain.cmake needs -DHW_ZIG_TARGET=<arch>-<os>-<abi>")
endif()
if(NOT HW_ZIG)
  set(HW_ZIG zig)
endif()
# try_compile() re-enters this file in a scratch project; carry the two settings over.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES HW_ZIG HW_ZIG_TARGET)

string(REGEX MATCH "^[^-]+" _hw_arch "${HW_ZIG_TARGET}")
if(HW_ZIG_TARGET MATCHES "-linux")
  set(CMAKE_SYSTEM_NAME Linux)
elseif(HW_ZIG_TARGET MATCHES "-macos")
  set(CMAKE_SYSTEM_NAME Darwin)
elseif(HW_ZIG_TARGET MATCHES "-windows")
  set(CMAKE_SYSTEM_NAME Windows)
else()
  message(FATAL_ERROR "zig-toolchain.cmake: unsupported target ${HW_ZIG_TARGET}")
endif()
set(CMAKE_SYSTEM_PROCESSOR ${_hw_arch})

# A list here is the compiler followed by arguments it is always given.
set(CMAKE_C_COMPILER ${HW_ZIG} cc -target ${HW_ZIG_TARGET})

# CMake wants ar and ranlib as single executables; `zig ar` is two words, so wrap them.
set(_hw_wrap ${CMAKE_BINARY_DIR}/zig-wrap)
foreach(_hw_tool ar ranlib)
  if(NOT EXISTS ${_hw_wrap}/${_hw_tool})
    file(WRITE ${_hw_wrap}/${_hw_tool} "#!/bin/sh\nexec ${HW_ZIG} ${_hw_tool} \"$@\"\n")
    file(CHMOD ${_hw_wrap}/${_hw_tool} PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
         WORLD_READ WORLD_EXECUTE)
  endif()
endforeach()
set(CMAKE_AR ${_hw_wrap}/ar)
set(CMAKE_RANLIB ${_hw_wrap}/ranlib)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

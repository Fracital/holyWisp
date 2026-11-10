# holyWisp: single entry point for building, testing and formatting.
#
# CMake does the compiling; this Makefile drives it so every workflow is one command.
# Presets live in CMakePresets.json (shared with IDEs).
#
#   make              debug build (ASan + UBSan)         -> build/debug
#   make test         debug build + ctest
#   make release      optimised build                     -> build/release
#   make run          run the debug server                (ARGS="--port 7000")
#   make format       clang-format -i over the tree
#   make check-format fail if clang-format would change anything (what CI runs)
#   make tidy         clang-tidy over the debug compile database
#   make npm          the npm package (node/): static binaries via zig + the compiled wrapper
#   make npm-test     the Node wrapper's tests against the release build
#   make test-windows the Windows build (zig) and its tests under Wine
#   make help         this list

SHELL := bash
.DEFAULT_GOAL := build

CMAKE        ?= cmake
CTEST        ?= ctest
CLANG_FORMAT ?= clang-format
CLANG_TIDY   ?= clang-tidy
JOBS         ?= $(shell nproc 2>/dev/null || echo 4)
GENERATOR    ?= $(if $(shell command -v ninja 2>/dev/null),Ninja,Unix Makefiles)
CMAKE_FLAGS  ?=
ARGS         ?=
CC           ?= cc
NODE         ?= node
NPM          ?= npm
ZIG          ?= $(shell command -v zig 2>/dev/null || command -v python-zig 2>/dev/null)
WINE         ?= wine

DEBUG_DIR   := build/debug
RELEASE_DIR := build/release
WINDOWS_DIR := build/win

# Every C file we own. Vendored code would be excluded here; there is none.
SOURCES := $(shell find include src tests -name '*.c' -o -name '*.h' | sort)
# The other platforms' halves of loop_backend.h and sys.h: formatted like everything else, but not
# compiled here, so not in this host's compile database for clang-tidy. (A Windows build is always
# a cross build from one of these two: see `make npm`.)
WINDOWS_ONLY := src/common/loop_select.c src/common/sys_win32.c src/compat/win32/posix.c
ifeq ($(shell uname -s),Darwin)
FOREIGN := src/common/loop_epoll.c src/common/sys_linux.c $(WINDOWS_ONLY)
else
FOREIGN := src/common/loop_kqueue.c src/common/sys_darwin.c $(WINDOWS_ONLY)
endif

.PHONY: build release test test-release test-windows run run-release format check-format tidy bench npm npm-test \
	deb rpm packages clean help

# ---------------------------------------------------------------------------------- build

$(DEBUG_DIR)/CMakeCache.txt:
	$(CMAKE) -S . -B $(DEBUG_DIR) -G "$(GENERATOR)" -DCMAKE_BUILD_TYPE=Debug -DHW_SANITIZE=ON \
		-DCMAKE_C_COMPILER=$(CC) $(CMAKE_FLAGS)

$(RELEASE_DIR)/CMakeCache.txt:
	$(CMAKE) -S . -B $(RELEASE_DIR) -G "$(GENERATOR)" -DCMAKE_BUILD_TYPE=Release -DHW_SANITIZE=OFF \
		-DCMAKE_C_COMPILER=$(CC) $(CMAKE_FLAGS)

build: $(DEBUG_DIR)/CMakeCache.txt ## debug build with sanitizers
	$(CMAKE) --build $(DEBUG_DIR) -j $(JOBS)

release: $(RELEASE_DIR)/CMakeCache.txt ## optimised build
	$(CMAKE) --build $(RELEASE_DIR) -j $(JOBS)

# ---------------------------------------------------------------------------------- test

test: build ## unit + e2e tests under ASan/UBSan
	$(CTEST) --test-dir $(DEBUG_DIR) --output-on-failure -j $(JOBS)

test-release: release ## the same tests against the optimised build
	$(CTEST) --test-dir $(RELEASE_DIR) --output-on-failure -j $(JOBS)

# Nothing here is Windows, so its build is a cross build (the one `make npm` ships) and its tests
# run under Wine. That is a real Winsock and a real select(), but not Windows: CI runs the same
# binaries on the real thing (build.yml, "Windows / tests").
test-windows: ## cross-build for Windows with zig and run the tests under Wine
	@test -n "$(ZIG)" || { echo "test-windows: zig not found (https://ziglang.org, or pip install ziglang); set ZIG"; exit 1; }
	$(CMAKE) -S . -B $(WINDOWS_DIR) -G "$(GENERATOR)" -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_TOOLCHAIN_FILE=cmake/zig-toolchain.cmake -DHW_ZIG=$(ZIG) -DHW_ZIG_TARGET=x86_64-windows-gnu
	$(CMAKE) --build $(WINDOWS_DIR) -j $(JOBS)
	@for t in $(WINDOWS_DIR)/test_*.exe; do \
		echo "== $$t"; \
		WINEDEBUG=-all $(WINE) $$t || exit 1; \
	done

# ---------------------------------------------------------------------------------- run

run: build ## run the debug server (ARGS="--port 7000 --allow-loopback")
	$(DEBUG_DIR)/holywisp $(ARGS)

run-release: release ## run the release server
	$(RELEASE_DIR)/holywisp $(ARGS)

# ---------------------------------------------------------------------------------- lint

format: ## rewrite every source file in the repo style
	$(CLANG_FORMAT) -i $(SOURCES)

check-format: ## fail when clang-format would change anything
	$(CLANG_FORMAT) --dry-run -Werror $(SOURCES)

# Depends on the full build, not just the cache: conn.c includes a generated header (the embedded
# web client), so the build must have run for clang-tidy to resolve the include.
tidy: build ## clang-tidy with the debug compile database
	$(CLANG_TIDY) -p $(DEBUG_DIR) --quiet $(filter-out $(FOREIGN),$(filter %.c,$(SOURCES)))

# ---------------------------------------------------------------------------------- bench

BENCH_DIR := build/bench

bench: release ## build the benchmark tools (bench/echo, bench/pump) into build/bench
	mkdir -p $(BENCH_DIR)
	$(CC) -O2 -Wall -Wextra -pthread -o $(BENCH_DIR)/echo bench/echo.c
	$(CC) -O2 -Wall -Wextra -pthread -I include -o $(BENCH_DIR)/pump bench/pump.c \
		$(RELEASE_DIR)/libholywisp-client.a $(RELEASE_DIR)/libholywisp.a

# ---------------------------------------------------------------------------------- npm

# The Node.js package (node/README.md). `make npm` needs zig (ZIG=..., `zig` or `python-zig` on the
# PATH): it cross-compiles one static binary per platform through cmake/zig-toolchain.cmake.
node/node_modules: node/package.json node/package-lock.json
	cd node && $(NPM) ci --no-audit --no-fund
	@touch $@

npm: node/node_modules ## build the npm package's binaries and wrapper into node/bin, node/dist
	$(NODE) node/scripts/build.mjs

npm-test: release node/node_modules ## the Node wrapper's tests against the release build
	cd node && HOLYWISP_BIN=$(CURDIR)/$(RELEASE_DIR)/holywisp $(NPM) test

# ---------------------------------------------------------------------------------- misc

deb: ## build a .deb into build/packages/
	deploy/package.sh deb

rpm: ## build an .rpm into build/packages/
	deploy/package.sh rpm

packages: ## build every package this host can (.deb and/or .rpm)
	deploy/package.sh all

clean: ## remove every build tree
	rm -rf build node/bin node/dist

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

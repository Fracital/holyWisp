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

DEBUG_DIR   := build/debug
RELEASE_DIR := build/release

# Every C file we own. Vendored code would be excluded here; there is none.
SOURCES := $(shell find include src tests -name '*.c' -o -name '*.h' | sort)

.PHONY: build release test test-release run run-release format check-format tidy deb rpm packages clean help

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
	$(CLANG_TIDY) -p $(DEBUG_DIR) --quiet $(filter %.c,$(SOURCES))

# ---------------------------------------------------------------------------------- misc

deb: ## build a .deb into build/packages/
	deploy/package.sh deb

rpm: ## build an .rpm into build/packages/
	deploy/package.sh rpm

packages: ## build every package this host can (.deb and/or .rpm)
	deploy/package.sh all

clean: ## remove every build tree
	rm -rf build

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

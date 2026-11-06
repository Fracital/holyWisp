# holyWisp C style

These are the ground rules for every `.c` and `.h` in this repository. `.clang-format` enforces the
layout half mechanically (`make format` rewrites, `make check-format` verifies, CI fails on drift) and
`.clang-tidy` enforces the naming half (`make tidy`). The rest is reviewed by hand.

## Language and portability

- C11 (`-std=c11`), with `_GNU_SOURCE` defined project-wide for `accept4`, `pipe2`, `eventfd` and
  friends. No C++ and no compiler extensions beyond `__attribute__` behind the `HW_*` macros in
  `include/holywisp/hw.h`.
- Linux is the target. The event loop is epoll. Anything platform-specific stays in
  `src/common/loop.c` and `src/common/net.c` so a second backend can be added without touching the
  protocol code.
- No third-party dependencies. SHA-1 and Base64 for the WebSocket handshake are in-tree. TLS is a
  reverse proxy's job.
- Warnings are errors: `-Wall -Wextra -Wpedantic -Wshadow -Wvla -Wstrict-prototypes
  -Wmissing-prototypes -Wpointer-arith -Wwrite-strings -Wundef`. Fix the warning, do not silence it;
  if a cast is the honest fix, add a one-line comment saying why.
- Fixed-width integers (`uint32_t`, `uint8_t`) for anything that touches the wire. `size_t` for
  lengths in memory. `int` only for flags, counters and return codes.

## Layout (clang-format owns this)

- Tabs for indentation, displayed at 4 columns. Spaces for alignment inside a line.
- 120 columns.
- K&R braces, attached everywhere, functions included:
  ```c
  static int conn_write(hw_conn *c, const uint8_t *data, size_t len) {
  	if (c->closed) return -1;
  	...
  }
  ```
- `char *p`, never `char* p`. `const` on the left: `const char *name`.
- A single-statement `if` may share the line with its body when the whole thing fits
  (`if (!p) return -1;`). Anything with an `else`, or any body of two or more statements, gets braces.
- `case` labels sit at the same column as `switch`. Every non-empty case ends in `break`, `return`
  or an explicit `// fall through` comment.
- Includes come in three groups separated by blank lines, each sorted: the file's own header or the
  project's `"holywisp/..."` headers, then other project headers, then system headers.
- One blank line between functions, at most one blank line anywhere.

## Naming (clang-tidy owns this)

- `snake_case` for functions, variables, parameters, struct and typedef names.
- `UPPER_CASE` for macros, enum constants and file-scope `static const` data. A `static const`
  inside a function is a local and stays `snake_case`.
- Everything exported from `include/holywisp/` carries the `hw_` prefix (`hw_buf_append`,
  `hw_server_run`). Enum constants carry `HW_`.
- File-local (`static`) functions have no prefix and read as `noun_verb`: `conn_close`,
  `stream_flush`. The noun is the first parameter's type, with its prefix dropped.
- Mutable globals are a smell. The few that exist (`g_sig_pipe`) carry `g_` and live in one place.
- Opaque handles are `typedef struct hw_foo hw_foo;` in the public header with the struct body in
  the `.c` file. Plain data structs (`hw_buf`, `hw_wisp_packet`) are defined in the header.

## Headers

- Include guards are `HOLYWISP_<FILE>_H`. No `#pragma once`.
- Every public header starts with a comment block saying what the module is for and, when it is
  not obvious, who calls it from which thread.
- Headers include what they use and nothing more. A header never includes another just to be
  convenient for its users.
- Public functions are declared once, in a header. `static` functions are not declared ahead of
  their definition unless mutual recursion forces it.

## Functions and errors

- Return `0` on success and `-1` on failure with `errno` set, the way the C library does. When
  there is nothing useful to put in `errno`, return a negative `HW_ERR_*` from `hw.h`.
- Functions that produce a value and can fail take an out-pointer as their last parameter.
- Early returns are preferred over nesting. `goto fail;` is the cleanup pattern when more than one
  resource has to be released; the label is always `fail`.
- A function that owns a pointer and frees it is named `_free`. A function that releases contents
  but not the struct is named `_clear` or `_reset`.
- No VLAs. Stack buffers have a named constant for their size. Anything larger than 64 KiB goes on
  the heap or in a per-worker scratch buffer.
- `memcpy` the wire, never cast a `uint8_t *` to `uint32_t *`. Little-endian helpers live in
  `wisp.h`; big-endian ones in `ws.h`.

## Comments

- `//` for line comments, `/* */` only for the file header block.
- Comments say *why*, or state an invariant the next reader could not infer. They do not restate the
  code. A comment above a function describes its contract: threads, ownership, what the return
  value means.
- No commented-out code. Delete it; git remembers.
- `TODO` is allowed only with an owner or an issue: `// TODO(name): ...`.

## Concurrency

- Each worker thread owns an `hw_loop` and everything registered on it. Nothing crosses threads
  except through `hw_loop_post` (wake via eventfd) and `_Atomic` counters.
- A struct documents which thread owns it at the top of its definition.
- Callbacks may close the object they were invoked on. Freeing is deferred to the next loop
  iteration (`hw_loop_post`) so nothing in the current dispatch batch touches freed memory.

## Tests

- Every module in `src/common/` has a `tests/test_<module>.c` that links the library and runs with
  `ctest`. Tests use the `CHECK(cond, fmt, ...)` macro from `tests/test.h`, print `ok <name>` per
  case and exit non-zero on the first failure.
- End-to-end tests start a real server on an ephemeral loopback port and drive it with the real
  client library. No mocks of the network.
- Tests build with the same warnings as the code and run under ASan/UBSan in the Debug preset.

## Git

- Commits are small and have an imperative subject under 72 characters, a blank line, then the why.
- Never add `Co-Authored-By`, `Signed-off-by` or any other trailer attributing a commit to a tool or
  model. The author field is the author. This applies to humans and agents alike.
- Nothing is committed that `make check-format` or `make test` rejects.

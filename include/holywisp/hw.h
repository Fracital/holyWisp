/*
 * holywisp/hw.h - project-wide macros, error codes and tiny helpers every module uses.
 */
#ifndef HOLYWISP_HW_H
#define HOLYWISP_HW_H

#include <stddef.h>
#include <stdint.h>

#define HW_VERSION "0.5.2"
#ifndef HW_VERSION_SUFFIX
#define HW_VERSION_SUFFIX "" // set at build time to a git commit, e.g. "+abc123"
#endif

#define HW_UNUSED                        __attribute__((unused))
#define HW_PRINTF(fmt_index, args_index) __attribute__((format(printf, fmt_index, args_index)))
#define HW_LIKELY(x)                     __builtin_expect(!!(x), 1)
#define HW_UNLIKELY(x)                   __builtin_expect(!!(x), 0)

#define HW_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define HW_MIN(a, b)    ((a) < (b) ? (a) : (b))
#define HW_MAX(a, b)    ((a) > (b) ? (a) : (b))

// Negative return codes for functions where errno has nothing useful to say.
enum hw_err {
	HW_OK = 0,
	HW_ERR_INVALID = -1,  // malformed input
	HW_ERR_AGAIN = -2,    // need more input
	HW_ERR_NOMEM = -3,    // allocation failed
	HW_ERR_TOOBIG = -4,   // input exceeds a configured limit
	HW_ERR_CLOSED = -5,   // the peer or the object is closed
	HW_ERR_TIMEOUT = -6,  // waited too long
	HW_ERR_PROTOCOL = -7, // the peer violated the protocol
	HW_ERR_IO = -8        // a system call failed; errno is set
};

// CLOCK_MONOTONIC in milliseconds.
uint64_t hw_now_ms(void);
int hw_set_nonblock(int fd);
int hw_set_cloexec(int fd);

#endif

/*
 * <signal.h> for Windows: sigaction(2) for the two signals that ask a process to stop. See
 * src/compat/win32/hw_w32.h.
 */
#ifndef HOLYWISP_COMPAT_SIGNAL_H
#define HOLYWISP_COMPAT_SIGNAL_H

// This file stands in front of the toolchain's header of the same name and passes on to it.
#pragma GCC system_header
#include_next <signal.h>

// Windows has no such signal: a write to a closed socket is only ever an error.
#ifndef SIGPIPE
#define SIGPIPE 13
#endif

typedef unsigned long hw_w32_sigset;
#define sigset_t hw_w32_sigset

struct sigaction {
	void (*sa_handler)(int);
	sigset_t sa_mask;
	int sa_flags;
};

int sigemptyset(sigset_t *set);
// SIGINT and SIGTERM only. The handler runs for raise(), for Ctrl+C (SIGINT), and for
// Ctrl+Break and the console closing, logging off or shutting down (SIGTERM): on a thread of its
// own, never interrupting one, and it stays installed.
int sigaction(int signo, const struct sigaction *act, struct sigaction *old);

typedef void (*hw_w32_sighandler)(int);
// signal(2), except that SIGPIPE is accepted and nothing is done about it.
hw_w32_sighandler hw_w32_signal(int signo, hw_w32_sighandler handler);

#ifndef HW_W32_NO_MACROS
#define signal(signo, handler) hw_w32_signal((signo), (handler))
#endif

#endif

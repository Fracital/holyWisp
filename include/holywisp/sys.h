/*
 * holywisp/sys.h - the calls that differ between kernels.
 *
 * holyWisp is written for Linux; macOS and Windows are ports for development machines. Everything
 * the three disagree on is declared here and implemented once for each, in sys_linux.c,
 * sys_darwin.c and sys_win32.c, and the event loop has a backend per kernel (loop_epoll.c,
 * loop_kqueue.c, loop_select.c). The conditional below is the only one in the tree: code elsewhere
 * calls these and stays the same on all of them. (On Windows the POSIX socket calls themselves are
 * supplied by src/compat/win32, which is why this file can include <sys/socket.h> there.)
 */
#ifndef HOLYWISP_SYS_H
#define HOLYWISP_SYS_H

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

// send(2) flags. Without MSG_NOSIGNAL the socket itself is marked (hw_sys_socket, hw_sys_accept)
// so a write to a closed peer is EPIPE and never a signal. MSG_MORE is only a hint.
#if defined(__linux__)
#define HW_MSG_NOSIGNAL MSG_NOSIGNAL
#define HW_MSG_MORE     MSG_MORE
#else
#define HW_MSG_NOSIGNAL 0
#define HW_MSG_MORE     0
#endif

// socket(2), close-on-exec, non-blocking when `nonblock`, and never raising SIGPIPE.
int hw_sys_socket(int domain, int type, int protocol, int nonblock);
// accept(2) with the same three properties, always non-blocking.
int hw_sys_accept(int listen_fd, struct sockaddr *addr, socklen_t *addr_len);

// Tune TCP keepalive on a socket that has SO_KEEPALIVE: the first probe after idle_s seconds of
// silence, then one every interval_s, and the peer is given up on after `count` unanswered.
void hw_sys_keepalive(int fd, int idle_s, int interval_s, int count);

// A listener for one more worker on the address `first` is bound to. Linux binds another
// SO_REUSEPORT socket and the kernel deals connections out between them. macOS gives every
// connection to one of such sockets, so there the result is a duplicate of `first` and the
// workers accept from one queue. -1 with errno on failure.
int hw_sys_listen_more(int first, const char *host, uint16_t port, int backlog);

// A non-blocking pipe to relay socket payloads through without copying them: fds[0] is read,
// fds[1] written. Its capacity is `want` if the kernel grants it and at least `min`, reported in
// *size. -1 with errno when no such pipe can be had (ENOBUFS: only a smaller one; ENOTSUP: this
// kernel cannot splice), and the caller copies instead.
int hw_sys_relay_pipe(int fds[2], size_t want, size_t min, size_t *size);
// Move up to n bytes from one descriptor to the other, one of them a relay pipe, without
// blocking. The byte count, 0 at end of input, or -1 with errno (EAGAIN when nothing can move,
// EINVAL/ENOSYS when the pair cannot be spliced).
ssize_t hw_sys_splice(int from, int to, size_t n);

// Whether hw_sys_close_reset ever does more than close.
int hw_sys_has_close_reset(void);
// Close a connected TCP socket the caller has no more use for, without what an ordinary close
// leaves behind: the connection in TIME_WAIT for a minute, and its local port taken for as long.
// It is reset instead, but only when the peer has acknowledged every byte written to it.
// Otherwise, and where the kernel cannot tell, this is close(2): nothing that was written is ever
// dropped on its way to the peer. 1 when the connection was reset, 0 when it was closed.
int hw_sys_close_reset(int fd);

// Fill buf with len bytes from the kernel's random source, the one that is fit for keys: nothing
// about them can be guessed from the clock, the pid or earlier output. 0, or -1 when the kernel
// has none to give, and then buf holds nothing to rely on.
int hw_sys_random(void *buf, size_t len);

// Whether there is a crypt(3) at all. Without one hw_sys_crypt always fails, so a hashed password
// can never match and the server refuses a config that holds one.
int hw_sys_has_crypt(void);
// crypt(3): hash `key` with the method and salt of `setting` into out. 0, or -1 when the hash
// does not fit or the method is unknown. Thread-safe. Which methods exist is the C library's
// business: glibc and musl know $5$ and $6$, macOS only the traditional DES form.
int hw_sys_crypt(const char *key, const char *setting, char *out, size_t out_cap);

// Whether hw_sys_pty_spawn can work at all here.
int hw_sys_has_pty(void);
// Run argv[0] (looked up on PATH) with the arguments argv on a new pseudo-terminal with default
// settings and TERM=xterm-256color, with SIGPIPE at its default whatever the caller has made of
// it, and with none of the caller's descriptors. The child's pid, with the terminal's master side
// in *master: non-blocking, close-on-exec, read and written like a socket, EIO once the child has
// gone.
// -1 with errno (ENOTSUP without hw_sys_has_pty).
pid_t hw_sys_pty_spawn(char *const argv[], int *master);
// Tell the terminal behind `master` the size of its window.
void hw_sys_pty_resize(int master, uint16_t rows, uint16_t cols);
// End a child of hw_sys_pty_spawn and reap it: hang up, and kill it if that did not end it at once.
void hw_sys_pty_end(pid_t pid);

#endif

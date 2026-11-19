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

#include <poll.h>
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

// Whether a datagram that a socket from hw_sys_socket sends to a port nothing listens on comes back
// as an error on that socket (ECONNREFUSED from a later send or receive on a connected socket), so
// a UDP stream to a closed port can be closed as unreachable. 0 where such a datagram is just lost
// and the socket goes on as if it had been delivered.
int hw_sys_has_udp_unreachable(void);

// ---- UDP for the WebTransport listener (docs/webtransport.md, "Connection IDs and steering")

// Whether hw_sys_udp_steer can work here. Where it cannot, the listener opens one UDP socket, on
// one worker, and that worker owns every WebTransport connection.
int hw_sys_has_udp_steer(void);
// Steer the datagrams that reach a group of UDP sockets bound one after another with
// SO_REUSEPORT to the same address, fds[0] first, by the QUIC connection ID they carry: a datagram
// of at least 7 bytes goes to fds[i] when i is byte 1 (a short header, whose DCID starts there) or,
// for a long header whose DCID is 8 bytes, byte 6 (where that DCID starts). Everything else, and an
// index of n or more (a client's first Initial, whose DCID it chose itself), goes where the
// kernel's hash of the addresses sends it, which is the same socket for every datagram of one
// client address. The index holds while no socket of the group is closed. 0, or -1 with errno
// (ENOTSUP without hw_sys_has_udp_steer).
int hw_sys_udp_steer(const int fds[], size_t n);

// One datagram of a batch. To receive: buf and cap are the caller's, and len, segment, addr and
// addr_len come back (a read longer than cap comes back with len 0: it was cut, and is to be
// dropped). buf then holds len bytes, which are one datagram, or on a socket with hw_sys_udp_gro
// on several datagrams of one sender back to back: each `segment` bytes long but the last, which
// may be shorter (segment == len for one). To send: buf, len, addr, addr_len and alone are the
// caller's, and an addr_len of 0 sends to a connected socket's peer; run_start too.
typedef struct hw_sys_dgram {
	uint8_t *buf;
	size_t cap;
	size_t len;
	size_t segment;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	// Sending: never in one write with others (Linux UDP_SEGMENT). A QUIC PMTU probe is one: a
	// hop that cannot carry it drops the whole write, and the packets that shared it with it.
	int alone;
	// Sending: never in one write with the datagram before it. One write of a run leaves the NIC
	// back to back however it was paced, so a sender marks the first datagram of each of its
	// pacer's releases, and a run is never more than one release.
	int run_start;
} hw_sys_dgram;

#define HW_SYS_BATCH_MAX 32    // the most datagrams (or coalesced reads) one batch call moves
#define HW_SYS_GRO_SLOT  65536 // the receive room a slot needs on a socket with hw_sys_udp_gro on

// Receive up to n datagrams from a non-blocking UDP socket, never waiting (one recvmmsg on Linux,
// one recvfrom after another elsewhere). The number of slots filled, at least 1, or -1 with errno
// (EAGAIN: none were waiting).
int hw_sys_recv_batch(int fd, hw_sys_dgram *d, size_t n);
// Send d[0..n) in order from a non-blocking UDP socket, never waiting (one sendmmsg on Linux).
// The number of datagrams sent from the front, at least 1, or -1 with errno when the first one
// could not go (EAGAIN: the socket buffer is full). Where the kernel can (hw_sys_has_udp_gso), a
// run of datagrams to one address, all of one length but the last, which may be shorter, is
// handed to it as one write that it cuts up again (Linux UDP_SEGMENT): the datagrams on the wire
// are the same, and a batch costs the kernel a few writes instead of one per datagram. A run ends
// before a datagram marked run_start, and never takes one marked alone.
int hw_sys_send_batch(int fd, const hw_sys_dgram *d, size_t n);
// Whether hw_sys_send_batch coalesces runs at all here.
int hw_sys_has_udp_gso(void);
// Ask the kernel to hand a UDP socket the datagrams one sender sends back to back as one read
// (Linux UDP_GRO), which hw_sys_recv_batch then reports with their segment size. 1 when that is
// on, and from then on every slot given to hw_sys_recv_batch for this socket must have a cap of
// at least HW_SYS_GRO_SLOT, or a coalesced read is cut and lost. 0 where it cannot be had: every
// read is one datagram, as before.
int hw_sys_udp_gro(int fd);

// Ask for a receive and a send buffer of `bytes` each on a socket, past the system's cap where the
// process may (Linux: SO_RCVBUFFORCE and SO_SNDBUFFORCE, which take CAP_NET_ADMIN; without it
// net.core.rmem_max and wmem_max cap what is granted). Returns the receive buffer the socket now
// has, as the kernel counts it (Linux counts double what it grants, for its bookkeeping), 0 when
// it cannot say.
size_t hw_sys_udp_buffers(int fd, int bytes);

// Every datagram of a UDP socket leaves whole with the don't-fragment bit set, whatever the path
// MTU the system has learnt (Linux IP_PMTUDISC_PROBE, macOS IP_DONTFRAG, Windows
// IP_DONTFRAGMENT; their IPv6 twins). One the path cannot carry is lost on the way, never sent in
// fragments. QUIC finds its own datagram size by probing (RFC 8899) and needs a probe that does not
// fit to be lost: a probe that got through fragmented made every packet after it two fragments,
// and the loss of either cost the packet. 0, or -1 with errno.
int hw_sys_udp_no_fragment(int fd);

// poll(2) with the timeout in microseconds (-1: none, 0: do not wait), never cut short: where the
// kernel waits only in milliseconds (macOS, Windows) it is rounded up to the next one. Linux
// waits in ppoll, to within its timer slack. What poll returns, EINTR included.
int hw_sys_poll_us(struct pollfd *fds, nfds_t n, int64_t timeout_us);
// The unit hw_sys_poll_us keeps a timeout in: 1 (microseconds) on Linux, 1000 where it rounds up.
unsigned hw_sys_poll_resolution_us(void);

// Whether hw_sys_set_mark can work at all here.
int hw_sys_has_mark(void);
// Give a socket a firewall mark (Linux SO_MARK), which policy routing can send out another way:
// the WARP tunnels pick their UDP this way. Takes CAP_NET_ADMIN. 0, or -1 with errno (EPERM
// without the capability; ENOTSUP without hw_sys_has_mark), and then the socket is as it was.
int hw_sys_set_mark(int fd, uint32_t mark);

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
// it, no signal blocked (hw_sys_user_signals blocks two), and with none of the caller's descriptors. The child's pid,
// with the terminal's master side in *master: non-blocking, close-on-exec, read and written like a socket, EIO once the
// child has gone. -1 with errno (ENOTSUP without hw_sys_has_pty).
pid_t hw_sys_pty_spawn(char *const argv[], int *master);
// Tell the terminal behind `master` the size of its window.
void hw_sys_pty_resize(int master, uint16_t rows, uint16_t cols);
// End a child of hw_sys_pty_spawn and reap it: hang up, and kill it if that did not end it at once.
void hw_sys_pty_end(pid_t pid);

// The operator's two signals, SIGUSR1 and SIGUSR2 where there are such: fn(1) is called for each
// SIGUSR1 sent to the process and fn(2) for each SIGUSR2, on a thread of its own that does
// nothing else, so fn may log or lock as any thread may and nothing is ever interrupted to run
// it. Two of one kind sent before the first is taken may come as one call. Call it once, before
// any other thread exists: the calling thread, and every thread it makes afterwards, has both
// signals blocked, and a thread made before would still die of one. 0, or -1 with errno
// (ENOTSUP where there are no such signals: Windows), and then nothing has changed.
int hw_sys_user_signals(void (*fn)(int which));

#endif

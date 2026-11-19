/*
 * holywisp/sys.h for Linux: every call here is the kernel's own.
 */
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/sys.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/uio.h>
#include <sys/wait.h>

int hw_sys_socket(int domain, int type, int protocol, int nonblock) {
	return socket(domain, type | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), protocol);
}

int hw_sys_accept(int listen_fd, struct sockaddr *addr, socklen_t *addr_len) {
	return accept4(listen_fd, addr, addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
}

void hw_sys_keepalive(int fd, int idle_s, int interval_s, int count) {
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_s, sizeof(idle_s));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_s, sizeof(interval_s));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
}

int hw_sys_listen_more(int first, const char *host, uint16_t port, int backlog) {
	return hw_listen_tcp(host, port, 1, backlog, NULL);
}

int hw_sys_relay_pipe(int fds[2], size_t want, size_t min, size_t *size) {
	if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) return -1;
	// Past fs.pipe-user-pages-soft the kernel hands out two-page pipes that cannot be enlarged.
	long sz = fcntl(fds[1], F_SETPIPE_SZ, (int)want);
	if (sz < (long)min) sz = fcntl(fds[1], F_SETPIPE_SZ, (int)min);
	if (sz < (long)min) {
		// EPERM is the same limit refusing an unprivileged resize outright: ENOBUFS, as promised.
		int saved = sz >= 0 || errno == EPERM ? ENOBUFS : errno;
		close(fds[0]);
		close(fds[1]);
		errno = saved;
		return -1;
	}
	*size = (size_t)sz;
	return 0;
}

ssize_t hw_sys_splice(int from, int to, size_t n) {
	return splice(from, NULL, to, NULL, n, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
}

int hw_sys_has_close_reset(void) {
	return 1;
}

int hw_sys_close_reset(int fd) {
	// SIOCOUTQ counts what the peer has not acknowledged, sent or not. A close with a zero linger
	// time resets the connection and discards exactly that, so it is asked for only at zero.
	int queued = 1;
	struct linger lg = {.l_onoff = 1, .l_linger = 0};
	int reset = ioctl(fd, SIOCOUTQ, &queued) == 0 && queued == 0 &&
	            setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)) == 0;
	close(fd);
	return reset;
}

int hw_sys_random(void *buf, size_t len) {
	uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = getrandom(p, len, 0);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

int hw_sys_has_udp_unreachable(void) {
	return 1;
}

int hw_sys_has_udp_steer(void) {
	return 1;
}

// A classic BPF program on the reuseport group (SO_ATTACH_REUSEPORT_CBPF, no capability needed).
// It runs with the UDP payload at offset 0 and returns the index of the socket to deliver to; an
// index past the group's end makes the kernel fall back to its hash (reuseport_select_sock). A
// load past the end of the datagram would end the program with 0, which is a valid index, so the
// length is checked first.
#define STEER_NONE 0xffffffffu

int hw_sys_udp_steer(const int fds[], size_t n) {
	if (n == 0) {
		errno = EINVAL;
		return -1;
	}
	// Jump offsets count from the instruction after the jump.
	struct sock_filter code[] = {
	    BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),            // 0: A = length
	    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 7, 0, 8),     // 1: under 7 bytes: 10
	    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),            // 2: A = first byte
	    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x80, 2, 0), // 3: long header: 6
	    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 1),            // 4: short header: A = DCID[0]
	    BPF_STMT(BPF_RET | BPF_A, 0),                     // 5
	    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 5),            // 6: A = DCID length
	    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 8, 0, 2),     // 7: not 8 bytes: 10
	    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6),            // 8: A = DCID[0]
	    BPF_STMT(BPF_RET | BPF_A, 0),                     // 9
	    BPF_STMT(BPF_RET | BPF_K, STEER_NONE),            // 10: the kernel's hash decides
	};
	struct sock_fprog prog = {.len = (unsigned short)HW_ARRAY_LEN(code), .filter = code};
	// The program belongs to the group, whichever member it is set on.
	return setsockopt(fds[0], SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof(prog));
}

// UDP_SEGMENT and UDP_GRO are Linux 4.18 and 5.0; a C library older than its kernel lacks the names.
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

// A run the kernel cuts up again: at most UDP_MAX_SEGMENTS (64 before Linux 6.9) datagrams, and
// at most what one UDP write may hold, which is a little under 64 KiB with the headers of either
// family; 65000 leaves room for both.
#define GSO_SEGMENTS_MAX 64
#define GSO_BYTES_MAX    65000

// Set once a write with UDP_SEGMENT has failed in a way that says the kernel or the device cannot
// do it at all (EIO: no checksum offload on the route; ENOPROTOOPT or EOPNOTSUPP: an old kernel).
// From then on every datagram is a write of its own, as everywhere else.
static _Atomic int g_gso_off;

int hw_sys_has_udp_gso(void) {
	return !g_gso_off;
}

int hw_sys_udp_gro(int fd) {
	int one = 1;
	return setsockopt(fd, SOL_UDP, UDP_GRO, &one, sizeof(one)) == 0;
}

// Room for one control message, aligned as one (a union with struct cmsghdr would be the usual
// way, but its flexible array member keeps it out of arrays).
typedef struct {
	_Alignas(struct cmsghdr) char buf[CMSG_SPACE(sizeof(int))];
} sys_cmsg_int;

typedef struct {
	_Alignas(struct cmsghdr) char buf[CMSG_SPACE(sizeof(uint16_t))];
} sys_cmsg_u16;

int hw_sys_recv_batch(int fd, hw_sys_dgram *d, size_t n) {
	struct mmsghdr mm[HW_SYS_BATCH_MAX];
	struct iovec iov[HW_SYS_BATCH_MAX];
	sys_cmsg_int ctl[HW_SYS_BATCH_MAX];
	if (n > HW_SYS_BATCH_MAX) n = HW_SYS_BATCH_MAX;
	memset(mm, 0, n * sizeof(mm[0]));
	for (size_t i = 0; i < n; i++) {
		iov[i].iov_base = d[i].buf;
		iov[i].iov_len = d[i].cap;
		mm[i].msg_hdr.msg_name = &d[i].addr;
		mm[i].msg_hdr.msg_namelen = sizeof(d[i].addr);
		mm[i].msg_hdr.msg_iov = &iov[i];
		mm[i].msg_hdr.msg_iovlen = 1;
		mm[i].msg_hdr.msg_control = ctl[i].buf;
		mm[i].msg_hdr.msg_controllen = sizeof(ctl[i].buf);
	}
	int r;
	do {
		r = recvmmsg(fd, mm, (unsigned)n, MSG_DONTWAIT, NULL);
	} while (r < 0 && errno == EINTR);
	for (int i = 0; i < r; i++) {
		struct msghdr *mh = &mm[i].msg_hdr;
		d[i].len = (mh->msg_flags & MSG_TRUNC) ? 0 : mm[i].msg_len;
		d[i].segment = d[i].len;
		d[i].addr_len = mh->msg_namelen;
		// The walk is written out: musl's CMSG_NXTHDR compares a size_t with a ptrdiff_t, which
		// -Wsign-compare makes an error in the static npm build. It counts the bytes left and
		// reads a header only when one fits in them: past the last message the buffer is
		// whatever the stack held, and a length read there once made a pointer that wrapped
		// round the end check and took the worker down.
		const char *p = (const char *)mh->msg_control;
		size_t left = mh->msg_controllen <= sizeof(ctl[i].buf) ? (size_t)mh->msg_controllen : 0;
		while (left >= sizeof(struct cmsghdr)) {
			struct cmsghdr cm;
			memcpy(&cm, p, sizeof(cm));
			if (cm.cmsg_len < sizeof(cm) || cm.cmsg_len > left) break;
			if (cm.cmsg_level == SOL_UDP && cm.cmsg_type == UDP_GRO && cm.cmsg_len >= CMSG_LEN(sizeof(int))) {
				int seg;
				memcpy(&seg, p + CMSG_LEN(0), sizeof(seg));
				if (seg > 0 && (size_t)seg < d[i].len) d[i].segment = (size_t)seg;
			}
			size_t step = CMSG_ALIGN(cm.cmsg_len);
			if (step >= left) break;
			p += step;
			left -= step;
		}
	}
	return r;
}

// How many datagrams from d[0] the kernel may take as one write: the same address, the same
// length, and the last of them no longer than the others, up to one that starts a run of its own;
// one that goes alone, by itself.
static size_t gso_run(const hw_sys_dgram *d, size_t n) {
	size_t seg = d[0].len, total = seg, k = 1;
	if (d[0].alone) return 1;
	while (k < n && k < GSO_SEGMENTS_MAX && !d[k].alone && !d[k].run_start && d[k].len <= seg && d[k].len > 0 &&
	       total + d[k].len <= GSO_BYTES_MAX && d[k].addr_len == d[0].addr_len &&
	       memcmp(&d[k].addr, &d[0].addr, d[0].addr_len) == 0) {
		total += d[k].len;
		k++;
		if (d[k - 1].len < seg) break; // a shorter one ends the run
	}
	return k;
}

static int send_batch(int fd, const hw_sys_dgram *d, size_t n, int gso) {
	struct mmsghdr mm[HW_SYS_BATCH_MAX];
	struct iovec iov[HW_SYS_BATCH_MAX];
	sys_cmsg_u16 ctl[HW_SYS_BATCH_MAX];
	size_t count[HW_SYS_BATCH_MAX]; // datagrams in each message
	size_t nmsg = 0;
	memset(mm, 0, n * sizeof(mm[0]));
	for (size_t i = 0; i < n;) {
		size_t k = gso && d[i].len > 0 ? gso_run(d + i, n - i) : 1;
		struct msghdr *mh = &mm[nmsg].msg_hdr;
		for (size_t j = 0; j < k; j++) {
			iov[i + j].iov_base = d[i + j].buf;
			iov[i + j].iov_len = d[i + j].len;
		}
		mh->msg_iov = &iov[i];
		mh->msg_iovlen = k;
		mh->msg_name = d[i].addr_len ? (void *)(uintptr_t)&d[i].addr : NULL; // sendmmsg does not write it
		mh->msg_namelen = d[i].addr_len;
		if (k > 1) {
			mh->msg_control = ctl[nmsg].buf;
			mh->msg_controllen = sizeof(ctl[nmsg].buf);
			struct cmsghdr *cm = CMSG_FIRSTHDR(mh);
			cm->cmsg_level = SOL_UDP;
			cm->cmsg_type = UDP_SEGMENT;
			cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
			uint16_t seg = (uint16_t)d[i].len;
			memcpy(CMSG_DATA(cm), &seg, sizeof(seg));
		}
		count[nmsg++] = k;
		i += k;
	}
	int r;
	do {
		r = sendmmsg(fd, mm, (unsigned)nmsg, MSG_DONTWAIT | MSG_NOSIGNAL);
	} while (r < 0 && errno == EINTR);
	if (r <= 0) return r < 0 ? -1 : 0;
	size_t sent = 0;
	for (size_t m = 0; m < (size_t)r && m < nmsg; m++) sent += count[m];
	return (int)sent;
}

int hw_sys_send_batch(int fd, const hw_sys_dgram *d, size_t n) {
	if (n > HW_SYS_BATCH_MAX) n = HW_SYS_BATCH_MAX;
	if (n == 0) return 0;
	int gso = !g_gso_off;
	int r = send_batch(fd, d, n, gso);
	if (r >= 0 || !gso || errno == EAGAIN || errno == EWOULDBLOCK) return r;
	// The first write failed. If it was a run, the run may be what failed (a path whose MTU is
	// under the segment size takes datagrams that size, refused only as a run: EINVAL), so it goes
	// again one datagram at a time, and only when the kernel cannot cut runs at all is that for good.
	if (gso_run(d, n) == 1) return r;
	int saved = errno;
	if (saved == EIO || saved == ENOPROTOOPT || saved == EOPNOTSUPP) g_gso_off = 1;
	return send_batch(fd, d, n, 0);
}

size_t hw_sys_udp_buffers(int fd, int bytes) {
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bytes, sizeof(bytes)) != 0) {
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
	}
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &bytes, sizeof(bytes)) != 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
	}
	int got = 0;
	socklen_t gl = sizeof(got);
	return getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &got, &gl) == 0 && got > 0 ? (size_t)got : 0;
}

int hw_sys_has_mark(void) {
	return 1;
}

int hw_sys_set_mark(int fd, uint32_t mark) {
	unsigned int v = mark;
	return setsockopt(fd, SOL_SOCKET, SO_MARK, &v, sizeof(v));
}

int hw_sys_has_crypt(void) {
	return 1;
}

int hw_sys_crypt(const char *key, const char *setting, char *out, size_t out_cap) {
	struct crypt_data data;
	memset(&data, 0, sizeof(data));
	const char *got = crypt_r(key, setting, &data);
	// A failure token ("*0", "*1") is not a hash: it must never compare equal to a stored value.
	if (!got || got[0] == '*') return -1;
	size_t n = strlen(got);
	if (n >= out_cap) return -1;
	memcpy(out, got, n + 1);
	return 0;
}

int hw_sys_has_pty(void) {
	return 1;
}

pid_t hw_sys_pty_spawn(char *const argv[], int *master) {
	pid_t pid = forkpty(master, NULL, NULL, NULL);
	if (pid < 0) return -1;
	if (pid == 0) {
		// The server ignores SIGPIPE and an ignored signal stays ignored across exec, where a
		// shell cannot even set it back: `yes | head` would never end.
		signal(SIGPIPE, SIG_DFL);
		setenv("TERM", "xterm-256color", 1);
		execvp(argv[0], argv);
		_exit(127); // exec failed; the master sees the end at once
	}
	if (hw_set_nonblock(*master) != 0 || hw_set_cloexec(*master) != 0) {
		int saved = errno;
		close(*master);
		hw_sys_pty_end(pid);
		errno = saved;
		return -1;
	}
	return pid;
}

void hw_sys_pty_resize(int master, uint16_t rows, uint16_t cols) {
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = rows;
	ws.ws_col = cols;
	ioctl(master, TIOCSWINSZ, &ws);
}

void hw_sys_pty_end(pid_t pid) {
	// A hang-up on its controlling terminal ends a shell promptly. What ignores it is killed: the
	// caller is a loop thread and cannot wait out a grace period.
	kill(pid, SIGHUP);
	if (waitpid(pid, NULL, WNOHANG) == 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
}

int hw_sys_udp_no_fragment(int fd) {
	// The family decides which option must take; a socket not bound yet has none to tell (Windows
	// refuses getsockname then), and takes whichever applies. A dual-stack socket's IPv4 datagrams
	// follow the IPv4 option, so an IPv6 socket gets both.
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	socklen_t sl = sizeof(ss);
	int family = getsockname(fd, (struct sockaddr *)&ss, &sl) == 0 ? ss.ss_family : AF_UNSPEC;
	int v4 = IP_PMTUDISC_PROBE, v6 = IPV6_PMTUDISC_PROBE;
	int r4 = setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, (const void *)&v4, sizeof(v4));
	if (family == AF_INET) return r4 == 0 ? 0 : -1;
	int r6 = setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, (const void *)&v6, sizeof(v6));
	if (family == AF_INET6) return r6 == 0 ? 0 : -1;
	return r4 == 0 || r6 == 0 ? 0 : -1;
}

int hw_sys_poll_us(struct pollfd *fds, nfds_t n, int64_t timeout_us) {
	if (timeout_us < 0) return ppoll(fds, n, NULL, NULL);
	struct timespec ts = {.tv_sec = (time_t)(timeout_us / 1000000), .tv_nsec = (long)(timeout_us % 1000000) * 1000};
	return ppoll(fds, n, &ts, NULL);
}

unsigned hw_sys_poll_resolution_us(void) {
	return 1;
}

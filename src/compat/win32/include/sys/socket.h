/*
 * <sys/socket.h> for Windows: the POSIX socket calls over Winsock, taking the descriptors of
 * posix.c and setting errno. See src/compat/win32/hw_w32.h.
 */
#ifndef HOLYWISP_COMPAT_SYS_SOCKET_H
#define HOLYWISP_COMPAT_SYS_SOCKET_H

#include <winsock2.h>
#include <ws2tcpip.h>

#include <sys/types.h>
#include <sys/uio.h>

struct msghdr {
	void *msg_name;
	socklen_t msg_namelen;
	struct iovec *msg_iov;
	size_t msg_iovlen;
	void *msg_control;
	size_t msg_controllen;
	int msg_flags;
};

// Not a Winsock flag: send and recv take it out and make that one call non-blocking.
#define MSG_DONTWAIT 0x40000000

#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

// Not a Winsock option: setsockopt answers ENOPROTOOPT. (Winsock's SO_REUSEADDR is not POSIX's
// either. It lets a second socket take a port that is in use, so setsockopt accepts it and does
// nothing: what POSIX means by it, rebinding a port whose old connections linger, Windows allows
// anyway.)
#define SO_REUSEPORT 0x7fff0001

int hw_w32_socket(int domain, int type, int protocol);
int hw_w32_accept(int fd, struct sockaddr *addr, socklen_t *len);
int hw_w32_bind(int fd, const struct sockaddr *addr, socklen_t len);
int hw_w32_connect(int fd, const struct sockaddr *addr, socklen_t len);
int hw_w32_listen(int fd, int backlog);
int hw_w32_shutdown(int fd, int how);
int hw_w32_getsockname(int fd, struct sockaddr *addr, socklen_t *len);
int hw_w32_getpeername(int fd, struct sockaddr *addr, socklen_t *len);
int hw_w32_getsockopt(int fd, int level, int name, void *value, socklen_t *len);
int hw_w32_setsockopt(int fd, int level, int name, const void *value, socklen_t len);
ssize_t hw_w32_send(int fd, const void *buf, size_t n, int flags);
ssize_t hw_w32_recv(int fd, void *buf, size_t n, int flags);
ssize_t hw_w32_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *to, socklen_t to_len);
ssize_t hw_w32_recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *from, socklen_t *from_len);
// Sends msg_iov to a connected socket; msg_name and msg_control are not supported.
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags);

#ifndef HW_W32_NO_MACROS
#define socket(domain, type, protocol)          hw_w32_socket((domain), (type), (protocol))
#define accept(fd, addr, len)                   hw_w32_accept((fd), (addr), (len))
#define bind(fd, addr, len)                     hw_w32_bind((fd), (addr), (len))
#define connect(fd, addr, len)                  hw_w32_connect((fd), (addr), (len))
#define listen(fd, backlog)                     hw_w32_listen((fd), (backlog))
#define shutdown(fd, how)                       hw_w32_shutdown((fd), (how))
#define getsockname(fd, addr, len)              hw_w32_getsockname((fd), (addr), (len))
#define getpeername(fd, addr, len)              hw_w32_getpeername((fd), (addr), (len))
#define getsockopt(fd, level, name, value, len) hw_w32_getsockopt((fd), (level), (name), (value), (len))
#define setsockopt(fd, level, name, value, len) hw_w32_setsockopt((fd), (level), (name), (value), (len))
#define send(fd, buf, n, flags)                 hw_w32_send((fd), (buf), (n), (flags))
#define recv(fd, buf, n, flags)                 hw_w32_recv((fd), (buf), (n), (flags))
#define sendto(fd, buf, n, flags, to, len)      hw_w32_sendto((fd), (buf), (n), (flags), (to), (len))
#define recvfrom(fd, buf, n, flags, from, len)  hw_w32_recvfrom((fd), (buf), (n), (flags), (from), (len))
#endif

#endif

// <netinet/tcp.h> for Windows. See src/compat/win32/hw_w32.h.
#ifndef HOLYWISP_COMPAT_NETINET_TCP_H
#define HOLYWISP_COMPAT_NETINET_TCP_H

#include <sys/socket.h>

// Windows 10 1709 and later; older headers do not name them.
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE 3
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT 16
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 17
#endif

#endif

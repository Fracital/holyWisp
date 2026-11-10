// <netdb.h> for Windows: getaddrinfo is Winsock's own. See src/compat/win32/hw_w32.h.
#ifndef HOLYWISP_COMPAT_NETDB_H
#define HOLYWISP_COMPAT_NETDB_H

#include <sys/socket.h>

// Winsock never returns it: its getaddrinfo has no errno to point at.
#ifndef EAI_SYSTEM
#define EAI_SYSTEM (-11)
#endif

#endif

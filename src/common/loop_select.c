/*
 * loop_backend.h on select(2), for Windows.
 *
 * Winsock's select is not the POSIX one: its fd_set is a counted array of sockets rather than a
 * bitmap, and the count is read from the set, so a set allocated with room for n sockets watches
 * n of them and FD_SETSIZE never comes into it. The poller keeps two such sets as its interest
 * (read, write), copies them before every wait, and passes the write set a second time as the
 * "exceptional" one, which is where Windows reports a connect that failed.
 *
 * WSAPoll would be the closer fit, but before Windows 10 2004 it never reports a failed connect
 * at all. Either one walks every socket on every wait. That is the cost of this port: it is here
 * so the server runs on a Windows development machine, as loop_kqueue.c is for a Mac.
 *
 * select answers with sockets, the loop wants its descriptors back with their generations, so
 * every watched socket has an entry found both ways: by descriptor (an array) and by socket (a
 * map). A socket with no interest is in neither set, and nothing is reported for it.
 */
#include "holywisp/hw.h"
#include "holywisp/loop.h"
#include "holywisp/map.h"

#include "hw_w32.h"
#include "loop_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

// Laid out as Winsock's fd_set, with as many sockets as were allocated.
typedef struct sock_set {
	u_int count;
	SOCKET sockets[];
} sock_set;

typedef struct entry {
	SOCKET sock;
	int fd;
	uint32_t gen;
	int rd_at; // position in the read set, -1 when not in it
	int wr_at;
} entry;

typedef struct poller {
	hw_w32_obj obj; // first: close(2) on the poller's descriptor ends up in poller_drop
	sock_set *rd, *wr;
	sock_set *rd_out, *wr_out, *ex_out; // what select is given, and overwrites
	u_int cap;                          // sockets each of the five has room for
	entry **by_fd;                      // indexed by fd - HW_W32_FD_BASE
	int by_fd_cap;
	hw_map by_sock;
	unsigned turn; // where the next wait starts reading its results
} poller;

static void poller_drop(hw_w32_obj *obj) {
	poller *p = (poller *)obj;
	for (int i = 0; i < p->by_fd_cap; i++) free(p->by_fd[i]);
	free(p->by_fd);
	hw_map_free(&p->by_sock);
	free(p->rd);
	free(p->wr);
	free(p->rd_out);
	free(p->wr_out);
	free(p->ex_out);
	free(p);
}

static poller *poller_of(int fd) {
	return (poller *)hw_w32_object_of(fd);
}

static int sets_reserve(poller *p, u_int need) {
	if (need <= p->cap) return 0;
	u_int cap = p->cap ? p->cap : 64;
	while (cap < need) cap *= 2;
	sock_set **sets[] = {&p->rd, &p->wr, &p->rd_out, &p->wr_out, &p->ex_out};
	for (size_t i = 0; i < sizeof(sets) / sizeof(sets[0]); i++) {
		sock_set *grown = realloc(*sets[i], sizeof(sock_set) + (size_t)cap * sizeof(SOCKET));
		if (!grown) {
			errno = ENOMEM;
			return -1; // the ones already grown are merely bigger than cap says
		}
		if (!*sets[i]) grown->count = 0;
		*sets[i] = grown;
	}
	p->cap = cap;
	return 0;
}

int hw_poller_open(void) {
	poller *p = calloc(1, sizeof(*p));
	if (!p) return -1;
	p->obj.drop = poller_drop;
	hw_map_init(&p->by_sock);
	if (sets_reserve(p, 64) != 0) {
		poller_drop(&p->obj);
		errno = ENOMEM;
		return -1;
	}
	int fd = hw_w32_object(&p->obj);
	if (fd < 0) {
		int saved = errno;
		poller_drop(&p->obj);
		errno = saved;
	}
	return fd;
}

int hw_poller_wake_open(int fds[2]) {
	if (hw_w32_pair(fds) != 0) return -1;
	if (hw_set_nonblock(fds[0]) != 0 || hw_set_nonblock(fds[1]) != 0) {
		int saved = errno;
		close(fds[0]);
		close(fds[1]);
		errno = saved;
		return -1;
	}
	return 0;
}

static void set_add(sock_set *set, int *at, SOCKET sock) {
	*at = (int)set->count;
	set->sockets[set->count++] = sock;
}

// Take a socket out of the interest set `set` (p->rd when `is_read`), moving the last one into
// its place.
static void set_remove(poller *p, sock_set *set, int is_read, int *at) {
	u_int last = set->count - 1;
	if ((u_int)*at != last) {
		SOCKET moved = set->sockets[last];
		set->sockets[*at] = moved;
		entry *other = hw_map_get(&p->by_sock, (uint32_t)moved);
		if (other) *(is_read ? &other->rd_at : &other->wr_at) = *at;
	}
	set->count = last;
	*at = -1;
}

static void entry_forget(poller *p, entry *e) {
	if (e->rd_at >= 0) set_remove(p, p->rd, 1, &e->rd_at);
	if (e->wr_at >= 0) set_remove(p, p->wr, 0, &e->wr_at);
	if (hw_map_get(&p->by_sock, (uint32_t)e->sock) == e) hw_map_remove(&p->by_sock, (uint32_t)e->sock);
	p->by_fd[e->fd - HW_W32_FD_BASE] = NULL;
	free(e);
}

static entry *entry_of(const poller *p, int fd) {
	int index = fd - HW_W32_FD_BASE;
	return index >= 0 && index < p->by_fd_cap ? p->by_fd[index] : NULL;
}

static entry *entry_new(poller *p, int fd) {
	SOCKET sock = hw_w32_sock(fd);
	if (sock == INVALID_SOCKET) return NULL;
	int index = fd - HW_W32_FD_BASE;
	if (index >= p->by_fd_cap) {
		int cap = p->by_fd_cap ? p->by_fd_cap : 64;
		while (cap <= index) cap *= 2;
		entry **grown = realloc(p->by_fd, (size_t)cap * sizeof(*grown));
		if (!grown) {
			errno = ENOMEM;
			return NULL;
		}
		memset(grown + p->by_fd_cap, 0, (size_t)(cap - p->by_fd_cap) * sizeof(*grown));
		p->by_fd = grown;
		p->by_fd_cap = cap;
	}
	// A socket that was closed while still watched leaves its entry behind, and Windows gives the
	// handle's number to the next socket: whatever is filed under it belongs to the dead one.
	entry *stale = hw_map_get(&p->by_sock, (uint32_t)sock);
	if (stale) entry_forget(p, stale);
	entry *e = calloc(1, sizeof(*e));
	if (!e || hw_map_put(&p->by_sock, (uint32_t)sock, e) != 0) {
		free(e);
		errno = ENOMEM;
		return NULL;
	}
	e->sock = sock;
	e->fd = fd;
	e->rd_at = -1;
	e->wr_at = -1;
	p->by_fd[index] = e;
	return e;
}

int hw_poller_set(int poller_fd, int fd, int fresh, unsigned old, unsigned events, uint32_t gen) {
	poller *p = poller_of(poller_fd);
	if (!p) return -1;
	entry *e = entry_of(p, fd);
	if (e && fresh) {
		entry_forget(p, e); // the descriptor was closed without being removed, and is in use again
		e = NULL;
	}
	if (!e) {
		e = entry_new(p, fd);
		if (!e) return -1;
	}
	if (sets_reserve(p, (p->rd->count > p->wr->count ? p->rd->count : p->wr->count) + 1) != 0) return -1;
	e->gen = gen;
	if ((events & HW_EV_READ) && e->rd_at < 0) set_add(p->rd, &e->rd_at, e->sock);
	if (!(events & HW_EV_READ) && e->rd_at >= 0) set_remove(p, p->rd, 1, &e->rd_at);
	if ((events & HW_EV_WRITE) && e->wr_at < 0) set_add(p->wr, &e->wr_at, e->sock);
	if (!(events & HW_EV_WRITE) && e->wr_at >= 0) set_remove(p, p->wr, 0, &e->wr_at);
	return 0;
}

void hw_poller_del(int poller_fd, int fd, unsigned events) {
	poller *p = poller_of(poller_fd);
	entry *e = p ? entry_of(p, fd) : NULL;
	if (e) entry_forget(p, e);
}

static void set_copy(sock_set *to, const sock_set *from) {
	to->count = from->count;
	memcpy(to->sockets, from->sockets, (size_t)from->count * sizeof(SOCKET));
}

// Report the sockets select left in `set`. A full batch drops the rest: readiness is a level, and
// the next wait starts one further along, so no socket is always the one left out.
static int collect(poller *p, const sock_set *set, unsigned event, hw_poll_event *out, int n, int max) {
	for (u_int i = 0; i < set->count && n < max; i++) {
		const entry *e = hw_map_get(&p->by_sock, (uint32_t)set->sockets[(i + p->turn) % set->count]);
		if (!e) continue;
		out[n].fd = e->fd;
		out[n].gen = e->gen;
		out[n].events = event;
		n++;
	}
	return n;
}

// select refused the sets because one socket in them is closed. Find those and report each as an
// error, which is what its owner needs to hear.
static int report_closed(poller *p, hw_poll_event *out, int max) {
	int n = 0;
	for (int i = 0; i < p->by_fd_cap && n < max; i++) {
		entry *e = p->by_fd[i];
		if (!e || (e->rd_at < 0 && e->wr_at < 0)) continue;
		int type = 0;
		socklen_t len = sizeof(type);
		if (getsockopt(e->fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0) continue;
		out[n].fd = e->fd;
		out[n].gen = e->gen;
		out[n].events = HW_EV_ERROR;
		n++;
		if (e->rd_at >= 0) set_remove(p, p->rd, 1, &e->rd_at);
		if (e->wr_at >= 0) set_remove(p, p->wr, 0, &e->wr_at);
	}
	return n;
}

int hw_poller_wait(int poller_fd, hw_poll_event *out, int max, int timeout_ms) {
	poller *p = poller_of(poller_fd);
	if (!p) return -1;
	if (p->rd->count == 0 && p->wr->count == 0) {
		// select with nothing to watch is an error here, not a sleep.
		if (timeout_ms != 0) Sleep(timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);
		return 0;
	}
	set_copy(p->rd_out, p->rd);
	set_copy(p->wr_out, p->wr);
	set_copy(p->ex_out, p->wr);
	struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
	int r = select(0, p->rd_out->count ? (fd_set *)p->rd_out : NULL, p->wr_out->count ? (fd_set *)p->wr_out : NULL,
	               p->ex_out->count ? (fd_set *)p->ex_out : NULL, timeout_ms < 0 ? NULL : &tv);
	if (r == SOCKET_ERROR) {
		if (WSAGetLastError() == WSAENOTSOCK) return report_closed(p, out, max);
		return hw_w32_fail();
	}
	if (r == 0) return 0;
	p->turn++;
	int n = collect(p, p->ex_out, HW_EV_ERROR, out, 0, max);
	n = collect(p, p->rd_out, HW_EV_READ, out, n, max);
	return collect(p, p->wr_out, HW_EV_WRITE, out, n, max);
}

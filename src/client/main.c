/*
 * holywisp-client: netcat through a Wisp server, plus an echo benchmark.
 *
 *   holywisp-client [-s ws://host:port/path] [--udp] [--v2] HOST PORT      stdin/stdout <-> HOST:PORT
 *   holywisp-client [-s ...] --bench BYTES HOST PORT                        echo throughput test
 */
#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/wisp.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PIPE_CHUNK (64 * 1024)
#define MOTD_SHOWN (4 * 511 + 1) // the longest MOTD the client keeps, every byte of it escaped

static void usage(const char *argv0) {
	fprintf(stderr,
	        "usage: %s [options] HOST PORT\n"
	        "\n"
	        "Relay stdin/stdout to HOST:PORT through a Wisp server.\n"
	        "\n"
	        "  -s, --server URL     ws://host:port/path (default ws://127.0.0.1:6001/)\n"
	        "  -u, --udp            open a UDP stream instead of TCP\n"
	        "  -2, --v2             negotiate wisp-v2\n"
	        "      --user U         v2 password auth username (with --pass)\n"
	        "      --pass P\n"
	        "      --confirm        v2: ask for a CONTINUE when the stream connects\n"
	        "      --idle-ms N      after stdin EOF, exit when nothing arrives for N ms (2000)\n"
	        "      --bench BYTES    send BYTES to an echo service at HOST:PORT and report throughput\n"
	        "  -v, --verbose        print events on stderr\n"
	        "  -h, --help\n",
	        argv0);
}

static int parse_url(const char *url, char *host, size_t host_cap, uint16_t *port, char *path, size_t path_cap) {
	const char *p = url;
	if (strncmp(p, "ws://", 5) == 0) {
		p += 5;
	} else if (strncmp(p, "wss://", 6) == 0) {
		fprintf(stderr, "wss:// is not supported; terminate TLS in front of the server\n");
		return -1;
	}
	const char *slash = strchr(p, '/');
	size_t hp_len = slash ? (size_t)(slash - p) : strlen(p);
	const char *path_src = slash ? slash : "/";
	if (hp_len >= host_cap || strlen(path_src) >= path_cap) return -1;
	memcpy(path, path_src, strlen(path_src) + 1);
	char hp[256];
	memcpy(hp, p, hp_len);
	hp[hp_len] = '\0';
	*port = 80;
	char *colon;
	if (hp[0] == '[') {
		char *close = strchr(hp, ']');
		if (!close) return -1;
		*close = '\0';
		memcpy(host, hp + 1, strlen(hp + 1) + 1);
		colon = close[1] == ':' ? close + 1 : NULL;
	} else {
		colon = strrchr(hp, ':');
		if (colon) *colon = '\0';
		memcpy(host, hp, strlen(hp) + 1);
	}
	if (colon) {
		long n = strtol(colon + 1, NULL, 10);
		if (n <= 0 || n > 65535) return -1;
		*port = (uint16_t)n;
	}
	return 0;
}

static int g_verbose;

static void log_event(const hw_client_event *ev) {
	if (!g_verbose) return;
	switch (ev->type) {
	case HW_CEV_DATA:
		fprintf(stderr, "[stream %u] DATA %zu bytes\n", ev->stream_id, ev->len);
		break;
	case HW_CEV_CLOSE:
		fprintf(stderr, "[stream %u] CLOSE %s (0x%02x)\n", ev->stream_id, hw_close_reason_str(ev->reason), ev->reason);
		break;
	case HW_CEV_CONTINUE:
		fprintf(stderr, "[stream %u] CONTINUE %u\n", ev->stream_id, ev->buffer_remaining);
		break;
	default:
		break;
	}
}

static int write_all(int fd, const uint8_t *p, size_t n) {
	while (n > 0) {
		ssize_t w = write(fd, p, n);
		if (w < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

// Why a send failed, for the user.
static const char *send_error(int r) {
	switch (r) {
	case HW_ERR_TIMEOUT:
		return "no CONTINUE from the server in time";
	case HW_ERR_TOOBIG:
		return "the server sent more than the client may queue while it waited for a CONTINUE";
	default:
		return "stream closed";
	}
}

// Write what has arrived to stdout, without waiting. 0 to go on; 1 when the relay is over, with
// the exit code in *rc.
static int pipe_drain(hw_client *c, uint32_t sid, int *rc) {
	hw_client_event ev;
	int r;
	while ((r = hw_client_poll(c, 0, &ev)) > 0) {
		log_event(&ev);
		if (ev.type == HW_CEV_DATA && ev.stream_id == sid) {
			if (write_all(STDOUT_FILENO, ev.data, ev.len) != 0) {
				*rc = 1;
				return 1;
			}
		} else if (ev.type == HW_CEV_CLOSE && (ev.stream_id == sid || ev.stream_id == 0)) {
			*rc = ev.reason == HW_CLOSE_VOLUNTARY ? 0 : 1;
			return 1;
		}
	}
	if (r < 0) {
		fprintf(stderr, "connection closed\n");
		*rc = 1;
		return 1;
	}
	return 0;
}

static int run_pipe(hw_client *c, uint32_t sid, int idle_ms) {
	uint8_t buf[PIPE_CHUNK];
	int stdin_open = 1;
	int rc;
	for (;;) {
		struct pollfd pfds[2] = {{.fd = hw_client_fd(c), .events = POLLIN}, {.fd = STDIN_FILENO, .events = POLLIN}};
		int r = poll(pfds, stdin_open ? 2 : 1, stdin_open ? -1 : idle_ms);
		if (r < 0 && errno == EINTR) continue;
		if (r < 0) return 1;
		if (r == 0) return 0; // idle after EOF
		if (stdin_open && (pfds[1].revents & (POLLIN | POLLHUP))) {
			ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n <= 0) {
				stdin_open = 0;
			} else {
				// A send that timed out sent nothing. The server holds its CONTINUE for as long as
				// the remote is slow to take what it has, so like any pipe this one waits: it
				// writes out what arrived meanwhile and offers the same bytes again.
				while ((r = hw_client_send(c, sid, buf, (size_t)n)) == HW_ERR_TIMEOUT) {
					if (g_verbose) fprintf(stderr, "[stream %u] still waiting for a CONTINUE\n", sid);
					if (pipe_drain(c, sid, &rc)) return rc;
				}
				if (r != 0) {
					fprintf(stderr, "send failed: %s\n", send_error(r));
					return 1;
				}
			}
		}
		if (pfds[0].revents && pipe_drain(c, sid, &rc)) return rc;
	}
}

static int run_bench(hw_client *c, uint32_t sid, size_t total) {
	uint8_t *chunk = malloc(PIPE_CHUNK);
	if (!chunk) return 1;
	for (size_t i = 0; i < PIPE_CHUNK; i++) chunk[i] = (uint8_t)(i * 31 + 7);
	uint64_t start = hw_now_ms();
	size_t sent = 0, received = 0;
	uint64_t sum_sent = 0, sum_recv = 0;
	while (received < total) {
		if (sent < total) {
			size_t n = HW_MIN(PIPE_CHUNK, total - sent);
			int s = hw_client_send(c, sid, chunk, n);
			if (s != 0) {
				fprintf(stderr, "send failed at %zu bytes: %s\n", sent, send_error(s));
				free(chunk);
				return 1;
			}
			for (size_t i = 0; i < n; i++) sum_sent += chunk[i];
			sent += n;
		}
		hw_client_event ev;
		int r;
		while ((r = hw_client_poll(c, sent < total ? 0 : 10000, &ev)) > 0) {
			if (ev.type == HW_CEV_DATA && ev.stream_id == sid) {
				for (size_t i = 0; i < ev.len; i++) sum_recv += ev.data[i];
				received += ev.len;
			} else if (ev.type == HW_CEV_CLOSE) {
				fprintf(stderr, "stream closed: %s\n", hw_close_reason_str(ev.reason));
				free(chunk);
				return 1;
			}
			if (received >= total) break;
		}
		if (r < 0 || (r == 0 && sent >= total)) {
			fprintf(stderr, "%s after %zu/%zu bytes\n", r < 0 ? "connection lost" : "timed out", received, total);
			free(chunk);
			return 1;
		}
	}
	uint64_t ms = hw_now_ms() - start;
	if (ms == 0) ms = 1;
	double mb = (double)total / (1024.0 * 1024.0);
	printf("%zu bytes echoed in %llu ms: %.1f MiB/s each way, checksum %s\n", total, (unsigned long long)ms,
	       mb / ((double)ms / 1000.0), sum_sent == sum_recv ? "ok" : "MISMATCH");
	free(chunk);
	return sum_sent == sum_recv ? 0 : 1;
}

int main(int argc, char **argv) {
	const char *url = "ws://127.0.0.1:6001/";
	int udp = 0;
	int idle_ms = 2000;
	size_t bench = 0;
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	const char *positional[2] = {NULL, NULL};
	int npos = 0;
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage(argv[0]);
			return 0;
		} else if ((!strcmp(a, "-s") || !strcmp(a, "--server")) && i + 1 < argc) {
			url = argv[++i];
		} else if (!strcmp(a, "-u") || !strcmp(a, "--udp")) {
			udp = 1;
		} else if (!strcmp(a, "-2") || !strcmp(a, "--v2")) {
			o.v2 = 1;
		} else if (!strcmp(a, "--user") && i + 1 < argc) {
			o.user = argv[++i];
			o.v2 = 1;
		} else if (!strcmp(a, "--pass") && i + 1 < argc) {
			o.pass = argv[++i];
		} else if (!strcmp(a, "--confirm")) {
			o.stream_confirm = 1;
			o.v2 = 1;
		} else if (!strcmp(a, "--idle-ms") && i + 1 < argc) {
			idle_ms = (int)strtol(argv[++i], NULL, 10);
		} else if (!strcmp(a, "--bench") && i + 1 < argc) {
			bench = (size_t)strtoull(argv[++i], NULL, 10);
		} else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
			g_verbose = 1;
		} else if (a[0] == '-' && a[1]) {
			fprintf(stderr, "unknown option %s\n", a);
			usage(argv[0]);
			return 2;
		} else if (npos < 2) {
			positional[npos++] = a;
		} else {
			usage(argv[0]);
			return 2;
		}
	}
	if (npos != 2) {
		usage(argv[0]);
		return 2;
	}
	char host[256], path[256];
	uint16_t port;
	if (parse_url(url, host, sizeof(host), &port, path, sizeof(path)) != 0) {
		fprintf(stderr, "bad server URL: %s\n", url);
		return 2;
	}
	long target_port = strtol(positional[1], NULL, 10);
	if (target_port <= 0 || target_port > 65535) {
		fprintf(stderr, "bad port: %s\n", positional[1]);
		return 2;
	}
	o.host = host;
	o.port = port;
	o.path = path;

	char err[512];
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	if (!c) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}
	if (o.user && o.pass && !hw_client_authenticated(c)) {
		fprintf(stderr, "warning: the server did not ask for a password, so none was sent: not authenticated\n");
	}
	if (g_verbose) {
		// The MOTD is the server's bytes; this is the user's terminal.
		const char *motd = hw_client_motd(c);
		char shown[MOTD_SHOWN];
		hw_client_printable(shown, sizeof(shown), motd, strlen(motd));
		fprintf(stderr, "connected: wisp-v%d, window %u%s%s\n", hw_client_is_v2(c) ? 2 : 1, hw_client_buffer_size(c),
		        shown[0] ? ", motd: " : "", shown);
	}
	uint32_t sid;
	int opened = hw_client_open(c, udp ? HW_STREAM_UDP : HW_STREAM_TCP, positional[0], (uint16_t)target_port, &sid);
	if (opened != 0) {
		fprintf(stderr, "%s\n",
		        opened == HW_ERR_INVALID ? "bad host: a hostname is 1 to 255 bytes" : "cannot open stream");
		hw_client_free(c);
		return 1;
	}
	int rc = bench ? run_bench(c, sid, bench) : run_pipe(c, sid, idle_ms);
	hw_client_free(c);
	return rc;
}

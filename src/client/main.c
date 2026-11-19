/*
 * holywisp-client: netcat through a Wisp server, plus an echo benchmark.
 *
 *   holywisp-client [-s ws://host:port/path] [--udp] [--v2] HOST PORT      stdin/stdout <-> HOST:PORT
 *   holywisp-client [-s ...] --bench BYTES HOST PORT                        echo throughput test
 *   holywisp-client -s https://host:port/ --pin SHA256 ...                  the same over WebTransport
 */
#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/sys.h"
#include "holywisp/wisp.h"

#include <errno.h>
#include <limits.h>
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
	        "  -s, --server URL     ws://host:port/path (default ws://127.0.0.1:6001/), or\n"
	        "                       https://host:port/path for WebTransport (UDP; port 443 by default)\n"
	        "      --pin HASH       WebTransport: the server certificate's SHA-256, base64 or hex\n"
	        "                       (a value of the server's /webtransport.json)\n"
	        "      --insecure       WebTransport: take any certificate (loopback tests only)\n"
	        "      --origin ORIGIN  WebTransport: send this origin header\n"
	        "      --connect-to A   WebTransport: connect to address or name A, the URL's host still\n"
	        "                       the SNI and :authority (as curl's --connect-to)\n"
	        "  -u, --udp            open a UDP stream instead of TCP\n"
	        "  -2, --v2             negotiate wisp-v2\n"
	        "      --user U         v2 password auth username (with --pass)\n"
	        "      --pass P\n"
	        "      --confirm        v2: ask for a CONTINUE when the stream connects\n"
	        "      --idle-ms N      after stdin EOF, exit when nothing arrives for N ms (2000)\n"
	        "      --bench BYTES    send BYTES to an echo service at HOST:PORT and report throughput\n"
	        "      --streams N      with --bench: over N streams at once, BYTES split among them (1)\n"
	        "      --server-stream  WebTransport v2: have the server open the Wisp stream and send its\n"
	        "                       CONTINUE at once (offers \"wisp-v2-server-stream\")\n"
	        "      --lanes N        WebTransport v2: ride up to N QUIC streams (lanes) when the server\n"
	        "                       offers them, the first included; at most 16 (1)\n"
	        "      --credit BYTES   v2: ask for stream credit with an initial window of BYTES per\n"
	        "                       stream (at least 16384): the server sends each stream only what\n"
	        "                       this client has read, and a window more (off)\n"
	        "      --read-rate BPS  read what arrives no faster than BPS bytes a second, a slow\n"
	        "                       reader; with --credit the server is held to that rate (off)\n"
	        "      --udp-buffer N   WebTransport: the UDP socket's buffers in bytes (4 MiB); 212992 is\n"
	        "                       a browser's on a Linux of stock settings\n"
	        "  -v, --verbose        print events on stderr\n"
	        "  -h, --help\n",
	        argv0);
}

static int parse_url(const char *url, char *host, size_t host_cap, uint16_t *port, char *path, size_t path_cap,
                     int *webtransport) {
	const char *p = url;
	*webtransport = 0;
	if (strncmp(p, "ws://", 5) == 0) {
		p += 5;
	} else if (strncmp(p, "https://", 8) == 0) {
		p += 8;
		*webtransport = 1;
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
	*port = *webtransport ? 443 : 80;
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

// A certificate hash as /webtransport.json gives it (base64) or as sha256sum prints it (hex).
static int parse_pin(const char *s, uint8_t out[32]) {
	size_t n = strlen(s);
	if (n == 64) {
		static const char hex[] = "0123456789abcdef0123456789ABCDEF";
		for (size_t i = 0; i < 64; i++) {
			const char *q = s[i] ? strchr(hex, s[i]) : NULL;
			if (!q) return -1;
			int v = (int)(q - hex) & 15;
			if (i % 2 == 0) {
				out[i / 2] = (uint8_t)(v << 4);
			} else {
				out[i / 2] |= (uint8_t)v;
			}
		}
		return 0;
	}
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint32_t acc = 0;
	int bits = 0;
	size_t got = 0;
	for (size_t i = 0; i < n && s[i] != '='; i++) {
		const char *q = strchr(b64, s[i]);
		if (!q || !s[i]) return -1;
		acc = acc << 6 | (uint32_t)(q - b64);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (got == 32) return -1;
			out[got++] = (uint8_t)(acc >> bits);
		}
	}
	return got == 32 ? 0 : -1;
}

static int g_verbose;

// --read-rate: the reader takes no more than this many bytes a second, counted from its first.
static uint64_t g_read_rate;
static uint64_t g_read_start;
static uint64_t g_read_bytes;

// How long the reader must wait before it may take anything more: 0 when it may now.
static int read_wait_ms(void) {
	if (!g_read_rate) return 0;
	uint64_t now = hw_now_ms();
	if (!g_read_start) g_read_start = now;
	uint64_t due = g_read_start + g_read_bytes * 1000 / g_read_rate;
	return due > now ? (int)HW_MIN(due - now, (uint64_t)INT_MAX) : 0;
}

static void read_count(size_t n) {
	g_read_bytes += n;
}

static void sleep_ms(int ms) {
	struct pollfd none;
	poll(&none, 0, ms);
}

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
	int r = 0;
	// A reader ahead of --read-rate takes nothing, and the client grants nothing, until it is due.
	while (read_wait_ms() == 0 && (r = hw_client_poll(c, 0, &ev)) > 0) {
		log_event(&ev);
		if (ev.type == HW_CEV_DATA) read_count(ev.len);
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
	uint64_t idle_at = 0; // after stdin's EOF: when to stop if nothing has arrived
	for (;;) {
		struct pollfd pfds[2] = {{.fd = hw_client_fd(c), .events = POLLIN}, {.fd = STDIN_FILENO, .events = POLLIN}};
		int64_t wait = -1;
		if (!stdin_open) {
			uint64_t now = hw_now_ms();
			if (now >= idle_at) return 0; // idle after EOF
			wait = (int64_t)HW_MIN(idle_at - now, (uint64_t)INT_MAX) * 1000;
		}
		// Over WebTransport the client's timers run only when it is called, and its pacer's are
		// microseconds away.
		int64_t timers = hw_client_wait_us(c);
		if (timers >= 0 && (wait < 0 || timers < wait)) wait = timers;
		// A reader that is ahead of --read-rate does not look at the server until it is due.
		int64_t paced = (int64_t)read_wait_ms() * 1000;
		if (paced > 0) {
			pfds[0].fd = -1;
			if (wait < 0 || paced < wait) wait = paced;
		}
		int r = hw_sys_poll_us(pfds, stdin_open ? 2 : 1, wait);
		if (r < 0 && errno == EINTR) continue;
		if (r < 0) return 1;
		if (r == 0) {
			if (pipe_drain(c, sid, &rc)) return rc;
			continue;
		}
		if (stdin_open && (pfds[1].revents & (POLLIN | POLLHUP))) {
			ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n <= 0) {
				stdin_open = 0;
				idle_at = hw_now_ms() + (uint64_t)(idle_ms > 0 ? idle_ms : 0);
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
		if (pfds[0].revents) {
			if (!stdin_open) idle_at = hw_now_ms() + (uint64_t)(idle_ms > 0 ? idle_ms : 0);
			if (pipe_drain(c, sid, &rc)) return rc;
		}
	}
}

// The sum of n bytes, the bench's checksum, which is where the client spends its time: eight
// bytes a step as four 16-bit lanes per half word, folded before a lane can overflow (256 words
// add at most 255 * 256 to one), so no compiler has to vectorize it for the bench to measure the
// server rather than this loop.
static uint64_t byte_sum(const uint8_t *p, size_t n) {
	const uint64_t lo = 0x00ff00ff00ff00ffull;
	uint64_t sum = 0;
	size_t i = 0;
	while (n - i >= 8) {
		size_t words = HW_MIN((n - i) / 8, (size_t)256);
		uint64_t a = 0, b = 0;
		for (size_t k = 0; k < words; k++, i += 8) {
			uint64_t w;
			memcpy(&w, p + i, 8);
			a += w & lo;
			b += (w >> 8) & lo;
		}
		for (int k = 0; k < 4; k++) sum += ((a >> (16 * k)) & 0xffff) + ((b >> (16 * k)) & 0xffff);
	}
	for (; i < n; i++) sum += p[i];
	return sum;
}

// The index of stream id among the bench's streams, which were opened in a row: nsid when it is
// none of them.
static size_t bench_index(const uint32_t *sid, size_t nsid, uint32_t id) {
	size_t k = id - sid[0];
	if (k < nsid && sid[k] == id) return k;
	for (k = 0; k < nsid; k++) {
		if (sid[k] == id) break;
	}
	return k;
}

// The echo benchmark over nsid streams at once, total bytes split among them: each stream sends
// a chunk in turn, and what has come back is taken between the sends. With stream credit a
// stream has at most half a window in flight: the server sends a stream no more than a window
// past what was taken, and an echo that cannot come back would hold the CONTINUE the next send
// waits for while nothing is taken.
static int run_bench(hw_client *c, const uint32_t *sid, size_t nsid, size_t total) {
	uint8_t *chunk = malloc(PIPE_CHUNK);
	size_t *sent = calloc(nsid, sizeof(*sent));
	size_t *recv = calloc(nsid, sizeof(*recv));
	if (!chunk || !sent || !recv) {
		free(chunk);
		free(sent);
		free(recv);
		return 1;
	}
	size_t ahead = hw_client_credit_window(c) / 2; // 0: no bound
	for (size_t i = 0; i < PIPE_CHUNK; i++) chunk[i] = (uint8_t)(i * 31 + 7);
	size_t per = total / nsid;
	total = per * nsid;
	uint64_t start = hw_now_ms();
	size_t sent_all = 0, received = 0;
	uint64_t sum_sent = 0, sum_recv = 0;
	int rc = 1;
	while (received < total) {
		int more = 0; // a stream may send more now
		for (size_t k = 0; k < nsid; k++) {
			if (sent[k] >= per) continue;
			size_t n = HW_MIN(PIPE_CHUNK, per - sent[k]);
			if (ahead) {
				size_t out = sent[k] - recv[k];
				if (out >= ahead) continue;
				n = HW_MIN(n, ahead - out);
			}
			more = 1;
			int s = hw_client_send(c, sid[k], chunk, n);
			if (s != 0) {
				fprintf(stderr, "send failed at %zu bytes: %s\n", sent_all, send_error(s));
				goto done;
			}
			sum_sent += byte_sum(chunk, n);
			sent[k] += n;
			sent_all += n;
		}
		hw_client_event ev;
		int r = 1;
		int wait = sent_all < total && more ? 0 : 10000;
		for (;;) {
			int paced = read_wait_ms();
			if (paced > 0) { // ahead of --read-rate: take nothing until it is due
				sleep_ms(HW_MIN(paced, 50));
				break;
			}
			r = hw_client_poll(c, wait, &ev);
			if (r <= 0) break;
			wait = 0; // something came: go back and send what that let go before waiting again
			if (ev.type == HW_CEV_DATA) {
				sum_recv += byte_sum(ev.data, ev.len);
				received += ev.len;
				read_count(ev.len);
				size_t k = bench_index(sid, nsid, ev.stream_id);
				if (k < nsid) recv[k] += ev.len;
			} else if (ev.type == HW_CEV_CLOSE) {
				fprintf(stderr, "stream closed: %s\n", hw_close_reason_str(ev.reason));
				goto done;
			}
			if (received >= total) break;
		}
		if (r < 0 || (r == 0 && wait > 0)) {
			fprintf(stderr, "%s after %zu/%zu bytes\n", r < 0 ? "connection lost" : "timed out", received, total);
			goto done;
		}
	}
	uint64_t ms = hw_now_ms() - start;
	if (ms == 0) ms = 1;
	double mb = (double)total / (1024.0 * 1024.0);
	printf("%zu bytes echoed in %llu ms: %.1f MiB/s each way, checksum %s\n", total, (unsigned long long)ms,
	       mb / ((double)ms / 1000.0), sum_sent == sum_recv ? "ok" : "MISMATCH");
	rc = sum_sent == sum_recv ? 0 : 1;
done:
	free(chunk);
	free(sent);
	free(recv);
	return rc;
}

int main(int argc, char **argv) {
	const char *url = "ws://127.0.0.1:6001/";
	int udp = 0;
	int idle_ms = 2000;
	size_t bench = 0;
	long streams = 1;
	int insecure = 0;
	const char *pin = NULL;
	const char *connect_to = NULL;
	uint8_t pin_hash[32];
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
		} else if (!strcmp(a, "--streams") && i + 1 < argc) {
			streams = strtol(argv[++i], NULL, 10);
		} else if (!strcmp(a, "--server-stream")) {
			o.wt_server_stream = 1;
			o.v2 = 1;
		} else if (!strcmp(a, "--lanes") && i + 1 < argc) {
			o.wt_lanes = (int)strtol(argv[++i], NULL, 10);
			o.v2 = 1;
		} else if (!strcmp(a, "--credit") && i + 1 < argc) {
			unsigned long long w = strtoull(argv[++i], NULL, 10);
			if (w == 0 || w > UINT32_MAX) {
				fprintf(stderr, "--credit is 1 to %u bytes\n", UINT32_MAX);
				return 2;
			}
			o.credit_window = (uint32_t)w;
			o.v2 = 1;
		} else if (!strcmp(a, "--read-rate") && i + 1 < argc) {
			g_read_rate = strtoull(argv[++i], NULL, 10);
			if (g_read_rate == 0) {
				fprintf(stderr, "--read-rate is a number of bytes a second\n");
				return 2;
			}
		} else if (!strcmp(a, "--pin") && i + 1 < argc) {
			pin = argv[++i];
		} else if (!strcmp(a, "--udp-buffer") && i + 1 < argc) {
			o.wt_udp_buffer = (size_t)strtoull(argv[++i], NULL, 10);
		} else if (!strcmp(a, "--insecure")) {
			insecure = 1;
		} else if (!strcmp(a, "--origin") && i + 1 < argc) {
			o.origin = argv[++i];
		} else if (!strcmp(a, "--connect-to") && i + 1 < argc) {
			connect_to = argv[++i];
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
	if (streams < 1 || streams > 1024 || o.wt_lanes < 0 || o.wt_lanes > 16) {
		fprintf(stderr, "--streams is 1 to 1024, --lanes 0 to 16\n");
		return 2;
	}
	char host[256], path[256];
	uint16_t port;
	if (parse_url(url, host, sizeof(host), &port, path, sizeof(path), &o.webtransport) != 0) {
		fprintf(stderr, "bad server URL: %s\n", url);
		return 2;
	}
	if (o.webtransport) {
		if (pin) {
			if (parse_pin(pin, pin_hash) != 0) {
				fprintf(stderr, "bad --pin: 32 bytes in base64 or hex\n");
				return 2;
			}
			o.pin_sha256 = pin_hash;
		} else if (!insecure) {
			// There is no certificate authority check: a pin is all that tells the server apart.
			fprintf(stderr, "an https:// server needs --pin (or --insecure, which takes any certificate)\n");
			return 2;
		}
	} else if (pin || insecure || o.origin || connect_to || o.wt_lanes || o.wt_server_stream || o.wt_udp_buffer) {
		fprintf(stderr, "--pin, --insecure, --origin, --connect-to, --lanes, --server-stream and --udp-buffer are for "
		                "an https:// (WebTransport) server\n");
		return 2;
	}
	long target_port = strtol(positional[1], NULL, 10);
	if (target_port <= 0 || target_port > 65535) {
		fprintf(stderr, "bad port: %s\n", positional[1]);
		return 2;
	}
	o.host = host;
	if (connect_to) {
		o.server_name = host;
		o.host = connect_to;
	}
	o.port = port;
	o.path = path;
	// A send that waits for one stream's CONTINUE queues what the others' echoes bring meanwhile:
	// a window each, so the queue a single stream needs, times the streams (up to 16 of them).
	if (bench && streams > 1) o.max_queue_bytes *= (size_t)HW_MIN(streams, 16);

	char err[512];
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	if (!c) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}
	if (o.credit_window && !hw_client_credit_window(c)) {
		fprintf(stderr, "warning: the server does not offer stream credit: --credit has no effect\n");
	}
	if (o.user && o.pass && !hw_client_authenticated(c)) {
		fprintf(stderr, "warning: the server did not ask for a password, so none was sent: not authenticated\n");
	}
	if (g_verbose) {
		// The MOTD is the server's bytes; this is the user's terminal.
		const char *motd = hw_client_motd(c);
		char shown[MOTD_SHOWN];
		hw_client_printable(shown, sizeof(shown), motd, strlen(motd));
		fprintf(stderr, "connected: wisp-v%d, window %u, %d lane%s%s, stream credit %u, stream limit %u%s%s\n",
		        hw_client_is_v2(c) ? 2 : 1, hw_client_buffer_size(c), hw_client_lanes(c),
		        hw_client_lanes(c) == 1 ? "" : "s", hw_client_server_stream(c) ? ", server-opened" : "",
		        hw_client_credit_window(c), hw_client_max_streams(c), shown[0] ? ", motd: " : "", shown);
	}
	if (!bench) streams = 1;
	uint32_t *sid = calloc((size_t)streams, sizeof(*sid));
	if (!sid) {
		hw_client_free(c);
		return 1;
	}
	for (long k = 0; k < streams; k++) {
		int opened = hw_client_open(c, udp ? HW_STREAM_UDP : HW_STREAM_TCP, positional[0], (uint16_t)target_port,
		                            &sid[k]);
		if (opened != 0) {
			fprintf(stderr, "%s\n",
			        opened == HW_ERR_INVALID ? "bad host: a hostname is 1 to 255 bytes" : "cannot open stream");
			free(sid);
			hw_client_free(c);
			return 1;
		}
	}
	int rc = bench ? run_bench(c, sid, (size_t)streams, bench) : run_pipe(c, sid[0], idle_ms);
	free(sid);
	hw_client_free(c);
	return rc;
}

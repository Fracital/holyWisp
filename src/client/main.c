/*
 * holywisp-client: netcat through a Wisp server, plus an echo benchmark.
 *
 *   holywisp-client [-s ws://host:port/path] [--udp] [--v2] HOST PORT      stdin/stdout <-> HOST:PORT
 *   holywisp-client [-s ...] --bench BYTES HOST PORT                        echo throughput test
 *   holywisp-client [-s ...] --bench BYTES --upload|--download HOST PORT    one direction: a sink, a source
 *   holywisp-client -s https://host:port/ --pin SHA256 ...                  the same over WebTransport
 *   holywisp-client -s https://host/ --pin-key SHA256 ...                   pinned to the server's key
 */
#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/sys.h"
#include "holywisp/tls13.h"
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
#define PASS_READ  130           // a password file's first 127 bytes and a CRLF, and one more to tell a longer one
#define PASS_ENV   "HOLYWISP_PASSWORD"

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
	        "      --pin-key HASH   WebTransport: the SHA-256 of the server certificate's public key\n"
	        "                       (SubjectPublicKeyInfo), base64, hex or sha256//base64; it holds\n"
	        "                       across renewals that keep the key. Up to 4, any one matching:\n"
	        "                       openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin\n"
	        "                       -outform der | openssl dgst -sha256 -binary | base64\n"
	        "      --insecure       WebTransport: take any certificate (loopback tests only)\n"
	        "      --origin ORIGIN  WebTransport: send this origin header\n"
	        "      --connect-to A   WebTransport: connect to address or name A, the URL's host still\n"
	        "                       the SNI and :authority (as curl's --connect-to)\n"
	        "  -u, --udp            open a UDP stream instead of TCP\n"
	        "  -2, --v2             negotiate wisp-v2\n"
	        "      --user U         v2 password auth username, the password from --pass-file, or\n"
	        "                       $" PASS_ENV ", or --pass\n"
	        "      --pass-file F    the password: the first line of file F\n"
	        "      --pass P         the password itself, which every user of this host can read in\n"
	        "                       the process list: prefer --pass-file or $" PASS_ENV "\n"
	        "      --confirm        v2: ask for a CONTINUE when the stream connects\n"
	        "      --idle-ms N      after stdin EOF, exit when nothing arrives for N ms (2000)\n"
	        "      --bench BYTES    send BYTES to an echo service at HOST:PORT and report throughput\n"
	        "      --streams N      with --bench: over N streams at once, BYTES split among them (1)\n"
	        "      --upload         with --bench: send BYTES to a sink (discard service) at HOST:PORT\n"
	        "      --download       with --bench: read BYTES from a source (chargen, bench/echo\n"
	        "                       --source) at HOST:PORT\n"
	        "      --server-stream  WebTransport v2: have the server open the Wisp stream and send its\n"
	        "                       CONTINUE at once (offers \"wisp-v2-server-stream\")\n"
	        "      --lanes N        WebTransport v2: ride up to N QUIC streams (lanes) when the server\n"
	        "                       offers them, the first included; at most 16 (1)\n"
	        "      --credit BYTES   v2: ask for stream credit with an initial window of BYTES per\n"
	        "                       stream (under 16384 counts as 16384): the server sends each\n"
	        "                       stream only what this client has read, and a window more (off)\n"
	        "      --upload-credit  v2: count uploads in bytes against the server's grants (INFO 0xE4)\n"
	        "                       instead of CONTINUE's packet window, when the server offers it\n"
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

// The password in a file: its first line, without the line ending, into out (PASS_READ + 1
// bytes). 0, or -1 with the reason printed. A first line too long for the password extension is
// refused here, never cut, and the password itself is never printed.
static int read_pass_file(const char *path, char *out) {
	FILE *f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "--pass-file %s: %s\n", path, strerror(errno));
		return -1;
	}
	char buf[PASS_READ];
	size_t n = fread(buf, 1, sizeof buf, f);
	fclose(f);
	// The line ends at the first CR or LF, not at a NUL (strcspn's end), so that a NUL inside
	// it is refused instead of cutting the password short.
	size_t line = 0;
	while (line < n && line < sizeof buf && buf[line] != '\r' && buf[line] != '\n') line++;
	if (line == sizeof buf) {
		fprintf(stderr, "--pass-file %s: the first line is over 127 bytes\n", path);
		return -1;
	}
	if (memchr(buf, '\0', line)) {
		fprintf(stderr, "--pass-file %s: the password holds a NUL byte\n", path);
		return -1;
	}
	if (line == 0) {
		fprintf(stderr, "--pass-file %s: the first line is empty\n", path);
		return -1;
	}
	memcpy(out, buf, line);
	out[line] = '\0';
	return 0;
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

enum {
	BENCH_ECHO,
	BENCH_UP,
	BENCH_DOWN
};

static uint64_t g_connect_us; // hw_client_connect, for the bench's report

// The benchmark over nsid streams at once, total bytes split among them. BENCH_ECHO: each stream
// sends a chunk in turn to an echo service, and what has come back is taken between the sends.
// With stream credit a stream has at most half a window in flight: the server sends a stream no
// more than a window past what was taken, and an echo that cannot come back would hold the
// CONTINUE the next send waits for while nothing is taken. BENCH_UP sends to a sink (a discard
// service), done when the last chunk is sent: the window holds a sender to what the remote takes,
// to within one window. BENCH_DOWN sends nothing and takes total bytes from a source (a chargen,
// echo --source).
static int run_bench(hw_client *c, const uint32_t *sid, size_t nsid, size_t total, int dir) {
	uint8_t *chunk = malloc(PIPE_CHUNK);
	size_t *sent = calloc(nsid, sizeof(*sent));
	size_t *recv = calloc(nsid, sizeof(*recv));
	if (!chunk || !sent || !recv) {
		free(chunk);
		free(sent);
		free(recv);
		return 1;
	}
	size_t ahead = dir == BENCH_ECHO ? hw_client_credit_window(c) / 2 : 0; // 0: no bound
	for (size_t i = 0; i < PIPE_CHUNK; i++) chunk[i] = (uint8_t)(i * 31 + 7);
	uint64_t chunk_sum = byte_sum(chunk, PIPE_CHUNK); // every send but a short last one is the whole chunk
	size_t per = total / nsid;
	total = per * nsid;
	uint64_t start = hw_now_us();
	uint64_t first_byte = 0; // from the start to the first DATA, in microseconds
	size_t sent_all = 0, received = 0;
	uint64_t sum_sent = 0, sum_recv = 0;
	int rc = 1;
	while (dir == BENCH_UP ? sent_all < total : received < total) {
		int more = 0; // a stream may send more now
		for (size_t k = 0; k < nsid && dir != BENCH_DOWN; k++) {
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
			if (dir == BENCH_ECHO) sum_sent += n == PIPE_CHUNK ? chunk_sum : byte_sum(chunk, n);
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
				if (!first_byte) first_byte = HW_MAX(hw_now_us() - start, (uint64_t)1);
				if (dir == BENCH_ECHO) sum_recv += byte_sum(ev.data, ev.len);
				received += ev.len;
				read_count(ev.len);
				size_t k = bench_index(sid, nsid, ev.stream_id);
				if (k < nsid) recv[k] += ev.len;
			} else if (ev.type == HW_CEV_CLOSE) {
				fprintf(stderr, "stream closed: %s\n", hw_close_reason_str(ev.reason));
				goto done;
			}
			if (dir != BENCH_UP && received >= total) break;
		}
		if (r < 0 || (r == 0 && wait > 0)) {
			fprintf(stderr, "%s after %zu/%zu bytes\n", r < 0 ? "connection lost" : "timed out",
			        dir == BENCH_UP ? sent_all : received, total);
			goto done;
		}
	}
	uint64_t ms = (hw_now_us() - start) / 1000;
	if (ms == 0) ms = 1;
	double rate = (double)total / (1024.0 * 1024.0) / ((double)ms / 1000.0);
	if (dir == BENCH_ECHO) {
		printf("%zu bytes echoed in %llu ms: %.1f MiB/s each way, checksum %s\n", total, (unsigned long long)ms, rate,
		       sum_sent == sum_recv ? "ok" : "MISMATCH");
		rc = sum_sent == sum_recv ? 0 : 1;
	} else {
		printf("%zu bytes %s in %llu ms: %.1f MiB/s %s\n", total, dir == BENCH_UP ? "sent" : "received",
		       (unsigned long long)ms, rate, dir == BENCH_UP ? "up" : "down");
		rc = 0;
	}
	if (first_byte) {
		printf("connect %.1f ms, first byte %.1f ms after the start\n", (double)g_connect_us / 1000.0,
		       (double)first_byte / 1000.0);
	} else {
		printf("connect %.1f ms\n", (double)g_connect_us / 1000.0);
	}
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
	int bench_dir = BENCH_ECHO;
	int insecure = 0;
	const char *pin = NULL;
	const char *connect_to = NULL;
	const char *pass_file = NULL;
	char pass_buf[PASS_READ + 1];
	uint8_t pin_hash[32];
	uint8_t key_pins[32 * HW_TLS_KEY_PINS_MAX];
	size_t key_pin_count = 0;
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
		} else if (!strcmp(a, "--pass-file") && i + 1 < argc) {
			pass_file = argv[++i];
		} else if (!strcmp(a, "--confirm")) {
			o.stream_confirm = 1;
			o.v2 = 1;
		} else if (!strcmp(a, "--idle-ms") && i + 1 < argc) {
			idle_ms = (int)strtol(argv[++i], NULL, 10);
		} else if (!strcmp(a, "--bench") && i + 1 < argc) {
			bench = (size_t)strtoull(argv[++i], NULL, 10);
		} else if (!strcmp(a, "--streams") && i + 1 < argc) {
			streams = strtol(argv[++i], NULL, 10);
		} else if (!strcmp(a, "--upload")) {
			bench_dir = BENCH_UP;
		} else if (!strcmp(a, "--download")) {
			bench_dir = BENCH_DOWN;
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
		} else if (!strcmp(a, "--upload-credit")) {
			o.upload_credit = 1;
			o.v2 = 1;
		} else if (!strcmp(a, "--read-rate") && i + 1 < argc) {
			g_read_rate = strtoull(argv[++i], NULL, 10);
			if (g_read_rate == 0) {
				fprintf(stderr, "--read-rate is a number of bytes a second\n");
				return 2;
			}
		} else if (!strcmp(a, "--pin") && i + 1 < argc) {
			pin = argv[++i];
		} else if (!strcmp(a, "--pin-key") && i + 1 < argc) {
			const char *k = argv[++i];
			if (!strncmp(k, "sha256//", 8)) k += 8; // curl's --pinnedpubkey form
			if (key_pin_count == HW_TLS_KEY_PINS_MAX || parse_pin(k, key_pins + 32 * key_pin_count) != 0) {
				fprintf(stderr, "bad --pin-key: 32 bytes in base64 or hex, at most %d of them\n", HW_TLS_KEY_PINS_MAX);
				return 2;
			}
			key_pin_count++;
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
	// The password from the command line is in every process listing; a file or the environment
	// are not. --pass, then --pass-file, then the environment, which counts only with --user.
	if (o.pass && pass_file) {
		fprintf(stderr, "--pass and --pass-file are one password: give one of them\n");
		return 2;
	}
	if (pass_file) {
		if (read_pass_file(pass_file, pass_buf) != 0) return 2;
		o.pass = pass_buf;
	} else if (!o.pass && o.user && getenv(PASS_ENV) && getenv(PASS_ENV)[0]) {
		o.pass = getenv(PASS_ENV);
	}
	if (o.user && !o.pass) {
		fprintf(stderr, "warning: --user without a password (--pass-file, $" PASS_ENV " or --pass): none is sent\n");
	}
	if (bench_dir != BENCH_ECHO && !bench) {
		fprintf(stderr, "--upload and --download are for --bench\n");
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
		}
		if (key_pin_count) {
			o.key_pins_sha256 = key_pins;
			o.key_pin_count = key_pin_count;
		}
		if (!pin && !key_pin_count && !insecure) {
			// There is no certificate authority check: a pin is all that tells the server apart.
			fprintf(stderr, "an https:// server needs --pin or --pin-key (or --insecure, which takes any "
			                "certificate)\n");
			return 2;
		}
	} else if (pin || key_pin_count || insecure || o.origin || connect_to || o.wt_lanes || o.wt_server_stream ||
	           o.wt_udp_buffer) {
		fprintf(
		    stderr,
		    "--pin, --pin-key, --insecure, --origin, --connect-to, --lanes, --server-stream and --udp-buffer are for "
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
	uint64_t connect_start = hw_now_us();
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	if (!c) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}
	g_connect_us = hw_now_us() - connect_start;
	if (o.credit_window && !hw_client_credit_window(c)) {
		fprintf(stderr, "warning: the server does not offer stream credit: --credit has no effect\n");
	}
	if (o.upload_credit && !hw_client_upload_window(c)) {
		fprintf(stderr, "warning: the server does not offer upload credit: --upload-credit has no effect\n");
	}
	if (o.user && o.pass && !hw_client_authenticated(c)) {
		fprintf(stderr, "warning: the server did not ask for a password, so none was sent: not authenticated\n");
	}
	if (g_verbose) {
		// The MOTD is the server's bytes; this is the user's terminal.
		const char *motd = hw_client_motd(c);
		char shown[MOTD_SHOWN];
		hw_client_printable(shown, sizeof(shown), motd, strlen(motd));
		fprintf(
		    stderr,
		    "connected: wisp-v%d, window %u, %d lane%s%s, stream credit %u, upload credit %u, stream limit %u%s%s\n",
		    hw_client_is_v2(c) ? 2 : 1, hw_client_buffer_size(c), hw_client_lanes(c),
		    hw_client_lanes(c) == 1 ? "" : "s", hw_client_server_stream(c) ? ", server-opened" : "",
		    hw_client_credit_window(c), hw_client_upload_window(c), hw_client_max_streams(c),
		    shown[0] ? ", motd: " : "", shown);
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
	int rc = bench ? run_bench(c, sid, (size_t)streams, bench, bench_dir) : run_pipe(c, sid[0], idle_ms);
	free(sid);
	hw_client_free(c);
	return rc;
}

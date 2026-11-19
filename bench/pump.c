/*
 * bench/pump.c - Wisp load generator built on libholywisp-client.
 *
 * One process is one connection to the server under test: a WebSocket (ws://) or a WebTransport
 * session (https://). Five modes:
 *
 *   tp     open N TCP streams to an echo service and keep every one of them full for D seconds,
 *          honouring the server's CONTINUE window and an in-flight byte cap per stream (what a
 *          real client's bufferedAmount check does). Reports bytes sent / received.
 *   up     the same toward a sink (echo --sink), which echoes nothing: what one direction of
 *          uploads costs, without the downloads that an echo brings back. Reports bytes sent.
 *   down   open N TCP streams to a source (echo --source), which sends without being asked, and
 *          read them for D seconds. Reports bytes received.
 *   rtt    one stream, one small message at a time, round-trip latency distribution.
 *   churn  keep K streams in flight: open, echo one byte, close, open another. Reports
 *          completed stream lifecycles per second, and how long each took from its CONNECT to
 *          its echoed byte.
 *
 * Every mode also reports connect_us, the WebSocket or WebTransport connect and the Wisp handshake,
 * and tp, up and down report first_byte_us: from the first send (down: the CONNECTs) to the first
 * byte that came back.
 *
 * Output is one JSON object on stdout so the harness can parse it.
 *
 *   pump [-s ws://127.0.0.1:6001/ | -s https://127.0.0.1:6001/] [--pin B64|HEX] [--pin-key B64|HEX]
 *        [--insecure] [--v2] --mode tp|up|down|rtt|churn [--streams N] [--duration S]
 *        [--chunk BYTES] [--inflight BYTES|K] [--settle-ms N] HOST PORT
 *
 * --settle-ms waits after opening the streams before the clock starts and the first byte is sent,
 * so the measurement does not depend on how a server treats DATA that lands while its outbound
 * dial is still in progress. A session's QUIC timers run inside the client's calls, so over
 * WebTransport the wait polls the client instead of sleeping, and discards what it reads.
 */
#define _GNU_SOURCE
#include <holywisp/client.h>
#include <holywisp/hw.h>
#include <holywisp/wisp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_STREAMS   256
#define MAX_KEY_PINS  4
#define CHURN_SAMPLES (4u << 20)

static uint64_t now_us(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000;
}

__attribute__((noreturn)) static void die(const char *what, const char *detail) {
	fprintf(stderr, "pump: %s%s%s\n", what, detail ? ": " : "", detail ? detail : "");
	exit(1);
}

typedef struct {
	uint32_t id;
	uint64_t sent;
	uint64_t recv;
} pstream;

static int find_stream(pstream *st, int n, uint32_t id) {
	for (int i = 0; i < n; i++)
		if (st[i].id == id) return i;
	return -1;
}

static int g_settle_ms;
static uint64_t g_connect_us;
static int g_webtransport;

// The packets a stream may send before the next CONTINUE, as the library counts them.
static uint32_t window_of(const hw_client *c, uint32_t sid) {
	uint32_t w = 0;
	if (hw_client_window(c, sid, &w) != 0) die("stream gone", NULL);
	return w;
}

// --settle-ms. A WebSocket sleeps; a session keeps its QUIC timers running and drops what comes.
static void settle(hw_client *c) {
	if (!g_settle_ms) return;
	if (!g_webtransport) {
		usleep((useconds_t)g_settle_ms * 1000);
		return;
	}
	uint64_t until = now_us() + (uint64_t)g_settle_ms * 1000;
	hw_client_event ev;
	for (uint64_t t = now_us(); t < until; t = now_us()) {
		int r = hw_client_poll(c, (int)((until - t + 999) / 1000), &ev);
		if (r < 0) die("connection lost", NULL);
		if (r > 0 && ev.type == HW_CEV_CLOSE) die("stream closed", hw_close_reason_str(ev.reason));
	}
}

static void open_streams(hw_client *c, const char *host, uint16_t port, pstream *st, int nstreams) {
	for (int i = 0; i < nstreams; i++) {
		if (hw_client_open(c, HW_STREAM_TCP, host, port, &st[i].id) != 0) die("open failed", NULL);
		st[i].sent = st[i].recv = 0;
	}
}

// tp and up: keep every stream's window and in-flight cap full for the duration. An echo's bytes
// come back (tp); a sink's never do (up), and then only the window holds a stream back.
static int run_send(hw_client *c, const char *host, uint16_t port, int nstreams, int duration_s, size_t chunk,
                    uint64_t inflight_cap, int echoed) {
	pstream st[MAX_STREAMS];
	uint8_t *buf = malloc(chunk);
	if (!buf) die("oom", NULL);
	for (size_t i = 0; i < chunk; i++) buf[i] = (uint8_t)(i * 31 + 7);
	uint32_t window = hw_client_buffer_size(c);
	open_streams(c, host, port, st, nstreams);
	settle(c);
	uint64_t start = now_us(), deadline = start + (uint64_t)duration_s * 1000000ull;
	uint64_t total_sent = 0, total_recv = 0, last_progress = start, stalled_at = 0, first_byte = 0;
	int stalls = 0;
	hw_client_event ev;
	while (now_us() < deadline) {
		int progressed = 0;
		for (int i = 0; i < nstreams; i++) {
			pstream *s = &st[i];
			if (window_of(c, s->id) == 0 || (echoed && s->sent - s->recv + chunk > inflight_cap)) continue;
			if (hw_client_send(c, s->id, buf, chunk) != 0) die("send failed", NULL);
			s->sent += chunk;
			total_sent += chunk;
			progressed = 1;
		}
		int r;
		while ((r = hw_client_poll(c, progressed ? 0 : 20, &ev)) > 0) {
			if (ev.type == HW_CEV_DATA) {
				int i = find_stream(st, nstreams, ev.stream_id);
				if (i >= 0) st[i].recv += ev.len;
				if (!first_byte) first_byte = now_us() - start;
				total_recv += ev.len;
				progressed = 1;
			} else if (ev.type == HW_CEV_CONTINUE) {
				progressed = 1;
			} else if (ev.type == HW_CEV_CLOSE) {
				fprintf(stderr, "pump: stream %u closed: %s\n", ev.stream_id, hw_close_reason_str(ev.reason));
				return 1;
			}
			if (progressed) break; // go refill before draining everything
		}
		if (r < 0) die("connection lost", NULL);
		uint64_t t = now_us();
		if (progressed) {
			last_progress = t;
		} else if (t - last_progress > 2000000ull) {
			// Every stream has spent its window and the server has not sent a CONTINUE for 2 s:
			// a flow-control stall. Recorded, not fatal; the throughput number carries it.
			if (!stalled_at) stalled_at = t - start;
			stalls++;
			last_progress = t;
		}
	}
	uint64_t el = now_us() - start;
	uint64_t counted = echoed ? total_recv : total_sent;
	printf("{\"mode\":\"%s\",\"streams\":%d,\"elapsed_us\":%llu,\"sent\":%llu,\"received\":%llu,"
	       "\"window\":%u,\"mib_s\":%.2f,\"stalls\":%d,\"stalled_at_us\":%llu,\"connect_us\":%llu,"
	       "\"first_byte_us\":%llu}\n",
	       echoed ? "tp" : "up", nstreams, (unsigned long long)el, (unsigned long long)total_sent,
	       (unsigned long long)total_recv, window, (double)counted / 1048576.0 / ((double)el / 1e6), stalls,
	       (unsigned long long)stalled_at, (unsigned long long)g_connect_us, (unsigned long long)first_byte);
	for (int i = 0; i < nstreams; i++) hw_client_close_stream(c, st[i].id, HW_CLOSE_VOLUNTARY);
	free(buf);
	return 0;
}

// down: read N streams from a source for the duration. The first byte is timed from the CONNECTs;
// what arrives during --settle-ms is not counted.
static int run_down(hw_client *c, const char *host, uint16_t port, int nstreams, int duration_s) {
	pstream st[MAX_STREAMS];
	uint64_t opened = now_us();
	open_streams(c, host, port, st, nstreams);
	hw_client_event ev;
	uint64_t first_byte = 0;
	while (!first_byte) {
		int r = hw_client_poll(c, 5000, &ev);
		if (r <= 0) die(r < 0 ? "connection lost" : "no byte from the source in 5 s", NULL);
		if (ev.type == HW_CEV_CLOSE) die("stream closed", hw_close_reason_str(ev.reason));
		if (ev.type == HW_CEV_DATA) first_byte = now_us() - opened;
	}
	uint64_t until = now_us() + (uint64_t)g_settle_ms * 1000;
	while (now_us() < until) {
		int r = hw_client_poll(c, 10, &ev);
		if (r < 0) die("connection lost", NULL);
		if (r > 0 && ev.type == HW_CEV_CLOSE) die("stream closed", hw_close_reason_str(ev.reason));
	}
	uint64_t start = now_us(), deadline = start + (uint64_t)duration_s * 1000000ull, total = 0;
	int stalls = 0;
	for (uint64_t t = start; t < deadline; t = now_us()) {
		int r = hw_client_poll(c, (int)HW_MIN((deadline - t + 999) / 1000, 2000), &ev);
		if (r < 0) die("connection lost", NULL);
		if (r == 0) {
			stalls += now_us() - t >= 2000000ull; // two seconds without a byte
			continue;
		}
		if (ev.type == HW_CEV_CLOSE) {
			fprintf(stderr, "pump: stream %u closed: %s\n", ev.stream_id, hw_close_reason_str(ev.reason));
			return 1;
		}
		if (ev.type != HW_CEV_DATA) continue;
		int i = find_stream(st, nstreams, ev.stream_id);
		if (i >= 0) st[i].recv += ev.len;
		total += ev.len;
	}
	uint64_t el = now_us() - start;
	printf("{\"mode\":\"down\",\"streams\":%d,\"elapsed_us\":%llu,\"received\":%llu,\"mib_s\":%.2f,\"stalls\":%d,"
	       "\"connect_us\":%llu,\"first_byte_us\":%llu}\n",
	       nstreams, (unsigned long long)el, (unsigned long long)total, (double)total / 1048576.0 / ((double)el / 1e6),
	       stalls, (unsigned long long)g_connect_us, (unsigned long long)first_byte);
	for (int i = 0; i < nstreams; i++) hw_client_close_stream(c, st[i].id, HW_CLOSE_VOLUNTARY);
	return 0;
}

static int cmp_u64(const void *a, const void *b) {
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y;
}

static int run_rtt(hw_client *c, const char *host, uint16_t port, int duration_s, size_t chunk) {
	uint32_t sid;
	if (hw_client_open(c, HW_STREAM_TCP, host, port, &sid) != 0) die("open failed", NULL);
	settle(c);
	size_t cap = 4u << 20, n = 0;
	uint64_t *samples = malloc(cap * sizeof *samples);
	uint8_t *buf = malloc(chunk), *in = malloc(chunk);
	if (!samples || !buf || !in) die("oom", NULL);
	memset(buf, 0x5a, chunk);
	int stalls = 0;
	uint64_t start = now_us(), deadline = start + (uint64_t)duration_s * 1000000ull;
	hw_client_event ev;
	while (now_us() < deadline && n < cap) {
		if (window_of(c, sid) == 0) {
			// Wait up to 1 s for the server's CONTINUE. A server that never sends it after exactly
			// one window has a flow-control bug; measure on a fresh stream and count the stall.
			uint64_t until = now_us() + 1000000ull;
			while (window_of(c, sid) == 0 && now_us() < until) {
				int r = hw_client_poll(c, 100, &ev);
				if (r < 0) die("connection lost", NULL);
				if (r > 0 && ev.type == HW_CEV_CLOSE) die("stream closed", hw_close_reason_str(ev.reason));
			}
			if (window_of(c, sid) == 0) {
				stalls++;
				hw_client_close_stream(c, sid, HW_CLOSE_VOLUNTARY);
				if (hw_client_open(c, HW_STREAM_TCP, host, port, &sid) != 0) die("open failed", NULL);
				settle(c);
			}
		}
		uint64_t t0 = now_us();
		if (hw_client_send(c, sid, buf, chunk) != 0) die("send failed", NULL);
		long long got = hw_client_read_exact(c, sid, in, chunk, 5000);
		if (got != (long)chunk) die("echo failed", NULL);
		samples[n++] = now_us() - t0;
		// read_exact queues the CONTINUE events it skipped past (the library has counted them);
		// drain them without blocking.
		int r;
		while ((r = hw_client_poll(c, 0, &ev)) > 0) {
		}
		if (r < 0) die("connection lost", NULL);
	}
	uint64_t el = now_us() - start;
	qsort(samples, n, sizeof *samples, cmp_u64);
	double sum = 0;
	for (size_t i = 0; i < n; i++) sum += (double)samples[i];
#define PCT(p) ((unsigned long long)samples[(size_t)((double)(n - 1) * (p))])
	printf("{\"mode\":\"rtt\",\"bytes\":%zu,\"elapsed_us\":%llu,\"count\":%zu,\"mean_us\":%.2f,\"p50_us\":%llu,"
	       "\"p90_us\":%llu,\"p99_us\":%llu,\"p999_us\":%llu,\"max_us\":%llu,\"rps\":%.1f,\"stalls\":%d,"
	       "\"connect_us\":%llu}\n",
	       chunk, (unsigned long long)el, n, sum / (double)n, PCT(0.50), PCT(0.90), PCT(0.99), PCT(0.999),
	       (unsigned long long)samples[n - 1], (double)n / ((double)el / 1e6), stalls,
	       (unsigned long long)g_connect_us);
#undef PCT
	hw_client_close_stream(c, sid, HW_CLOSE_VOLUNTARY);
	free(samples);
	free(buf);
	free(in);
	return 0;
}

static int run_churn(hw_client *c, const char *host, uint16_t port, int duration_s, int k) {
	uint32_t ids[MAX_STREAMS];
	uint64_t opened[MAX_STREAMS];
	uint8_t one = 0x42;
	uint64_t completed = 0, failed = 0;
	uint64_t *samples = malloc(CHURN_SAMPLES * sizeof *samples); // CONNECT to echoed byte, per stream
	size_t n = 0;
	if (!samples) die("oom", NULL);
	for (int i = 0; i < k; i++) {
		opened[i] = now_us();
		if (hw_client_open(c, HW_STREAM_TCP, host, port, &ids[i]) != 0) die("open failed", NULL);
		if (hw_client_send(c, ids[i], &one, 1) != 0) die("send failed", NULL);
	}
	uint64_t start = now_us(), deadline = start + (uint64_t)duration_s * 1000000ull;
	hw_client_event ev;
	while (now_us() < deadline) {
		int r = hw_client_poll(c, 100, &ev);
		if (r < 0) die("connection lost", NULL);
		if (r == 0) continue;
		if (ev.type != HW_CEV_DATA && ev.type != HW_CEV_CLOSE) continue;
		if (ev.stream_id == 0) die("connection closed by server", NULL);
		int slot = -1;
		for (int j = 0; j < k; j++)
			if (ids[j] == ev.stream_id) slot = j;
		if (slot < 0) continue;
		uint64_t t = now_us();
		if (ev.type == HW_CEV_DATA) {
			completed++;
			if (n < CHURN_SAMPLES) samples[n++] = t - opened[slot];
			hw_client_close_stream(c, ev.stream_id, HW_CLOSE_VOLUNTARY);
		} else {
			failed++;
		}
		opened[slot] = t;
		if (hw_client_open(c, HW_STREAM_TCP, host, port, &ids[slot]) != 0) die("open failed", NULL);
		if (hw_client_send(c, ids[slot], &one, 1) != 0) die("send failed", NULL);
	}
	uint64_t el = now_us() - start;
	qsort(samples, n, sizeof *samples, cmp_u64);
#define PCT(p) (n ? (unsigned long long)samples[(size_t)((double)(n - 1) * (p))] : 0ull)
	printf("{\"mode\":\"churn\",\"inflight\":%d,\"elapsed_us\":%llu,\"completed\":%llu,\"failed\":%llu,"
	       "\"per_s\":%.1f,\"open_p50_us\":%llu,\"open_p99_us\":%llu,\"connect_us\":%llu}\n",
	       k, (unsigned long long)el, (unsigned long long)completed, (unsigned long long)failed,
	       (double)completed / ((double)el / 1e6), PCT(0.50), PCT(0.99), (unsigned long long)g_connect_us);
#undef PCT
	free(samples);
	return 0;
}

// A SHA-256 as base64 or hex, as holywisp-client's --pin takes it.
static int parse_hash(const char *s, uint8_t out[32]) {
	static const char hex[] = "0123456789abcdef0123456789ABCDEF";
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t n = strlen(s);
	if (n == 64) {
		for (size_t i = 0; i < 64; i++) {
			const char *q = strchr(hex, s[i]);
			if (!q) return -1;
			int v = (int)(q - hex) & 15;
			out[i / 2] = (uint8_t)(i % 2 ? out[i / 2] | v : v << 4);
		}
		return 0;
	}
	uint32_t acc = 0;
	int bits = 0;
	size_t got = 0;
	for (size_t i = 0; i < n && s[i] != '='; i++) {
		const char *q = strchr(b64, s[i]);
		if (!q) return -1;
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

int main(int argc, char **argv) {
	const char *url = "ws://127.0.0.1:6001/";
	const char *mode = "tp";
	int streams = 1, duration = 10, v2 = 0, insecure = 0;
	size_t chunk = 64 * 1024;
	uint64_t inflight = 0;
	uint8_t pin[32], key_pins[32 * MAX_KEY_PINS];
	int has_pin = 0;
	size_t key_pin_count = 0;
	const char *pos[2] = {NULL, NULL};
	int npos = 0;
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "-s") && i + 1 < argc)
			url = argv[++i];
		else if (!strcmp(a, "--v2"))
			v2 = 1;
		else if (!strcmp(a, "--mode") && i + 1 < argc)
			mode = argv[++i];
		else if (!strcmp(a, "--streams") && i + 1 < argc)
			streams = atoi(argv[++i]);
		else if (!strcmp(a, "--duration") && i + 1 < argc)
			duration = atoi(argv[++i]);
		else if (!strcmp(a, "--chunk") && i + 1 < argc)
			chunk = (size_t)strtoull(argv[++i], NULL, 10);
		else if (!strcmp(a, "--inflight") && i + 1 < argc)
			inflight = strtoull(argv[++i], NULL, 10);
		else if (!strcmp(a, "--settle-ms") && i + 1 < argc)
			g_settle_ms = atoi(argv[++i]);
		else if (!strcmp(a, "--pin") && i + 1 < argc) {
			if (parse_hash(argv[++i], pin) != 0) die("bad --pin", argv[i]);
			has_pin = 1;
		} else if (!strcmp(a, "--pin-key") && i + 1 < argc) {
			const char *k = argv[++i];
			if (!strncmp(k, "sha256//", 8)) k += 8;
			if (key_pin_count == MAX_KEY_PINS || parse_hash(k, key_pins + 32 * key_pin_count) != 0)
				die("bad --pin-key", argv[i]);
			key_pin_count++;
		} else if (!strcmp(a, "--insecure"))
			insecure = 1;
		else if (a[0] == '-')
			die("unknown option", a);
		else if (npos < 2)
			pos[npos++] = a;
	}
	if (npos != 2 || streams < 1 || streams > MAX_STREAMS) die("usage: pump [opts] HOST PORT", NULL);
	if (!strcmp(mode, "churn") && inflight > MAX_STREAMS) die("churn: --inflight is at most 256 streams", NULL);

	// ws://host:port/path, or https:// for WebTransport
	g_webtransport = !strncmp(url, "https://", 8);
	char hostbuf[256], pathbuf[256] = "/";
	const char *p = strstr(url, "://");
	p = p ? p + 3 : url;
	const char *slash = strchr(p, '/');
	size_t hl = slash ? (size_t)(slash - p) : strlen(p);
	if (hl >= sizeof hostbuf) die("bad url", url);
	memcpy(hostbuf, p, hl);
	hostbuf[hl] = 0;
	if (slash) snprintf(pathbuf, sizeof pathbuf, "%s", slash);
	char *colon = strrchr(hostbuf, ':');
	uint16_t sport = g_webtransport ? 443 : 6001;
	if (colon) {
		*colon = 0;
		sport = (uint16_t)atoi(colon + 1);
	}
	if (g_webtransport && !has_pin && !key_pin_count && !insecure)
		die("an https:// server needs --pin, --pin-key or --insecure", NULL);

	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = hostbuf;
	o.port = sport;
	o.path = pathbuf;
	o.v2 = v2;
	o.max_message = 2u << 20;
	o.webtransport = g_webtransport;
	o.pin_sha256 = has_pin ? pin : NULL;
	o.key_pins_sha256 = key_pin_count ? key_pins : NULL;
	o.key_pin_count = key_pin_count;
	char err[256];
	uint64_t t0 = now_us();
	hw_client *c = hw_client_connect(&o, err, sizeof err);
	if (!c) die("connect failed", err);
	g_connect_us = now_us() - t0;

	int rc;
	uint16_t port = (uint16_t)atoi(pos[1]);
	if (!strcmp(mode, "tp"))
		rc = run_send(c, pos[0], port, streams, duration, chunk, inflight ? inflight : 4u << 20, 1);
	else if (!strcmp(mode, "up"))
		rc = run_send(c, pos[0], port, streams, duration, chunk, 0, 0);
	else if (!strcmp(mode, "down"))
		rc = run_down(c, pos[0], port, streams, duration);
	else if (!strcmp(mode, "rtt"))
		rc = run_rtt(c, pos[0], port, duration, chunk == 64 * 1024 ? 64 : chunk);
	else if (!strcmp(mode, "churn"))
		rc = run_churn(c, pos[0], port, duration, inflight ? (int)inflight : 32);
	else
		die("unknown mode", mode);
	hw_client_free(c);
	return rc;
}

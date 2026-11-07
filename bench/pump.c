/*
 * bench/pump.c - Wisp load generator built on libholywisp-client.
 *
 * One process is one WebSocket connection to the server under test. Three modes:
 *
 *   tp     open N TCP streams to an echo service and keep every one of them full for D seconds,
 *          honouring the server's CONTINUE window and an in-flight byte cap per stream (what a
 *          real client's bufferedAmount check does). Reports bytes sent / received.
 *   rtt    one stream, one small message at a time, round-trip latency distribution.
 *   churn  keep K streams in flight: open, echo one byte, close, open another. Reports
 *          completed stream lifecycles per second.
 *
 * Output is one JSON object on stdout so the harness can parse it.
 *
 *   pump [-s ws://127.0.0.1:6001/] [--v2] --mode tp|rtt|churn [--streams N] [--duration S]
 *        [--chunk BYTES] [--inflight BYTES|K] [--settle-ms N] HOST PORT
 *
 * --settle-ms waits after opening the streams before the clock starts and the first byte is sent,
 * so the measurement does not depend on how a server treats DATA that lands while its outbound
 * dial is still in progress.
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

#define MAX_STREAMS 256

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
	uint32_t credits;
	uint64_t sent;
	uint64_t recv;
} pstream;

static int find_stream(pstream *st, int n, uint32_t id) {
	for (int i = 0; i < n; i++)
		if (st[i].id == id) return i;
	return -1;
}

static int g_settle_ms;

static int run_tp(hw_client *c, const char *host, uint16_t port, int nstreams, int duration_s, size_t chunk,
                  uint64_t inflight_cap) {
	pstream st[MAX_STREAMS];
	uint8_t *buf = malloc(chunk);
	if (!buf) die("oom", NULL);
	for (size_t i = 0; i < chunk; i++) buf[i] = (uint8_t)(i * 31 + 7);
	uint32_t window = hw_client_buffer_size(c);
	for (int i = 0; i < nstreams; i++) {
		if (hw_client_open(c, HW_STREAM_TCP, host, port, &st[i].id) != 0) die("open failed", NULL);
		st[i].credits = window;
		st[i].sent = st[i].recv = 0;
	}
	if (g_settle_ms) usleep((useconds_t)g_settle_ms * 1000);
	uint64_t start = now_us(), deadline = start + (uint64_t)duration_s * 1000000ull;
	uint64_t total_sent = 0, total_recv = 0, last_progress = start, stalled_at = 0;
	int stalls = 0;
	hw_client_event ev;
	while (now_us() < deadline) {
		int progressed = 0;
		for (int i = 0; i < nstreams; i++) {
			pstream *s = &st[i];
			if (s->credits == 0 || s->sent - s->recv + chunk > inflight_cap) continue;
			if (hw_client_send(c, s->id, buf, chunk) != 0) die("send failed", NULL);
			s->credits--;
			s->sent += chunk;
			total_sent += chunk;
			progressed = 1;
		}
		int r;
		while ((r = hw_client_poll(c, progressed ? 0 : 20, &ev)) > 0) {
			if (ev.type == HW_CEV_DATA) {
				int i = find_stream(st, nstreams, ev.stream_id);
				if (i >= 0) st[i].recv += ev.len;
				total_recv += ev.len;
				progressed = 1;
			} else if (ev.type == HW_CEV_CONTINUE) {
				int i = find_stream(st, nstreams, ev.stream_id);
				if (i >= 0) st[i].credits = ev.buffer_remaining;
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
	printf("{\"mode\":\"tp\",\"streams\":%d,\"elapsed_us\":%llu,\"sent\":%llu,\"received\":%llu,"
	       "\"window\":%u,\"mib_s\":%.2f,\"stalls\":%d,\"stalled_at_us\":%llu}\n",
	       nstreams, (unsigned long long)el, (unsigned long long)total_sent, (unsigned long long)total_recv, window,
	       (double)total_recv / 1048576.0 / ((double)el / 1e6), stalls, (unsigned long long)stalled_at);
	for (int i = 0; i < nstreams; i++) hw_client_close_stream(c, st[i].id, HW_CLOSE_VOLUNTARY);
	free(buf);
	return 0;
}

static int cmp_u64(const void *a, const void *b) {
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y;
}

static int run_rtt(hw_client *c, const char *host, uint16_t port, int duration_s, size_t chunk) {
	uint32_t sid;
	if (hw_client_open(c, HW_STREAM_TCP, host, port, &sid) != 0) die("open failed", NULL);
	uint32_t credits = hw_client_buffer_size(c);
	if (g_settle_ms) usleep((useconds_t)g_settle_ms * 1000);
	size_t cap = 4u << 20, n = 0;
	uint64_t *samples = malloc(cap * sizeof *samples);
	uint8_t *buf = malloc(chunk), *in = malloc(chunk);
	if (!samples || !buf || !in) die("oom", NULL);
	memset(buf, 0x5a, chunk);
	int stalls = 0;
	uint64_t start = now_us(), deadline = start + (uint64_t)duration_s * 1000000ull;
	hw_client_event ev;
	while (now_us() < deadline && n < cap) {
		if (credits == 0) {
			// Wait up to 1 s for the server's CONTINUE. A server that never sends it after exactly
			// one window has a flow-control bug; measure on a fresh stream and count the stall.
			uint64_t until = now_us() + 1000000ull;
			while (credits == 0 && now_us() < until) {
				int r = hw_client_poll(c, 100, &ev);
				if (r < 0) die("connection lost", NULL);
				if (r > 0 && ev.type == HW_CEV_CONTINUE && ev.stream_id == sid) credits = ev.buffer_remaining;
				if (r > 0 && ev.type == HW_CEV_CLOSE) die("stream closed", hw_close_reason_str(ev.reason));
			}
			if (credits == 0) {
				stalls++;
				hw_client_close_stream(c, sid, HW_CLOSE_VOLUNTARY);
				if (hw_client_open(c, HW_STREAM_TCP, host, port, &sid) != 0) die("open failed", NULL);
				credits = hw_client_buffer_size(c);
				if (g_settle_ms) usleep((useconds_t)g_settle_ms * 1000);
			}
		}
		uint64_t t0 = now_us();
		if (hw_client_send(c, sid, buf, chunk) != 0) die("send failed", NULL);
		credits--;
		long got = hw_client_read_exact(c, sid, in, chunk, 5000);
		if (got != (long)chunk) die("echo failed", NULL);
		samples[n++] = now_us() - t0;
		// read_exact queues CONTINUE events it skipped past; drain them without blocking.
		int r;
		while ((r = hw_client_poll(c, 0, &ev)) > 0)
			if (ev.type == HW_CEV_CONTINUE && ev.stream_id == sid) credits = ev.buffer_remaining;
		if (r < 0) die("connection lost", NULL);
	}
	uint64_t el = now_us() - start;
	qsort(samples, n, sizeof *samples, cmp_u64);
	double sum = 0;
	for (size_t i = 0; i < n; i++) sum += (double)samples[i];
#define PCT(p) ((unsigned long long)samples[(size_t)((double)(n - 1) * (p))])
	printf("{\"mode\":\"rtt\",\"bytes\":%zu,\"elapsed_us\":%llu,\"count\":%zu,\"mean_us\":%.2f,\"p50_us\":%llu,"
	       "\"p90_us\":%llu,\"p99_us\":%llu,\"p999_us\":%llu,\"max_us\":%llu,\"rps\":%.1f,\"stalls\":%d}\n",
	       chunk, (unsigned long long)el, n, sum / (double)n, PCT(0.50), PCT(0.90), PCT(0.99), PCT(0.999),
	       (unsigned long long)samples[n - 1], (double)n / ((double)el / 1e6), stalls);
#undef PCT
	hw_client_close_stream(c, sid, HW_CLOSE_VOLUNTARY);
	free(samples);
	free(buf);
	free(in);
	return 0;
}

static int run_churn(hw_client *c, const char *host, uint16_t port, int duration_s, int k) {
	uint32_t ids[MAX_STREAMS];
	uint8_t one = 0x42;
	uint64_t completed = 0, failed = 0;
	for (int i = 0; i < k; i++) {
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
		if (ev.type == HW_CEV_DATA) {
			completed++;
			hw_client_close_stream(c, ev.stream_id, HW_CLOSE_VOLUNTARY);
		} else {
			failed++;
		}
		if (hw_client_open(c, HW_STREAM_TCP, host, port, &ids[slot]) != 0) die("open failed", NULL);
		if (hw_client_send(c, ids[slot], &one, 1) != 0) die("send failed", NULL);
	}
	uint64_t el = now_us() - start;
	printf("{\"mode\":\"churn\",\"inflight\":%d,\"elapsed_us\":%llu,\"completed\":%llu,\"failed\":%llu,"
	       "\"per_s\":%.1f}\n",
	       k, (unsigned long long)el, (unsigned long long)completed, (unsigned long long)failed,
	       (double)completed / ((double)el / 1e6));
	return 0;
}

int main(int argc, char **argv) {
	const char *url = "ws://127.0.0.1:6001/";
	const char *mode = "tp";
	int streams = 1, duration = 10, v2 = 0;
	size_t chunk = 64 * 1024;
	uint64_t inflight = 0;
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
		else if (a[0] == '-')
			die("unknown option", a);
		else if (npos < 2)
			pos[npos++] = a;
	}
	if (npos != 2 || streams < 1 || streams > MAX_STREAMS) die("usage: pump [opts] HOST PORT", NULL);

	// ws://host:port/path
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
	uint16_t sport = 6001;
	if (colon) {
		*colon = 0;
		sport = (uint16_t)atoi(colon + 1);
	}

	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = hostbuf;
	o.port = sport;
	o.path = pathbuf;
	o.v2 = v2;
	o.max_message = 2u << 20;
	char err[256];
	hw_client *c = hw_client_connect(&o, err, sizeof err);
	if (!c) die("connect failed", err);

	int rc;
	if (!strcmp(mode, "tp"))
		rc = run_tp(c, pos[0], (uint16_t)atoi(pos[1]), streams, duration, chunk, inflight ? inflight : 4u << 20);
	else if (!strcmp(mode, "rtt"))
		rc = run_rtt(c, pos[0], (uint16_t)atoi(pos[1]), duration, chunk == 64 * 1024 ? 64 : chunk);
	else if (!strcmp(mode, "churn"))
		rc = run_churn(c, pos[0], (uint16_t)atoi(pos[1]), duration, inflight ? (int)inflight : 32);
	else
		die("unknown mode", mode);
	hw_client_free(c);
	return rc;
}

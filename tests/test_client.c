/*
 * The client library against a server that is not on its side. Each case starts a fake server on
 * an ephemeral loopback port, which answers the upgrade and then plays one script: it withholds a
 * CONTINUE, floods, trickles packets that are not events, answers with a protocol nobody asked
 * for, or puts escape sequences where text is expected. The client must stay inside the limits
 * its caller set (time, memory), send nothing the server did not ask for, and hand its caller
 * nothing that is unsafe to print.
 *
 * A script never outlives FAKE_LIFE_MS, so a client that waits without bound fails its case
 * (the server hangs up and the result is wrong) instead of hanging the suite.
 */
#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/sys.h"
#include "holywisp/wisp.h"
#include "holywisp/ws.h"

#include "test.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

#include <sys/socket.h>

#define FAKE_LIFE_MS     6000
#define FAKE_SLICE_MS    20
#define FAKE_FRAME_MAX   1024               // the largest frame a case's client sends
#define FLOOD_BLOB       (64 * 1024)        // frames are sent this many bytes at a time
#define FLOOD_DATA_LEN   (16 * 1024)        // payload of one flooded DATA packet
#define FLOOD_DATA_BYTES (64 * 1024 * 1024) // a DATA flood ends here: twice the default queue budget
#define FLOOD_EMPTY      200000             // a flood of empty DATA packets ends here
#define OTHER_STREAM     99                 // a stream id the client never opened

// ---------------------------------------------------------------------------------- fake server

typedef struct fake fake;
typedef void (*fake_script)(fake *f, int fd);

// One listener, one connection, one script, on its own thread. The test sets the fields above the
// line before fake_start and reads the ones below it after fake_join; `go` and `stop` are the only
// ones both threads touch while the script runs.
struct fake {
	fake_script script;
	const char *raw_response;  // sent in place of the 101; the connection ends there
	const char *echo_protocol; // Sec-WebSocket-Protocol in the 101, whether or not one was offered
	uint32_t window;           // the stream-0 CONTINUE
	int advertise_password;    // the INFO carries the password extension
	const char *motd;          // the INFO carries this MOTD
	int handshake;             // pong flood: complete the Wisp handshake first
	int flood_on_data;         // flood: start at the client's first DATA instead of its CONNECT
	uint32_t flood_stream;
	size_t flood_len; // payload of each flooded DATA packet
	_Atomic int go;   // the test lets the script take its next step
	_Atomic int stop; // fake_join: whatever the script is doing, end it
	// ------------------------------------------------------------------------------------------
	int offered_protocol; // the upgrade request carried Sec-WebSocket-Protocol
	int client_info;      // INFO packets the client sent
	int client_password;  // ... that carried the password extension
	char user[64];
	char pass[64];
	int connects; // CONNECT packets the client sent
	size_t connect_host_len;
	int data_packets; // DATA packets the client sent

	int lfd;
	uint16_t port;
	pthread_t thread;
	uint64_t deadline;
};

static int fake_over(const fake *f) {
	return atomic_load(&f->stop) || hw_now_ms() >= f->deadline;
}

static int fake_send(fake *f, int fd, const void *data, size_t len) {
	const uint8_t *p = data;
	while (len > 0) {
		if (fake_over(f)) return -1;
		ssize_t n = send(fd, p, len, HW_MSG_NOSIGNAL);
		if (n > 0) {
			p += n;
			len -= (size_t)n;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd pfd = {.fd = fd, .events = POLLOUT};
			poll(&pfd, 1, FAKE_SLICE_MS);
		} else if (n == 0 || errno != EINTR) {
			return -1;
		}
	}
	return 0;
}

// Read exactly n bytes. 1 done, 0 when not one byte came within timeout_ms, -1 when the client is
// gone, the script is over or the bytes stopped half way.
static int fake_recv(fake *f, int fd, uint8_t *buf, size_t n, int timeout_ms) {
	size_t got = 0;
	uint64_t until = hw_now_ms() + (uint64_t)timeout_ms;
	while (got < n) {
		if (hw_now_ms() >= f->deadline) return -1;
		if (got == 0 && hw_now_ms() >= until) return 0;
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		if (poll(&pfd, 1, FAKE_SLICE_MS) <= 0) continue;
		ssize_t r = recv(fd, buf + got, n - got, 0);
		if (r > 0) {
			got += (size_t)r;
		} else if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
			return -1;
		}
	}
	return 1;
}

static size_t frame_write(uint8_t *out, uint8_t opcode, const void *payload, size_t len) {
	size_t hl = hw_ws_write_header(out, 1, opcode, len, NULL);
	if (len) memcpy(out + hl, payload, len);
	return hl + len;
}

static size_t packet_write(uint8_t *out, uint8_t type, uint32_t sid, const void *payload, size_t len) {
	size_t hl = hw_ws_write_header(out, 1, HW_WS_BINARY, HW_WISP_HEADER_LEN + len, NULL);
	hw_wisp_write_header(out + hl, type, sid);
	if (len) memcpy(out + hl + HW_WISP_HEADER_LEN, payload, len);
	return hl + HW_WISP_HEADER_LEN + len;
}

static int fake_packet(fake *f, int fd, uint8_t type, uint32_t sid, const void *payload, size_t len) {
	uint8_t buf[HW_WS_MAX_HEADER + HW_WISP_HEADER_LEN + FAKE_FRAME_MAX];
	CHECK(len <= FAKE_FRAME_MAX, "packet of %zu bytes", len);
	return fake_send(f, fd, buf, packet_write(buf, type, sid, payload, len));
}

static int fake_continue(fake *f, int fd, uint32_t sid, uint32_t n) {
	uint8_t le[4];
	hw_put_le32(le, n);
	return fake_packet(f, fd, HW_WISP_CONTINUE, sid, le, sizeof(le));
}

// Record what one unmasked client message was.
static void fake_note(fake *f, const uint8_t *msg, size_t len) {
	hw_wisp_packet p;
	if (hw_wisp_parse(msg, len, &p) != 0) return;
	if (p.type == HW_WISP_DATA) f->data_packets++;
	if (p.type == HW_WISP_CONNECT) {
		hw_wisp_connect cn;
		if (hw_wisp_parse_connect(&p, &cn) == 0) f->connect_host_len = cn.host_len;
		f->connects++;
	}
	if (p.type == HW_WISP_INFO) {
		hw_wisp_info info;
		f->client_info++;
		if (hw_wisp_parse_info(&p, &info) != 0 || !info.has_password) return;
		f->client_password++;
		if (info.user && info.user_len < sizeof(f->user)) memcpy(f->user, info.user, info.user_len);
		if (info.pass && info.pass_len < sizeof(f->pass)) memcpy(f->pass, info.pass, info.pass_len);
	}
}

// Read and record one client frame. 1 read, 0 nothing came within timeout_ms, -1 the client is gone.
static int fake_read(fake *f, int fd, int timeout_ms) {
	uint8_t head[HW_WS_MAX_HEADER];
	uint8_t body[FAKE_FRAME_MAX];
	int r = fake_recv(f, fd, head, 2, timeout_ms);
	if (r <= 0) return r;
	hw_ws_frame fr;
	size_t have = 2;
	while (hw_ws_parse_header(head, have, &fr) == HW_ERR_AGAIN) {
		if (have == sizeof(head) || fake_recv(f, fd, head + have, 1, FAKE_LIFE_MS) != 1) return -1;
		have++;
	}
	if (!fr.masked || fr.payload_len > sizeof(body)) return -1;
	size_t len = (size_t)fr.payload_len;
	if (len && fake_recv(f, fd, body, len, FAKE_LIFE_MS) != 1) return -1;
	hw_ws_mask(body, len, fr.mask, 0);
	if (fr.opcode == HW_WS_BINARY) fake_note(f, body, len);
	return 1;
}

// Keep reading what the client sends until it hangs up, so that the counters are complete.
static void fake_hold(fake *f, int fd) {
	while (fake_read(f, fd, FAKE_SLICE_MS) >= 0) {
	}
}

// Read until *counter reaches want. 0 when it did, -1 when the client left first.
static int fake_await(fake *f, int fd, const int *counter, int want) {
	while (*counter < want) {
		if (fake_read(f, fd, FAKE_SLICE_MS) < 0) return -1;
	}
	return 0;
}

static void *fake_main(void *arg) {
	fake *f = arg;
	int fd = -1;
	while (fd < 0 && !fake_over(f)) {
		struct pollfd pfd = {.fd = f->lfd, .events = POLLIN};
		if (poll(&pfd, 1, FAKE_SLICE_MS) > 0) fd = hw_sys_accept(f->lfd, NULL, NULL);
	}
	if (fd < 0) return NULL;
	hw_tcp_tune(fd, 1);
	uint8_t head[HW_HTTP_MAX_REQUEST];
	size_t have = 0;
	hw_http_request *req = malloc(sizeof(*req));
	CHECK(req != NULL, "out of memory");
	int r;
	while ((r = hw_http_parse_request(head, have, req)) == HW_ERR_AGAIN && have < sizeof(head)) {
		if (fake_recv(f, fd, head + have, 1, FAKE_LIFE_MS) != 1) break;
		have++;
	}
	if (r > 0) {
		f->offered_protocol = req->ws_protocol[0] != '\0';
		char accept[HW_WS_ACCEPT_LEN + 1];
		char resp[512];
		hw_ws_accept_key(req->ws_key, accept);
		int n = snprintf(resp, sizeof(resp),
		                 "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
		                 "Sec-WebSocket-Accept: %s\r\n%s%s%s\r\n",
		                 accept, f->echo_protocol ? "Sec-WebSocket-Protocol: " : "",
		                 f->echo_protocol ? f->echo_protocol : "", f->echo_protocol ? "\r\n" : "");
		if (f->raw_response) {
			fake_send(f, fd, f->raw_response, strlen(f->raw_response));
		} else if (fake_send(f, fd, resp, (size_t)n) == 0) {
			f->script(f, fd);
		}
	}
	free(req);
	close(fd);
	return NULL;
}

static void fake_start(fake *f) {
	f->lfd = hw_listen_tcp("127.0.0.1", 0, 0, 4, &f->port);
	CHECK(f->lfd >= 0, "listen: %s", strerror(errno));
	f->deadline = hw_now_ms() + FAKE_LIFE_MS;
	CHECK_EQ(pthread_create(&f->thread, NULL, fake_main, f), 0);
}

static void fake_join(fake *f) {
	atomic_store(&f->stop, 1);
	pthread_join(f->thread, NULL);
	close(f->lfd);
}

// ---------------------------------------------------------------------------------- scripts

// A v1 server and nothing more.
static void script_plain(fake *f, int fd) {
	if (fake_continue(f, fd, 0, f->window) != 0) return;
	fake_hold(f, fd);
}

// The window the server advertises is never refilled until the test says so.
static void script_withhold(fake *f, int fd) {
	if (fake_continue(f, fd, 0, f->window) != 0) return;
	while (!atomic_load(&f->go)) {
		if (fake_read(f, fd, FAKE_SLICE_MS) < 0) return;
	}
	if (fake_continue(f, fd, 1, 4) != 0) return;
	fake_hold(f, fd);
}

// Once the client is committed (its CONNECT, or its first DATA), send it DATA packets as fast as
// the socket takes them and never a CONTINUE.
static void script_flood(fake *f, int fd) {
	if (fake_continue(f, fd, 0, f->window) != 0) return;
	if (fake_await(f, fd, f->flood_on_data ? &f->data_packets : &f->connects, 1) != 0) return;
	uint8_t *payload = calloc(1, FLOOD_DATA_LEN);
	uint8_t *blob = malloc(FLOOD_BLOB + HW_WS_MAX_HEADER + HW_WISP_HEADER_LEN + FLOOD_DATA_LEN);
	CHECK(payload && blob, "out of memory");
	size_t blob_len = 0;
	size_t per_blob = 0;
	while (blob_len < FLOOD_BLOB) {
		blob_len += packet_write(blob + blob_len, HW_WISP_DATA, f->flood_stream, payload, f->flood_len);
		per_blob++;
	}
	size_t total = f->flood_len ? FLOOD_DATA_BYTES / f->flood_len : FLOOD_EMPTY;
	for (size_t sent = 0; sent < total; sent += per_blob) {
		if (fake_send(f, fd, blob, blob_len) != 0) break;
	}
	free(payload);
	free(blob);
	fake_hold(f, fd);
}

// A v2 server: INFO, the client's INFO, CONTINUE.
static void script_v2(fake *f, int fd) {
	uint8_t info[2 + 5 + 1 + 5 + 256];
	size_t n = 0;
	info[n++] = HW_WISP_MAJOR;
	info[n++] = HW_WISP_MINOR;
	if (f->advertise_password) {
		uint8_t required = 1;
		n += hw_wisp_build_extension(info + n, sizeof(info) - n, HW_EXT_PASSWORD, &required, 1);
	}
	if (f->motd) {
		n += hw_wisp_build_extension(info + n, sizeof(info) - n, HW_EXT_MOTD, f->motd, (uint32_t)strlen(f->motd));
	}
	if (fake_packet(f, fd, HW_WISP_INFO, 0, info, n) != 0) return;
	if (fake_await(f, fd, &f->client_info, 1) != 0) return;
	if (fake_continue(f, fd, 0, f->window) != 0) return;
	fake_hold(f, fd);
}

// After the handshake, a packet that is no event every 100 ms, for as long as the client stays.
static void script_trickle(fake *f, int fd) {
	static const uint8_t info[2] = {HW_WISP_MAJOR, HW_WISP_MINOR};
	if (fake_continue(f, fd, 0, f->window) != 0) return;
	while (fake_packet(f, fd, HW_WISP_INFO, 0, info, sizeof(info)) == 0) {
		uint64_t next = hw_now_ms() + 100;
		while (hw_now_ms() < next) {
			if (fake_read(f, fd, FAKE_SLICE_MS) < 0) return;
		}
	}
}

// Empty PONG frames as fast as the socket takes them: the reader is never left without one.
static void script_pong_flood(fake *f, int fd) {
	if (f->handshake && fake_continue(f, fd, 0, f->window) != 0) return;
	uint8_t *blob = malloc(FLOOD_BLOB);
	CHECK(blob != NULL, "out of memory");
	for (size_t n = 0; n + 2 <= FLOOD_BLOB;) n += frame_write(blob + n, HW_WS_PONG, NULL, 0);
	while (fake_send(f, fd, blob, FLOOD_BLOB) == 0) {
	}
	free(blob);
}

// Two packets for stream 1 with one for another stream between them, then the CLOSE.
static void script_pieces(fake *f, int fd) {
	uint8_t reason = HW_CLOSE_VOLUNTARY;
	if (fake_continue(f, fd, 0, f->window) != 0) return;
	if (fake_await(f, fd, &f->connects, 1) != 0) return;
	if (fake_packet(f, fd, HW_WISP_DATA, 1, "abc", 3) != 0) return;
	if (fake_packet(f, fd, HW_WISP_DATA, OTHER_STREAM, "zz", 2) != 0) return;
	if (fake_packet(f, fd, HW_WISP_DATA, 1, "defgh", 5) != 0) return;
	if (fake_packet(f, fd, HW_WISP_CLOSE, 1, &reason, 1) != 0) return;
	fake_hold(f, fd);
}

// ---------------------------------------------------------------------------------- helpers

static void client_opts(hw_client_opts *o, const fake *f, int timeout_ms) {
	hw_client_opts_defaults(o);
	o->host = "127.0.0.1";
	o->port = f->port;
	o->timeout_ms = timeout_ms;
}

static hw_client *client_connect(const hw_client_opts *o) {
	char err[256];
	hw_client *c = hw_client_connect(o, err, sizeof(err));
	CHECK(c != NULL, "connect: %s", err);
	return c;
}

// Every queued event, without waiting. The result is what ended the drain.
static int drain_queue(hw_client *c, size_t *events, size_t *bytes) {
	hw_client_event ev;
	int r;
	*events = 0;
	*bytes = 0;
	while ((r = hw_client_poll(c, 0, &ev)) > 0) {
		(*events)++;
		if (ev.type == HW_CEV_DATA) *bytes += ev.len;
	}
	return r;
}

// ---------------------------------------------------------------------------------- cases

// A window of zero and no CONTINUE: the send gives up when the client's timeout says so, has sent
// nothing, and works once the server does send one.
static void test_send_waits_no_longer_than_the_timeout(void) {
	fake f = {.script = script_withhold, .window = 0};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 300);
	hw_client *c = client_connect(&o);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "example.com", 80, &sid), 0);
	CHECK_EQ(sid, 1);
	uint64_t t0 = hw_now_ms();
	int r = hw_client_send(c, sid, "x", 1);
	uint64_t took = hw_now_ms() - t0;
	CHECK(r == HW_ERR_TIMEOUT, "send without credit returned %d after %llu ms", r, (unsigned long long)took);
	CHECK(took >= 250 && took < 2500, "a 300 ms wait took %llu ms", (unsigned long long)took);

	atomic_store(&f.go, 1);
	for (int i = 0; i < 10 && (r = hw_client_send(c, sid, "y", 1)) == HW_ERR_TIMEOUT; i++) {
	}
	CHECK(r == 0, "send after the CONTINUE returned %d", r);
	hw_client_free(c);
	fake_join(&f);
	CHECK(f.data_packets == 1, "the send that timed out put %d packets on the wire", f.data_packets - 1);
}

// A window of one, never refilled, and a flood behind it. The second send has to wait for a
// CONTINUE and queues what arrives: it must fail when the queue's budget is spent, with no more
// than the budget held.
static void send_flood_case(size_t flood_len, size_t max_bytes, size_t max_events) {
	fake f = {.script = script_flood, .window = 1, .flood_on_data = 1, .flood_stream = 1, .flood_len = flood_len};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 5000);
	o.max_queue_bytes = max_bytes;
	o.max_queue_events = max_events;
	hw_client *c = client_connect(&o);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "example.com", 80, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "x", 1), 0);
	int r = hw_client_send(c, sid, "x", 1);
	CHECK(r == HW_ERR_TOOBIG, "send into a flood returned %d", r);

	size_t events, bytes;
	CHECK_EQ(drain_queue(c, &events, &bytes), HW_ERR_CLOSED);
	CHECK(events > 0 && events <= max_events, "%zu events queued, limit %zu", events, max_events);
	CHECK(bytes <= max_bytes, "%zu bytes queued, limit %zu", bytes, max_bytes);
	CHECK_EQ(hw_client_send(c, sid, "x", 1), HW_ERR_CLOSED);
	hw_client_free(c);
	fake_join(&f);
}

static void test_send_queue_is_bounded_in_bytes(void) {
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	CHECK(o.max_queue_bytes >= 1024 * 1024 && o.max_queue_bytes <= 64 * 1024 * 1024, "default of %zu bytes",
	      o.max_queue_bytes);
	send_flood_case(FLOOD_DATA_LEN, 1024 * 1024, o.max_queue_events);
}

static void test_send_queue_is_bounded_in_events(void) {
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	CHECK(o.max_queue_events >= 1024 && o.max_queue_events <= 1024 * 1024, "default of %zu events", o.max_queue_events);
	send_flood_case(0, o.max_queue_bytes, 500);
}

// The same for the events hw_client_read_exact sets aside while it waits for one stream's bytes.
static void test_read_exact_queue_is_bounded(void) {
	fake f = {.script = script_flood, .window = 8, .flood_stream = OTHER_STREAM, .flood_len = FLOOD_DATA_LEN};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 5000);
	o.max_queue_bytes = 1024 * 1024;
	hw_client *c = client_connect(&o);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "example.com", 80, &sid), 0);
	uint8_t buf[4];
	long long n = hw_client_read_exact(c, sid, buf, sizeof(buf), 5000);
	CHECK(n == HW_ERR_TOOBIG, "read_exact beside a flood returned %lld", n);

	size_t events, bytes;
	CHECK_EQ(drain_queue(c, &events, &bytes), HW_ERR_CLOSED);
	CHECK(bytes > 0 && bytes <= o.max_queue_bytes, "%zu bytes queued, limit %zu", bytes, o.max_queue_bytes);
	hw_client_free(c);
	fake_join(&f);
}

// Credentials go to a server that advertised the password extension and to no other, and the
// caller can tell which it was.
static void test_password_only_when_the_server_asks(void) {
	for (int advertise = 0; advertise <= 1; advertise++) {
		fake f = {.script = script_v2, .window = 8, .echo_protocol = HW_WISP_V2_PROTOCOL};
		f.advertise_password = advertise;
		fake_start(&f);
		hw_client_opts o;
		client_opts(&o, &f, 3000);
		o.v2 = 1;
		o.user = "alice";
		o.pass = "Tr0ub4dor&3";
		hw_client *c = client_connect(&o);
		CHECK_EQ(hw_client_is_v2(c), 1);
		CHECK_EQ(hw_client_authenticated(c), advertise);
		hw_client_free(c);
		fake_join(&f);
		CHECK_EQ(f.client_info, 1);
		CHECK(f.client_password == advertise, "password extension sent %d times to a server that %s for it",
		      f.client_password, advertise ? "asked" : "did not ask");
		CHECK_STR(f.user, advertise ? "alice" : "");
		CHECK_STR(f.pass, advertise ? "Tr0ub4dor&3" : "");
	}

	// Without credentials there is nothing to send, whatever the server advertises.
	fake f = {.script = script_v2, .window = 8, .echo_protocol = HW_WISP_V2_PROTOCOL, .advertise_password = 1};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 3000);
	o.v2 = 1;
	hw_client *c = client_connect(&o);
	CHECK_EQ(hw_client_authenticated(c), 0);
	hw_client_free(c);
	fake_join(&f);
	CHECK_EQ(f.client_password, 0);
}

// A server that answers "wisp-v2" to a client that did not offer it does not get a v2 client, and
// so no INFO and no password.
static void test_unoffered_subprotocol_is_refused(void) {
	fake f = {.script = script_v2, .window = 8, .echo_protocol = HW_WISP_V2_PROTOCOL, .advertise_password = 1};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 1000);
	o.user = "alice";
	o.pass = "Tr0ub4dor&3";
	char err[256] = "";
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c == NULL, "connected as wisp-v%d to a server that chose the protocol itself", hw_client_is_v2(c) ? 2 : 1);
	CHECK(strstr(err, "subprotocol") != NULL, "error was: %s", err);
	fake_join(&f);
	CHECK_EQ(f.offered_protocol, 0);
	CHECK_EQ(f.client_info, 0);
	CHECK_EQ(f.client_password, 0);
}

// A password that does not fit the extension is an error, not a shorter password.
static void test_long_credentials_are_refused(void) {
	fake f = {.script = script_v2, .window = 8, .echo_protocol = HW_WISP_V2_PROTOCOL, .advertise_password = 1};
	fake_start(&f);
	char pass[129];
	memset(pass, 'p', sizeof(pass) - 1);
	pass[sizeof(pass) - 1] = '\0';
	hw_client_opts o;
	client_opts(&o, &f, 1000);
	o.v2 = 1;
	o.user = "alice";
	o.pass = pass;
	char err[256] = "";
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c == NULL, "connected with a password of %zu bytes", strlen(pass));
	CHECK(strstr(err, "password") != NULL, "error was: %s", err);
	fake_join(&f);
	CHECK_EQ(f.client_password, 0);
}

// Packets that are no events arrive every 100 ms: a 300 ms wait is still 300 ms.
static void test_poll_timeout_is_a_bound(void) {
	fake f = {.script = script_trickle, .window = 128};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 3000);
	hw_client *c = client_connect(&o);
	hw_client_event ev;
	uint64_t t0 = hw_now_ms();
	int r = hw_client_poll(c, 300, &ev);
	uint64_t took = hw_now_ms() - t0;
	CHECK(r == 0, "poll returned %d after %llu ms", r, (unsigned long long)took);
	CHECK(took >= 250 && took < 1500, "a 300 ms poll took %llu ms", (unsigned long long)took);

	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "example.com", 80, &sid), 0);
	uint8_t buf[4];
	t0 = hw_now_ms();
	long long n = hw_client_read_exact(c, sid, buf, sizeof(buf), 300);
	took = hw_now_ms() - t0;
	CHECK(n == HW_ERR_TIMEOUT, "read_exact returned %lld after %llu ms", n, (unsigned long long)took);
	CHECK(took >= 250 && took < 1500, "a 300 ms read_exact took %llu ms", (unsigned long long)took);
	hw_client_free(c);
	fake_join(&f);
}

// The same with frames that never reach the packet layer, sent faster than they can be read.
static void test_poll_timeout_holds_under_a_pong_flood(void) {
	fake f = {.script = script_pong_flood, .window = 128, .handshake = 1};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 3000);
	hw_client *c = client_connect(&o);
	hw_client_event ev;
	uint64_t t0 = hw_now_ms();
	int r = hw_client_poll(c, 300, &ev);
	uint64_t took = hw_now_ms() - t0;
	CHECK(r == 0, "poll returned %d after %llu ms", r, (unsigned long long)took);
	CHECK(took >= 250 && took < 1500, "a 300 ms poll took %llu ms", (unsigned long long)took);
	hw_client_free(c);
	fake_join(&f);
}

// And during the handshake, which the server never completes.
static void test_connect_timeout_is_a_bound(void) {
	fake f = {.script = script_pong_flood};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 300);
	char err[256] = "";
	uint64_t t0 = hw_now_ms();
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	uint64_t took = hw_now_ms() - t0;
	CHECK(c == NULL, "connected to a server that never sent a CONTINUE");
	CHECK(strstr(err, "timed out") != NULL, "error after %llu ms was: %s", (unsigned long long)took, err);
	CHECK(took >= 250 && took < 1500, "a 300 ms connect took %llu ms", (unsigned long long)took);
	fake_join(&f);
}

static void test_printable(void) {
	char out[64];
	CHECK_EQ(hw_client_printable(out, sizeof(out), "plain text ~", 12), 12);
	CHECK_STR(out, "plain text ~");
	// ESC, CR, LF, DEL, a raw C1 byte and CSI as UTF-8 encodes it.
	CHECK_EQ(hw_client_printable(out, sizeof(out), "a\x1b[2J\r\n\x7f\x9b\xc2\x9b", 11), 4 + 7 * 4);
	CHECK_STR(out, "a\\x1b[2J\\x0d\\x0a\\x7f\\x9b\\xc2\\x9b");
	CHECK_EQ(hw_client_printable(out, sizeof(out), "a\0b", 3), 6);
	CHECK_STR(out, "a\\x00b");
	// An escape that does not fit is left out whole, and what follows it with it.
	CHECK_EQ(hw_client_printable(out, 6, "ab\001c", 4), 2);
	CHECK_STR(out, "ab");
	CHECK_EQ(hw_client_printable(out, 7, "ab\001c", 4), 6);
	CHECK_STR(out, "ab\\x01");
	out[0] = 'x';
	CHECK_EQ(hw_client_printable(out, 1, "abc", 3), 0);
	CHECK_STR(out, "");
	out[0] = 'x';
	CHECK_EQ(hw_client_printable(out, 0, "abc", 3), 0);
	CHECK_EQ(out[0], 'x');
}

static int is_printable(const char *s) {
	for (; *s; s++) {
		if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7e) return 0;
	}
	return 1;
}

// What the server says where an HTTP response or a MOTD belongs ends up on a terminal.
static void test_server_text_is_escaped(void) {
	fake bad = {.raw_response = "HTTP/1.1 500 \x1b]0;TITLE\x07\x1b[2J\x1b[1;31mfake prompt$ \r\n\r\n"};
	fake_start(&bad);
	hw_client_opts o;
	client_opts(&o, &bad, 1000);
	char err[512] = "";
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c == NULL, "connected through a 500");
	CHECK(is_printable(err), "raw bytes in the error");
	CHECK(strstr(err, "500 \\x1b]0;TITLE\\x07\\x1b[2J") != NULL, "error was: %s", err);
	fake_join(&bad);

	const char *motd = "hi\x1b]0;TITLE\x07\r\nconnected: a forged line";
	fake f = {.script = script_v2, .window = 8, .echo_protocol = HW_WISP_V2_PROTOCOL, .motd = motd};
	fake_start(&f);
	client_opts(&o, &f, 3000);
	o.v2 = 1;
	c = client_connect(&o);
	// The library keeps the MOTD as it came (it may be UTF-8); printing it is hw_client_printable's.
	CHECK_STR(hw_client_motd(c), motd);
	char shown[256];
	hw_client_printable(shown, sizeof(shown), hw_client_motd(c), strlen(hw_client_motd(c)));
	CHECK_STR(shown, "hi\\x1b]0;TITLE\\x07\\x0d\\x0aconnected: a forged line");
	hw_client_free(c);
	fake_join(&f);
}

// A hostname the CONNECT cannot carry whole is refused, never cut: "<250 bytes>.trusted.example"
// with ".evil.example" behind it must not be opened as the trusted name.
static void test_open_refuses_a_host_that_does_not_fit(void) {
	fake f = {.script = script_plain, .window = 8};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 3000);
	hw_client *c = client_connect(&o);
	char host[257];
	memset(host, 'a', sizeof(host));
	host[256] = '\0';
	uint32_t sid = 0;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, host, 80, &sid), HW_ERR_INVALID);
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "", 80, &sid), HW_ERR_INVALID);
	host[255] = '\0';
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, host, 80, &sid), 0);
	CHECK_EQ(sid, 1);
	hw_client_free(c);
	fake_join(&f);
	CHECK(f.connects == 1, "%d CONNECT packets for one valid host", f.connects);
	CHECK_EQ(f.connect_host_len, 255);
}

// The count is a long long (a long is 32 bits on Windows), a packet that holds more than was
// asked for keeps its rest, and events for other streams and the CLOSE stay in order.
static void test_read_exact_counts_and_keeps_the_rest(void) {
	long long (*read_exact)(hw_client *, uint32_t, uint8_t *, size_t, int) = hw_client_read_exact;
	fake f = {.script = script_pieces, .window = 8};
	fake_start(&f);
	hw_client_opts o;
	client_opts(&o, &f, 3000);
	hw_client *c = client_connect(&o);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "example.com", 80, &sid), 0);
	CHECK_EQ(sid, 1);
	uint8_t buf[16];
	CHECK_EQ(read_exact(c, sid, buf, 4, 3000), 4);
	CHECK(memcmp(buf, "abcd", 4) == 0, "first four bytes");
	CHECK_EQ(read_exact(c, sid, buf, 2, 3000), 2);
	CHECK(memcmp(buf, "ef", 2) == 0, "next two bytes");
	hw_client_event ev;
	CHECK_EQ(hw_client_poll(c, 3000, &ev), 1);
	CHECK(ev.type == HW_CEV_DATA && ev.stream_id == OTHER_STREAM && ev.len == 2, "the other stream's packet");
	// Two bytes are left and then the stream closes: fewer than asked for, and the CLOSE is kept.
	CHECK_EQ(read_exact(c, sid, buf, 10, 3000), 2);
	CHECK(memcmp(buf, "gh", 2) == 0, "last two bytes");
	CHECK_EQ(hw_client_poll(c, 3000, &ev), 1);
	CHECK(ev.type == HW_CEV_CLOSE && ev.stream_id == sid && ev.reason == HW_CLOSE_VOLUNTARY, "the CLOSE");
	hw_client_free(c);
	fake_join(&f);
}

int main(void) {
	RUN(test_send_waits_no_longer_than_the_timeout);
	RUN(test_send_queue_is_bounded_in_bytes);
	RUN(test_send_queue_is_bounded_in_events);
	RUN(test_read_exact_queue_is_bounded);
	RUN(test_password_only_when_the_server_asks);
	RUN(test_unoffered_subprotocol_is_refused);
	RUN(test_long_credentials_are_refused);
	RUN(test_poll_timeout_is_a_bound);
	RUN(test_poll_timeout_holds_under_a_pong_flood);
	RUN(test_connect_timeout_is_a_bound);
	RUN(test_printable);
	RUN(test_server_text_is_escaped);
	RUN(test_open_refuses_a_host_that_does_not_fit);
	RUN(test_read_exact_counts_and_keeps_the_rest);
	return 0;
}

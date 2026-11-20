/*
 * holywisp/log.h: one call is one line, whatever a client put into the strings it is given.
 */
#include "holywisp/log.h"
#include "holywisp/server.h"

#include "server/config.h"
#include "test.h"

#include <unistd.h>

#define CAPTURE_MAX 8192

// Run one hw_log call with stderr pointed at a file and return what it wrote.
static size_t capture_at(int level, char *out, size_t cap, const char *tag, const char *text) {
	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-log");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	fflush(stderr);
	int saved = dup(STDERR_FILENO);
	CHECK(saved >= 0, "dup");
	CHECK(dup2(fd, STDERR_FILENO) >= 0, "dup2");
	hw_log(level, tag, "%s", text);
	CHECK(dup2(saved, STDERR_FILENO) >= 0, "restore stderr");
	close(saved);
	close(fd);
	FILE *f = fopen(path, "rb");
	CHECK(f != NULL, "reopen");
	size_t n = fread(out, 1, cap - 1, f);
	fclose(f);
	unlink(path);
	out[n] = '\0';
	return n;
}

static size_t capture(char *out, size_t cap, const char *tag, const char *text) {
	return capture_at(HW_LOG_ERROR, out, cap, tag, text);
}

static size_t count_byte(const char *s, size_t n, char c) {
	size_t k = 0;
	for (size_t i = 0; i < n; i++) k += s[i] == c;
	return k;
}

static void test_plain_line(void) {
	char out[CAPTURE_MAX];
	size_t n = capture(out, sizeof(out), "conn", "hello world 42");
	CHECK(n > 0 && out[n - 1] == '\n', "the line ends in its newline");
	CHECK_EQ(count_byte(out, n, '\n'), 1);
	CHECK(strstr(out, "[error] conn: hello world 42\n") != NULL, "got \"%s\"", out);
	// What is not a control byte is left alone, UTF-8 included.
	n = capture(out, sizeof(out), "conn", "caf\xc3\xa9 \\ \"quoted\" ~");
	CHECK_EQ(count_byte(out, n, '\n'), 1);
	CHECK(strstr(out, "conn: caf\xc3\xa9 \\ \"quoted\" ~\n") != NULL, "got \"%s\"", out);
}

// A CONNECT host with a line feed in it: without the escape this is two log lines, the second
// one written by the client.
static void test_no_forged_line(void) {
	char out[CAPTURE_MAX];
	size_t n = capture(out, sizeof(out), "filter",
	                   "blocked evil.test\n2026-01-01T00:00:00.000Z [info] auth: admin logged in\r\n:80");
	CHECK_EQ(count_byte(out, n, '\n'), 1);
	CHECK_EQ(count_byte(out, n, '\r'), 0);
	CHECK(out[n - 1] == '\n', "the one newline is the line's own");
	CHECK(strstr(out, "evil.test\\x0a2026-01-01T00:00:00.000Z [info] auth: admin logged in\\x0d\\x0a:80\n") != NULL,
	      "got \"%s\"", out);
}

static void test_no_terminal_escapes(void) {
	char out[CAPTURE_MAX];
	size_t n = capture(out, sizeof(out), "auth", "user \x1b[2J\x1b]0;owned\x07 tab\there del\x7f bell\x01");
	CHECK_EQ(count_byte(out, n, '\x1b'), 0);
	CHECK_EQ(count_byte(out, n, '\x07'), 0);
	CHECK_EQ(count_byte(out, n, '\t'), 0);
	CHECK_EQ(count_byte(out, n, '\x7f'), 0);
	CHECK(strstr(out, "user \\x1b[2J\\x1b]0;owned\\x07 tab\\x09here del\\x7f bell\\x01\n") != NULL, "got \"%s\"", out);
	// The tag goes through the same sink.
	n = capture(out, sizeof(out), "ta\ng", "x");
	CHECK_EQ(count_byte(out, n, '\n'), 1);
	CHECK(strstr(out, "ta\\x0ag: x\n") != NULL, "got \"%s\"", out);
}

// A message that grows past the line when escaped is cut between escapes, never inside one, and
// still ends in exactly one newline.
static void test_long_message(void) {
	static char text[4000];
	memset(text, '\n', sizeof(text) - 1);
	char out[CAPTURE_MAX];
	size_t n = capture(out, sizeof(out), "conn", text);
	CHECK(n > 900 && n <= 1024, "line of %zu bytes", n);
	CHECK_EQ(count_byte(out, n, '\n'), 1);
	CHECK(out[n - 1] == '\n', "ends in the newline");
	CHECK(n >= 5 && memcmp(out + n - 5, "\\x0a\n", 5) == 0, "the last escape is whole: \"%s\"", out + n - 9);
	// The same for one that is too long as it is.
	memset(text, 'a', sizeof(text) - 1);
	n = capture(out, sizeof(out), "conn", text);
	CHECK(n > 900 && n <= 1024, "line of %zu bytes", n);
	CHECK_EQ(count_byte(out, n, '\n'), 1);
}

static void test_levels(void) {
	CHECK_EQ(hw_log_level_parse("debug"), HW_LOG_DEBUG);
	CHECK_EQ(hw_log_level_parse("WARNING"), HW_LOG_WARN);
	CHECK_EQ(hw_log_level_parse("loud"), -1);
	// Every level's name is the one the parser takes back, and a level out of range is the nearest.
	for (int l = HW_LOG_DEBUG; l <= HW_LOG_NONE; l++) CHECK_EQ(hw_log_level_parse(hw_log_level_name(l)), l);
	CHECK_STR(hw_log_level_name(-3), "debug");
	CHECK_STR(hw_log_level_name(HW_LOG_WARN), "warn");
	CHECK_STR(hw_log_level_name(99), "none");
	int before = hw_log_get_level();
	hw_log_set_level(99);
	CHECK_EQ(hw_log_get_level(), HW_LOG_NONE);
	hw_log_set_level(before);
	// A level that is not one writes nothing.
	char out[CAPTURE_MAX];
	CHECK_EQ(capture_at(HW_LOG_NONE, out, sizeof(out), "conn", "never written"), 0);
	CHECK_EQ(capture_at(-1, out, sizeof(out), "conn", "never written"), 0);
	CHECK(capture_at(HW_LOG_DEBUG, out, sizeof(out), "conn", "written") > 0, "debug is a level");
}

// One statement's budget: HW_LOG_BURST lines a second, the rest counted, and the count handed to
// the first line of a later second. A burst that is spent stays spent until the second turns.
static void test_limit(void) {
	hw_log_limit l;
	memset(&l, 0, sizeof(l));
	uint32_t held = 99;
	for (int i = 0; i < HW_LOG_BURST; i++) {
		CHECK(hw_log_limit_take(&l, 5000 + (uint64_t)i, &held), "line %d of the burst", i);
		CHECK_EQ(held, 0);
	}
	for (int i = 0; i < 30; i++) CHECK(!hw_log_limit_take(&l, 5900, &held), "line %d past the burst", i);
	CHECK(hw_log_limit_take(&l, 6000, &held), "a new second");
	CHECK_EQ(held, 30);
	CHECK(hw_log_limit_take(&l, 6001, &held), "the count was handed over once");
	CHECK_EQ(held, 0);
	// A clock that has not moved does not refill it, one far later does.
	for (int i = 2; i < HW_LOG_BURST; i++) CHECK(hw_log_limit_take(&l, 6500, &held), "line %d", i);
	CHECK(!hw_log_limit_take(&l, 6999, &held), "spent");
	CHECK(hw_log_limit_take(&l, 1000000, &held), "much later");
	CHECK_EQ(held, 1);

	// Through the macro: a statement reached 100 times in one burst writes at most two seconds' worth.
	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-log-limit");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	fflush(stderr);
	int saved = dup(STDERR_FILENO);
	CHECK(dup2(fd, STDERR_FILENO) >= 0, "dup2");
	int before = hw_log_get_level();
	hw_log_set_level(HW_LOG_INFO);
	for (int i = 0; i < 100; i++) HW_WARN_LIMITED("flood", "line %d", i);
	hw_log_set_level(before);
	CHECK(dup2(saved, STDERR_FILENO) >= 0, "restore stderr");
	close(saved);
	close(fd);
	static char out[64 * 1024];
	FILE *f = fopen(path, "rb");
	CHECK(f != NULL, "reopen");
	size_t n = fread(out, 1, sizeof(out) - 1, f);
	fclose(f);
	unlink(path);
	out[n] = '\0';
	size_t lines = count_byte(out, n, '\n');
	CHECK(lines >= HW_LOG_BURST && lines <= 2 * HW_LOG_BURST + 1, "%zu lines written", lines);
	CHECK(strstr(out, "flood: line 0\n") != NULL, "the first line is there");
}

// stderr into a file from capture_begin to capture_end, which returns what was written.
typedef struct {
	char path[512];
	int fd, saved;
} capture_state;

static void capture_begin(capture_state *st) {
	hw_test_tmp(st->path, sizeof(st->path), "hw-log-cap");
	st->fd = mkstemp(st->path);
	CHECK(st->fd >= 0, "tmp");
	fflush(stderr);
	st->saved = dup(STDERR_FILENO);
	CHECK(st->saved >= 0, "dup");
	CHECK(dup2(st->fd, STDERR_FILENO) >= 0, "dup2");
}

static size_t capture_end(capture_state *st, char *out, size_t cap) {
	fflush(stderr);
	CHECK(dup2(st->saved, STDERR_FILENO) >= 0, "restore stderr");
	close(st->saved);
	close(st->fd);
	FILE *f = fopen(st->path, "rb");
	CHECK(f != NULL, "reopen");
	size_t n = fread(out, 1, cap - 1, f);
	fclose(f);
	unlink(st->path);
	out[n] = '\0';
	return n;
}

// The proxy setting may hold a user name and a password, and its host is the operator's: none of
// it reaches the log, not when its host does not resolve and not when the setting is refused.
static void test_proxy_never_logged(void) {
	static const char *const secrets[] = {"wisp-proxy-user", "wisp-proxy-pass", "wisp-proxy-host"};
	char out[CAPTURE_MAX];
	capture_state st;
	int before = hw_log_get_level();

	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	strcpy(cfg.host, "127.0.0.1");
	cfg.port = 0;
	cfg.workers = 1;
	cfg.log_level = HW_LOG_DEBUG;
	snprintf(cfg.proxy, sizeof(cfg.proxy), "%s",
	         "socks5://wisp-proxy-user:wisp-proxy-pass@wisp-proxy-host.invalid:1080");
	capture_begin(&st);
	hw_server *s = hw_server_new(&cfg);
	capture_end(&st, out, sizeof(out));
	CHECK(s == NULL, "a server whose proxy does not resolve does not start");
	CHECK(strstr(out, "cannot resolve the proxy's host") != NULL, "the failure is logged: %s", out);
	for (size_t i = 0; i < 3; i++) CHECK(strstr(out, secrets[i]) == NULL, "%s in the log: %s", secrets[i], out);

	// A setting the validator refuses: the message names the key alone.
	snprintf(cfg.proxy, sizeof(cfg.proxy), "%s", "ftp://wisp-proxy-user:wisp-proxy-pass@wisp-proxy-host:21");
	capture_begin(&st);
	s = hw_server_new(&cfg);
	capture_end(&st, out, sizeof(out));
	CHECK(s == NULL, "a proxy of an unknown scheme is refused");
	CHECK(strstr(out, "proxy") != NULL, "the refusal is logged: %s", out);
	for (size_t i = 0; i < 3; i++) CHECK(strstr(out, secrets[i]) == NULL, "%s in the log: %s", secrets[i], out);

	// And the parser's own message, which a config file's error line carries: a value too long
	// for its field.
	char value[600], err[512];
	int len = snprintf(value, sizeof(value), "%s", "socks5://wisp-proxy-user:wisp-proxy-pass@wisp-proxy-host:1080");
	memset(value + len, 'x', sizeof(value) - 1 - (size_t)len);
	value[sizeof(value) - 1] = '\0';
	hw_server_config_defaults(&cfg);
	CHECK(hw_config_set(&cfg, "proxy", value, err, sizeof(err)) != 0, "a proxy setting too long is refused");
	for (size_t i = 0; i < 3; i++) CHECK(strstr(err, secrets[i]) == NULL, "%s in \"%s\"", secrets[i], err);
	hw_log_set_level(before);
}

int main(void) {
	RUN(test_plain_line);
	RUN(test_no_forged_line);
	RUN(test_no_terminal_escapes);
	RUN(test_long_message);
	RUN(test_levels);
	RUN(test_limit);
	RUN(test_proxy_never_logged);
	return 0;
}

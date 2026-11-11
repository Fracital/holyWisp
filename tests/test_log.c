/*
 * holywisp/log.h: one call is one line, whatever a client put into the strings it is given.
 */
#include "holywisp/log.h"

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

int main(void) {
	RUN(test_plain_line);
	RUN(test_no_forged_line);
	RUN(test_no_terminal_escapes);
	RUN(test_long_message);
	RUN(test_levels);
	return 0;
}

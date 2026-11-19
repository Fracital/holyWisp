/*
 * tests/test.h - the whole test framework: CHECK, and a counter so a test that checks nothing
 * is noticed. Each binary prints `ok <case>` per case and exits 1 on the first failure.
 */
#ifndef HOLYWISP_TESTS_TEST_H
#define HOLYWISP_TESTS_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A mkstemp(3) template in the system's temporary directory: TMPDIR, else TEMP (Windows), else /tmp.
static inline void hw_test_tmp(char *out, size_t cap, const char *name) {
	const char *dir = getenv("TMPDIR");
	if (!dir || !*dir) dir = getenv("TEMP");
	if (!dir || !*dir) dir = "/tmp";
	snprintf(out, cap, "%s/%s-XXXXXX", dir, name);
}

static int g_checks;

#define CHECK(cond, ...)                                                    \
	do {                                                                    \
		g_checks++;                                                         \
		if (!(cond)) {                                                      \
			fprintf(stderr, "FAIL %s:%d: %s: ", __FILE__, __LINE__, #cond); \
			fprintf(stderr, __VA_ARGS__);                                   \
			fprintf(stderr, "\n");                                          \
			exit(1);                                                        \
		}                                                                   \
	} while (0)

#define CHECK_EQ(a, b)  CHECK((a) == (b), "%lld != %lld", (long long)(a), (long long)(b))
#define CHECK_STR(a, b) CHECK(strcmp((a), (b)) == 0, "\"%s\" != \"%s\"", (a), (b))

// Whether s, from *pos, is one JSON value (RFC 8259, without string escapes other than \" and
// \\, which is all the server writes), with nothing after it but whitespace when top is set. For
// the bodies the server makes by hand: GET /stats, /webtransport.json.
static inline int hw_test_json_value(const char *s, size_t *pos, int top) {
	size_t i = *pos;
	while (s[i] == ' ' || s[i] == '\n') i++;
	if (s[i] == '{' || s[i] == '[') {
		char close = s[i] == '{' ? '}' : ']';
		int obj = s[i] == '{';
		i++;
		while (s[i] == ' ' || s[i] == '\n') i++;
		if (s[i] == close) {
			i++;
		} else {
			for (;;) {
				if (obj) {
					if (s[i] != '"') return 0;
					if (!hw_test_json_value(s, &i, 0)) return 0;
					while (s[i] == ' ') i++;
					if (s[i++] != ':') return 0;
				}
				if (!hw_test_json_value(s, &i, 0)) return 0;
				while (s[i] == ' ' || s[i] == '\n') i++;
				if (s[i] == ',') {
					i++;
					while (s[i] == ' ' || s[i] == '\n') i++;
					continue;
				}
				if (s[i++] != close) return 0;
				break;
			}
		}
	} else if (s[i] == '"') {
		for (i++; s[i] != '"'; i++) {
			if (!s[i] || (unsigned char)s[i] < 0x20) return 0;
			if (s[i] == '\\' && (s[i + 1] == '"' || s[i + 1] == '\\')) i++;
		}
		i++;
	} else if (s[i] == '-' || (s[i] >= '0' && s[i] <= '9')) {
		if (s[i] == '-') i++;
		if (s[i] < '0' || s[i] > '9') return 0;
		while ((s[i] >= '0' && s[i] <= '9') || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '+' ||
		       s[i] == '-') {
			i++;
		}
	} else if (!strncmp(s + i, "true", 4) || !strncmp(s + i, "null", 4)) {
		i += 4;
	} else if (!strncmp(s + i, "false", 5)) {
		i += 5;
	} else {
		return 0;
	}
	if (top) {
		while (s[i] == ' ' || s[i] == '\n' || s[i] == '\r') i++;
		if (s[i]) return 0;
	}
	*pos = i;
	return 1;
}

static inline int hw_test_json_valid(const char *s) {
	size_t pos = 0;
	return hw_test_json_value(s, &pos, 1);
}

#define RUN(fn)                                                \
	do {                                                       \
		int before = g_checks;                                 \
		fn();                                                  \
		if (g_checks == before) {                              \
			fprintf(stderr, "FAIL %s checked nothing\n", #fn); \
			exit(1);                                           \
		}                                                      \
		printf("ok %s\n", #fn);                                \
	} while (0)

#endif

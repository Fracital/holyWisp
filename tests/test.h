/*
 * tests/test.h - the whole test framework: CHECK, and a counter so a test that checks nothing
 * is noticed. Each binary prints `ok <case>` per case and exits 1 on the first failure.
 */
#ifndef HOLYWISP_TESTS_TEST_H
#define HOLYWISP_TESTS_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

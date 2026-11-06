/*
 * holywisp/log.h implementation: one formatted line per call, one write(2), so lines from
 * different worker threads never interleave.
 */
#include "holywisp/log.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define LOG_LINE_MAX 1024

static _Atomic int g_log_level = HW_LOG_INFO;
static const char *const LEVEL_NAMES[] = {"debug", "info", "warn", "error", "none"};

void hw_log_set_level(int level) {
	if (level < HW_LOG_DEBUG) level = HW_LOG_DEBUG;
	if (level > HW_LOG_NONE) level = HW_LOG_NONE;
	atomic_store_explicit(&g_log_level, level, memory_order_relaxed);
}

int hw_log_get_level(void) {
	return atomic_load_explicit(&g_log_level, memory_order_relaxed);
}

int hw_log_level_parse(const char *name) {
	for (size_t i = 0; i < HW_ARRAY_LEN(LEVEL_NAMES); i++) {
		if (strcasecmp(name, LEVEL_NAMES[i]) == 0) return (int)i;
	}
	if (strcasecmp(name, "warning") == 0) return HW_LOG_WARN;
	return -1;
}

void hw_log(int level, const char *tag, const char *fmt, ...) {
	if (level < HW_LOG_DEBUG || level >= HW_LOG_NONE) return;
	char line[LOG_LINE_MAX];
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm;
	gmtime_r(&ts.tv_sec, &tm);
	int n = snprintf(line, sizeof(line), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ [%s] %s: ", tm.tm_year + 1900,
	                 tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000,
	                 LEVEL_NAMES[level], tag);
	if (n < 0) return;
	size_t off = (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1;
	va_list ap;
	va_start(ap, fmt);
	n = vsnprintf(line + off, sizeof(line) - off, fmt, ap);
	va_end(ap);
	if (n < 0) return;
	off += (size_t)n;
	if (off >= sizeof(line) - 1) off = sizeof(line) - 2;
	line[off++] = '\n';
	ssize_t r = write(STDERR_FILENO, line, off);
	(void)r;
}

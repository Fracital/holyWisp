/*
 * holywisp/log.h - levelled logging to stderr. Thread-safe (one write(2) per line).
 */
#ifndef HOLYWISP_LOG_H
#define HOLYWISP_LOG_H

#include "holywisp/hw.h"

enum hw_log_level {
	HW_LOG_DEBUG = 0,
	HW_LOG_INFO = 1,
	HW_LOG_WARN = 2,
	HW_LOG_ERROR = 3,
	HW_LOG_NONE = 4
};

void hw_log_set_level(int level);
int hw_log_get_level(void);
// "debug" | "info" | "warn" | "error" | "none"; -1 when unknown.
int hw_log_level_parse(const char *name);
void hw_log(int level, const char *tag, const char *fmt, ...) HW_PRINTF(3, 4);

#define HW_LOG_AT(level, tag, ...)                                              \
	do {                                                                        \
		if ((level) >= hw_log_get_level()) hw_log((level), (tag), __VA_ARGS__); \
	} while (0)
#define HW_DEBUG(tag, ...) HW_LOG_AT(HW_LOG_DEBUG, tag, __VA_ARGS__)
#define HW_INFO(tag, ...)  HW_LOG_AT(HW_LOG_INFO, tag, __VA_ARGS__)
#define HW_WARN(tag, ...)  HW_LOG_AT(HW_LOG_WARN, tag, __VA_ARGS__)
#define HW_ERROR(tag, ...) HW_LOG_AT(HW_LOG_ERROR, tag, __VA_ARGS__)

#endif

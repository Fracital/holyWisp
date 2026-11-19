/*
 * holywisp/log.h - levelled logging to stderr. Thread-safe (one write(2) per line).
 *
 * A call is one line, whatever its arguments hold: every byte below 0x20 and 0x7f in the tag and
 * the formatted message is written as \xNN, so a string that came from a client can neither start
 * a line of its own nor send an escape sequence to a terminal. Callers pass such strings as they
 * are and do not escape them first.
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
// The name hw_log_level_parse takes for a level, a level out of range as the nearest one.
const char *hw_log_level_name(int level);
void hw_log(int level, const char *tag, const char *fmt, ...) HW_PRINTF(3, 4);

#define HW_LOG_AT(level, tag, ...)                                              \
	do {                                                                        \
		if ((level) >= hw_log_get_level()) hw_log((level), (tag), __VA_ARGS__); \
	} while (0)
#define HW_DEBUG(tag, ...) HW_LOG_AT(HW_LOG_DEBUG, tag, __VA_ARGS__)
#define HW_INFO(tag, ...)  HW_LOG_AT(HW_LOG_INFO, tag, __VA_ARGS__)
#define HW_WARN(tag, ...)  HW_LOG_AT(HW_LOG_WARN, tag, __VA_ARGS__)
#define HW_ERROR(tag, ...) HW_LOG_AT(HW_LOG_ERROR, tag, __VA_ARGS__)

// The budget of one log statement whose lines a client can cause as often as it likes (a refused
// CONNECT, a refused upgrade): at most HW_LOG_BURST lines in a second of hw_now_ms, so that one
// client's CONNECT rate does not become the log's write rate. Lines past it are counted and not
// written, and the next line that is written is preceded by one that says how many were not. Zero
// is a fresh budget. Lock-free and shared by every thread that reaches the statement; a line or
// two more than the budget may pass where a second turns over.
typedef struct hw_log_limit {
	_Atomic uint64_t second; // hw_now_ms / 1000 the count is for
	_Atomic uint32_t count;  // lines taken in that second, written or not
	_Atomic uint32_t held;   // lines not written since the last one that was
} hw_log_limit;

#define HW_LOG_BURST 20

// 1 when a line may be written at now_ms, with *held set to the number of lines that were held
// back before it (and that number cleared); 0 when the second's budget is spent, and the line is
// counted as held back.
int hw_log_limit_take(hw_log_limit *l, uint64_t now_ms, uint32_t *held);

// HW_INFO and HW_WARN under a budget of their own: one per statement, wherever it is reached from.
#define HW_LOG_LIMITED(level, tag, ...)                                                                                \
	do {                                                                                                               \
		static hw_log_limit hw_log_limit_site;                                                                         \
		uint32_t hw_log_limit_held;                                                                                    \
		if ((level) >= hw_log_get_level() && hw_log_limit_take(&hw_log_limit_site, hw_now_ms(), &hw_log_limit_held)) { \
			if (hw_log_limit_held) {                                                                                   \
				hw_log((level), (tag), "%u lines like the next were not written (at most %d a second)",                \
				       (unsigned)hw_log_limit_held, HW_LOG_BURST);                                                     \
			}                                                                                                          \
			hw_log((level), (tag), __VA_ARGS__);                                                                       \
		}                                                                                                              \
	} while (0)
#define HW_INFO_LIMITED(tag, ...) HW_LOG_LIMITED(HW_LOG_INFO, tag, __VA_ARGS__)
#define HW_WARN_LIMITED(tag, ...) HW_LOG_LIMITED(HW_LOG_WARN, tag, __VA_ARGS__)

#endif

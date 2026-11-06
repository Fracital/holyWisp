/*
 * holywisp/buf.h - growable byte buffer with a read cursor.
 *
 * [0, off) has been consumed, [off, len) is readable, [len, cap) is free. Producers either
 * hw_buf_append() or write straight into hw_buf_tail() and hw_buf_commit(). Consumers read from
 * hw_buf_head() for hw_buf_avail() bytes and hw_buf_consume(). Compaction happens inside consume
 * when the consumed prefix is larger than what is left, so steady-state streaming does not copy
 * on every read.
 */
#ifndef HOLYWISP_BUF_H
#define HOLYWISP_BUF_H

#include <stddef.h>
#include <stdint.h>

typedef struct hw_buf {
	uint8_t *data;
	size_t off;
	size_t len;
	size_t cap;
} hw_buf;

void hw_buf_init(hw_buf *b);
void hw_buf_free(hw_buf *b);
// Drop everything, keep the allocation.
void hw_buf_clear(hw_buf *b);
// Make sure at least `extra` bytes can be written after len. 0 on success, -1 (ENOMEM) otherwise.
int hw_buf_reserve(hw_buf *b, size_t extra);
int hw_buf_append(hw_buf *b, const void *data, size_t n);
int hw_buf_append_u8(hw_buf *b, uint8_t v);

// Direct write access: write up to hw_buf_room() bytes at hw_buf_tail(), then commit.
static inline uint8_t *hw_buf_tail(hw_buf *b) {
	return b->data + b->len;
}
static inline size_t hw_buf_room(const hw_buf *b) {
	return b->cap - b->len;
}
static inline void hw_buf_commit(hw_buf *b, size_t n) {
	b->len += n;
}

// Read access.
static inline const uint8_t *hw_buf_head(const hw_buf *b) {
	return b->data + b->off;
}
static inline size_t hw_buf_avail(const hw_buf *b) {
	return b->len - b->off;
}
void hw_buf_consume(hw_buf *b, size_t n);

#endif

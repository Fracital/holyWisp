/*
 * holywisp/buf.h implementation.
 */
#include "holywisp/buf.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define BUF_MIN_CAP 256

void hw_buf_init(hw_buf *b) {
	b->data = NULL;
	b->off = 0;
	b->len = 0;
	b->cap = 0;
}

void hw_buf_free(hw_buf *b) {
	free(b->data);
	hw_buf_init(b);
}

void hw_buf_clear(hw_buf *b) {
	b->off = 0;
	b->len = 0;
}

int hw_buf_reserve(hw_buf *b, size_t extra) {
	if (b->cap - b->len >= extra) return 0;
	// Compact first: the consumed prefix may already be enough room.
	if (b->off > 0) {
		memmove(b->data, b->data + b->off, b->len - b->off);
		b->len -= b->off;
		b->off = 0;
		if (b->cap - b->len >= extra) return 0;
	}
	size_t need = b->len + extra;
	size_t cap = b->cap ? b->cap : BUF_MIN_CAP;
	while (cap < need) {
		if (cap > SIZE_MAX / 2) {
			cap = need;
			break;
		}
		cap *= 2;
	}
	uint8_t *p = realloc(b->data, cap);
	if (!p) {
		errno = ENOMEM;
		return -1;
	}
	b->data = p;
	b->cap = cap;
	return 0;
}

int hw_buf_append(hw_buf *b, const void *data, size_t n) {
	if (n == 0) return 0;
	if (hw_buf_reserve(b, n) != 0) return -1;
	memcpy(b->data + b->len, data, n);
	b->len += n;
	return 0;
}

int hw_buf_append_u8(hw_buf *b, uint8_t v) {
	return hw_buf_append(b, &v, 1);
}

void hw_buf_consume(hw_buf *b, size_t n) {
	b->off += n;
	if (b->off >= b->len) {
		b->off = 0;
		b->len = 0;
		return;
	}
	// Keep the readable part near the front so appends rarely need to grow the allocation.
	if (b->off > (b->len - b->off)) {
		memmove(b->data, b->data + b->off, b->len - b->off);
		b->len -= b->off;
		b->off = 0;
	}
}

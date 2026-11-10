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

// Compaction is amortised: the readable bytes are moved to the front only when at least as many
// consumed bytes sit in front of them, so a buffer that holds a large backlog while being drained
// in small pieces is never shuffled once per piece. Otherwise the allocation grows geometrically.
int hw_buf_reserve(hw_buf *b, size_t extra) {
	if (b->cap - b->len >= extra) return 0;
	size_t used = b->len - b->off;
	if (b->off > 0 && used <= b->off) {
		memmove(b->data, b->data + b->off, used);
		b->len = used;
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
	// An empty buffer has nothing worth carrying over: a fresh block spares realloc's copy.
	uint8_t *p;
	if (b->len == 0) {
		p = malloc(cap);
		if (p) free(b->data);
	} else {
		p = realloc(b->data, cap);
	}
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
	if (b->off < b->len) return;
	b->off = 0;
	b->len = 0;
}

void hw_buf_shrink(hw_buf *b, size_t keep) {
	if (b->len != b->off || b->cap <= keep) return;
	b->off = 0;
	b->len = 0;
	if (keep == 0) {
		free(b->data);
		b->data = NULL;
		b->cap = 0;
		return;
	}
	uint8_t *p = malloc(keep); // empty, so nothing to copy
	if (p) {
		free(b->data);
		b->data = p;
		b->cap = keep;
	}
}

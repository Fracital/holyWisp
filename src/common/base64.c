/*
 * holywisp/base64.h implementation.
 */
#include "holywisp/base64.h"

static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t hw_base64_encode(const uint8_t *in, size_t len, char *out, size_t out_cap) {
	size_t need = HW_BASE64_LEN(len);
	if (out_cap < need) return 0;
	size_t o = 0;
	size_t i = 0;
	while (i + 3 <= len) {
		uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
		out[o++] = ALPHABET[(v >> 18) & 63];
		out[o++] = ALPHABET[(v >> 12) & 63];
		out[o++] = ALPHABET[(v >> 6) & 63];
		out[o++] = ALPHABET[v & 63];
		i += 3;
	}
	if (len - i == 1) {
		uint32_t v = (uint32_t)in[i] << 16;
		out[o++] = ALPHABET[(v >> 18) & 63];
		out[o++] = ALPHABET[(v >> 12) & 63];
		out[o++] = '=';
		out[o++] = '=';
	} else if (len - i == 2) {
		uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
		out[o++] = ALPHABET[(v >> 18) & 63];
		out[o++] = ALPHABET[(v >> 12) & 63];
		out[o++] = ALPHABET[(v >> 6) & 63];
		out[o++] = '=';
	}
	out[o] = '\0';
	return o;
}

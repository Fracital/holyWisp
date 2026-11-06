/*
 * holywisp/base64.h - standard Base64 (RFC 4648) with padding.
 */
#ifndef HOLYWISP_BASE64_H
#define HOLYWISP_BASE64_H

#include <stddef.h>
#include <stdint.h>

// Bytes needed for the encoding of n bytes, NUL included.
#define HW_BASE64_LEN(n) ((((n) + 2) / 3) * 4 + 1)

// Returns the number of characters written (not counting the NUL), 0 when out_cap is too small.
size_t hw_base64_encode(const uint8_t *in, size_t len, char *out, size_t out_cap);

#endif

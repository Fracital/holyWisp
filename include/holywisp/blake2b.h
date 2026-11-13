/*
 * holywisp/blake2b.h - BLAKE2b (RFC 7693), unkeyed, used only to pick a WARP tunnel for a UDP
 * stream exactly as the edge router does (holywisp/warp.h).
 */
#ifndef HOLYWISP_BLAKE2B_H
#define HOLYWISP_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#define HW_BLAKE2B_MAX 64

// The BLAKE2b digest of data, outlen bytes long (1 to HW_BLAKE2B_MAX), with no key. A digest of
// a given length is its own function, not a prefix of a longer one: Python's
// hashlib.blake2b(data, digest_size=outlen).digest().
void hw_blake2b(const void *data, size_t len, uint8_t *out, size_t outlen);

#endif

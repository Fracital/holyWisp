/*
 * holywisp/sha1.h - SHA-1, used only for the WebSocket accept key (RFC 6455 section 4.2.2).
 */
#ifndef HOLYWISP_SHA1_H
#define HOLYWISP_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define HW_SHA1_LEN 20

void hw_sha1(const void *data, size_t len, uint8_t out[HW_SHA1_LEN]);

#endif

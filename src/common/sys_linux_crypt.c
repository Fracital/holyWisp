/*
 * holywisp/sys.h for Linux, the part only the server calls: crypt(3), from libcrypt. In a file
 * of its own, linked into libholywisp-server and not libholywisp, so that what links only the
 * latter (holywisp-client) does not need libcrypt.so to start (CMakeLists.txt).
 */
#include "holywisp/hw.h"
#include "holywisp/sys.h"

#include <crypt.h>
#include <string.h>

int hw_sys_has_crypt(const char *setting) {
	return 1;
}

int hw_sys_crypt(const char *key, const char *setting, char *out, size_t out_cap) {
	struct crypt_data data;
	memset(&data, 0, sizeof(data));
	const char *got = crypt_r(key, setting, &data);
	// A failure token ("*0", "*1") is not a hash: it must never compare equal to a stored value.
	if (!got || got[0] == '*') return -1;
	size_t n = strlen(got);
	if (n >= out_cap) return -1;
	memcpy(out, got, n + 1);
	return 0;
}

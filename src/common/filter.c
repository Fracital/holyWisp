/*
 * holywisp/filter.h implementation.
 */
#include "holywisp/filter.h"

#include "holywisp/net.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

// ---------------------------------------------------------------------------------- hostnames

void hw_hostname_normalize(char *dst, size_t cap, const char *src, size_t src_len) {
	while (src_len > 0 && isspace((unsigned char)src[0])) {
		src++;
		src_len--;
	}
	while (src_len > 0 && (isspace((unsigned char)src[src_len - 1]) || src[src_len - 1] == '.')) src_len--;
	size_t n = src_len < cap - 1 ? src_len : cap - 1;
	for (size_t i = 0; i < n; i++) dst[i] = (char)tolower((unsigned char)src[i]);
	dst[n] = '\0';
}

int hw_hostlist_add(hw_hostlist *l, const char *pattern) {
	if (l->count >= HW_MAX_FILTER_HOSTS) return -1;
	char norm[HW_FILTER_HOST_LEN];
	hw_hostname_normalize(norm, sizeof(norm), pattern, strlen(pattern));
	if (!norm[0]) return -1;
	// "*.x" and ".x" are the same wildcard; store as ".x".
	if (norm[0] == '*' && norm[1] == '.') memmove(norm, norm + 1, strlen(norm));
	if (norm[0] == '.' && !norm[1]) return -1;
	snprintf(l->entries[l->count++], HW_FILTER_HOST_LEN, "%s", norm);
	return 0;
}

int hw_hostlist_match(const hw_hostlist *l, const char *host, size_t host_len) {
	if (l->count == 0) return 0;
	char norm[HW_FILTER_HOST_LEN];
	hw_hostname_normalize(norm, sizeof(norm), host, host_len);
	size_t n = strlen(norm);
	for (int i = 0; i < l->count; i++) {
		const char *e = l->entries[i];
		size_t el = strlen(e);
		if (e[0] == '.') {
			// Suffix match on a label boundary: ".example.com" matches "a.example.com".
			if (n > el && strcmp(norm + n - el, e) == 0) return 1;
		} else if (n == el && strcmp(norm, e) == 0) {
			return 1;
		}
	}
	return 0;
}

// ---------------------------------------------------------------------------------- ports

static int parse_port(const char *s, char **end, long *out) {
	long v = strtol(s, end, 10);
	if (*end == s || v < 1 || v > 65535) return -1;
	*out = v;
	return 0;
}

int hw_portset_add(hw_portset *s, const char *spec) {
	char *end;
	long lo, hi;
	if (parse_port(spec, &end, &lo) != 0) return -1;
	hi = lo;
	if (*end == '-') {
		if (parse_port(end + 1, &end, &hi) != 0) return -1;
	}
	while (*end == ' ') end++;
	if (*end) return -1;
	if (hi < lo) {
		long t = lo;
		lo = hi;
		hi = t;
	}
	for (long p = lo; p <= hi; p++) {
		if (!hw_portset_has(s, (uint16_t)p)) {
			s->bits[p >> 3] |= (uint8_t)(1u << (p & 7));
			s->count++;
		}
	}
	return 0;
}

// ---------------------------------------------------------------------------------- CIDR

int hw_cidr_parse(const char *text, hw_cidr *out) {
	char buf[64];
	snprintf(buf, sizeof(buf), "%s", text);
	char *slash = strchr(buf, '/');
	int bits = -1;
	if (slash) {
		*slash = '\0';
		char *end;
		long b = strtol(slash + 1, &end, 10);
		if (end == slash + 1 || *end || b < 0) return -1;
		bits = (int)b;
	}
	struct in_addr v4;
	struct in6_addr v6;
	if (inet_pton(AF_INET, buf, &v4) == 1) {
		if (bits > 32) return -1;
		out->family = AF_INET;
		memcpy(out->addr, &v4, 4);
		out->bits = bits < 0 ? 32 : bits;
		return 0;
	}
	if (inet_pton(AF_INET6, buf, &v6) == 1) {
		if (bits > 128) return -1;
		out->family = AF_INET6;
		memcpy(out->addr, &v6, 16);
		out->bits = bits < 0 ? 128 : bits;
		return 0;
	}
	return -1;
}

// Extract the address bytes of sa as IPv4 (4) or IPv6 (16), unwrapping ::ffff:a.b.c.d.
static int addr_bytes(const struct sockaddr *sa, uint8_t out[16], int *family) {
	if (sa->sa_family == AF_INET) {
		memcpy(out, &((const struct sockaddr_in *)sa)->sin_addr, 4);
		*family = AF_INET;
		return 0;
	}
	if (sa->sa_family != AF_INET6) return -1;
	const uint8_t *a = ((const struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
	static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
	if (memcmp(a, mapped, 12) == 0) {
		memcpy(out, a + 12, 4);
		*family = AF_INET;
		return 0;
	}
	memcpy(out, a, 16);
	*family = AF_INET6;
	return 0;
}

int hw_cidr_contains(const hw_cidr *c, const struct sockaddr *sa) {
	uint8_t a[16];
	int family;
	if (addr_bytes(sa, a, &family) != 0 || family != c->family) return 0;
	int full = c->bits / 8;
	int rem = c->bits % 8;
	if (memcmp(a, c->addr, (size_t)full) != 0) return 0;
	if (rem == 0) return 1;
	uint8_t mask = (uint8_t)(0xFF << (8 - rem));
	return (a[full] & mask) == (c->addr[full] & mask);
}

int hw_cidr_any_contains(const hw_cidr *list, int n, const struct sockaddr *sa) {
	for (int i = 0; i < n; i++) {
		if (hw_cidr_contains(&list[i], sa)) return 1;
	}
	return 0;
}

// ---------------------------------------------------------------------------------- real IP

const char *hw_addr_ip_str(const struct sockaddr *sa, char *buf, size_t cap) {
	uint8_t a[16];
	int family;
	if (addr_bytes(sa, a, &family) != 0) {
		snprintf(buf, cap, "?");
		return buf;
	}
	inet_ntop(family, a, buf, (socklen_t)cap);
	return buf;
}

void hw_real_ip(const struct sockaddr *peer, const hw_cidr *trusted, int ntrusted, const char *const *header_values,
                int nvalues, char out[HW_IP_STR_LEN]) {
	hw_addr_ip_str(peer, out, HW_IP_STR_LEN);
	if (ntrusted == 0 || !hw_cidr_any_contains(trusted, ntrusted, peer)) return;
	for (int h = 0; h < nvalues; h++) {
		const char *v = header_values[h];
		if (!v || !*v) continue;
		// Walk the comma list from the right: the right-most address not added by a trusted hop.
		const char *end = v + strlen(v);
		while (end > v) {
			const char *start = end;
			while (start > v && start[-1] != ',') start--;
			const char *tok = start;
			const char *tok_end = end;
			while (tok < tok_end && isspace((unsigned char)*tok)) tok++;
			while (tok_end > tok && isspace((unsigned char)tok_end[-1])) tok_end--;
			char cand[HW_IP_STR_LEN + 2];
			size_t n = (size_t)(tok_end - tok);
			if (n > 0 && n < sizeof(cand)) {
				memcpy(cand, tok, n);
				cand[n] = '\0';
				struct sockaddr_storage ss;
				socklen_t sl;
				if (hw_addr_parse(cand, 0, &ss, &sl) == 1 &&
				    !hw_cidr_any_contains(trusted, ntrusted, (struct sockaddr *)&ss)) {
					hw_addr_ip_str((struct sockaddr *)&ss, out, HW_IP_STR_LEN);
					return;
				}
			}
			end = start > v ? start - 1 : v;
		}
	}
}

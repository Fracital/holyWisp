/*
 * holywisp/warp.h implementation. The router's side is edge-router.py (site_key,
 * rendezvous_score, WarpTunnels.pick); a change here that it does not make moves sites between
 * tunnels, so their TCP and UDP leave from different exits.
 */
#include "holywisp/warp.h"

#include "holywisp/blake2b.h"
#include "holywisp/net.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

// Second-level labels under a two-letter TLD that are a public suffix of their own: the router's
// SLD_SUFFIXES, word for word.
static const char *const SLD_SUFFIXES[] = {"co", "com", "net", "org", "gov", "edu", "ac", "or",
                                           "ne", "go",  "gob", "nic", "mil", "ltd", "plc"};

static int is_sld_suffix(const char *label, size_t len) {
	for (size_t i = 0; i < sizeof(SLD_SUFFIXES) / sizeof(SLD_SUFFIXES[0]); i++) {
		if (strlen(SLD_SUFFIXES[i]) == len && memcmp(SLD_SUFFIXES[i], label, len) == 0) return 1;
	}
	return 0;
}

int hw_warp_site_key(const char *host, char *out, size_t cap) {
	if (cap == 0) return -1;
	out[0] = '\0';
	size_t n = strlen(host);
	while (n > 0 && host[n - 1] == '.') n--; // Python's rstrip("."): every trailing dot
	// The labels' boundaries: dot[k] is the index of the k-th dot from the right.
	size_t dots[3];
	int ndots = 0;
	for (size_t i = n; i > 0 && ndots < 3; i--) {
		if (host[i - 1] == '.') dots[ndots++] = i - 1;
	}
	size_t start = 0;
	if (ndots >= 2) { // three labels or more
		size_t last_len = n - dots[0] - 1;
		const char *second = host + dots[1] + 1;
		size_t second_len = dots[0] - dots[1] - 1;
		char lower[4];
		int suffix = 0;
		if (last_len == 2 && second_len < sizeof(lower)) {
			for (size_t i = 0; i < second_len; i++) lower[i] = (char)tolower((unsigned char)second[i]);
			suffix = is_sld_suffix(lower, second_len);
		}
		if (suffix) {
			start = ndots >= 3 ? dots[2] + 1 : 0;
		} else {
			start = dots[1] + 1;
		}
	}
	size_t len = n - start;
	if (len + 1 > cap) return -1;
	for (size_t i = 0; i < len; i++) out[i] = (char)tolower((unsigned char)host[start + i]);
	out[len] = '\0';
	return 0;
}

int hw_warp_client_key(const uint8_t *secret, size_t secret_len, const char *ip, char out[HW_WARP_CLIENT_KEY_LEN + 1]) {
	out[0] = '\0';
	struct sockaddr_storage ss;
	socklen_t sl;
	if (!ip || hw_addr_parse(ip, 0, &ss, &sl) != 1) return -1;
	static const uint8_t v4_mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
	const uint8_t *a;
	size_t alen;
	if (ss.ss_family == AF_INET) {
		a = (const uint8_t *)&((const struct sockaddr_in *)&ss)->sin_addr;
		alen = 4;
	} else {
		a = (const uint8_t *)&((const struct sockaddr_in6 *)&ss)->sin6_addr;
		alen = 8;
		if (!memcmp(a, v4_mapped, sizeof(v4_mapped))) {
			a += 12;
			alen = 4;
		}
	}
	uint8_t msg[256 + 1 + 8];
	if (secret_len > 256) secret_len = 256;
	if (secret_len) memcpy(msg, secret, secret_len);
	msg[secret_len] = 0;
	memcpy(msg + secret_len + 1, a, alen);
	uint8_t d[8];
	hw_blake2b(msg, secret_len + 1 + alen, d, sizeof(d));
	static const char hex_digits[] = "0123456789abcdef";
	for (int i = 0; i < 8; i++) {
		out[2 * i] = hex_digits[d[i] >> 4];
		out[2 * i + 1] = hex_digits[d[i] & 15];
	}
	out[HW_WARP_CLIENT_KEY_LEN] = '\0';
	return 0;
}

int hw_warp_stream_key(const char *client, const char *site, char *out, size_t cap) {
	int n = client && *client ? snprintf(out, cap, "%s/%s", client, site) : snprintf(out, cap, "%s", site);
	if (n < 0 || (size_t)n >= cap) {
		if (cap) out[0] = '\0';
		return -1;
	}
	return 0;
}

uint64_t hw_warp_score(const char *key, const char *name) {
	size_t kl = strlen(key), nl = strlen(name);
	char stack[320];
	char *buf = kl + nl + 1 <= sizeof(stack) ? stack : malloc(kl + nl + 1);
	if (!buf) return 0;
	memcpy(buf, key, kl);
	buf[kl] = '\0';
	memcpy(buf + kl + 1, name, nl);
	uint8_t d[8];
	hw_blake2b(buf, kl + nl + 1, d, sizeof(d));
	if (buf != stack) free(buf);
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) v = v << 8 | d[i];
	return v;
}

const hw_warp_tunnel *hw_warp_pick(const hw_warp_state *st, int v6, const char *key) {
	const hw_warp_tunnel *list = v6 ? st->v6 : st->v4;
	int n = v6 ? st->n6 : st->n4;
	const hw_warp_tunnel *best = NULL;
	uint64_t best_score = 0;
	for (int i = 0; i < n; i++) {
		uint64_t score = hw_warp_score(key, list[i].name);
		// max() over (score, name): equal scores go to the greater name.
		if (!best || score > best_score || (score == best_score && strcmp(list[i].name, best->name) > 0)) {
			best = &list[i];
			best_score = score;
		}
	}
	return best;
}

// ---- the state file
//
// A reader for one shape of JSON, strict about that shape and about JSON's syntax, that steps over
// whatever else the file holds. The router writes it with json.dump; nothing here has to read
// anything cleverer than that, but it must never be fooled by it.

#define JSON_DEPTH_MAX 32

typedef struct {
	const char *p;
	const char *end;
	const char *err;
} jreader;

static void jws(jreader *j) {
	while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')) j->p++;
}

static int jeat(jreader *j, char c) {
	jws(j);
	if (j->p < j->end && *j->p == c) {
		j->p++;
		return 1;
	}
	return 0;
}

// A string. Its bytes go to out when it is plain (no escapes, nothing below 0x20) and fits;
// *len is its length then, and (size_t)-1 when it is not. 0, or -1 when it is not a string.
static int jstring(jreader *j, char *out, size_t cap, size_t *len) {
	jws(j);
	if (j->p >= j->end || *j->p != '"') return -1;
	j->p++;
	size_t n = 0;
	int plain = 1;
	while (j->p < j->end && *j->p != '"') {
		unsigned char ch = (unsigned char)*j->p;
		if (ch < 0x20) return -1; // JSON allows no raw control characters in a string
		if (ch == '\\') {
			plain = 0;
			if (j->p + 1 >= j->end) return -1;
			j->p += 2;
			continue;
		}
		if (out && n + 1 < cap) out[n] = (char)ch;
		n++;
		j->p++;
	}
	if (j->p >= j->end) return -1;
	j->p++;
	if (out && cap > 0) out[n < cap ? n : cap - 1] = '\0';
	if (len) *len = plain && (!out || n < cap) ? n : (size_t)-1;
	return 0;
}

static int jskip(jreader *j, int depth);

static int jskip_container(jreader *j, char close, int is_object, int depth) {
	if (jeat(j, close)) return 0;
	for (;;) {
		if (is_object) {
			if (jstring(j, NULL, 0, NULL) != 0 || !jeat(j, ':')) return -1;
		}
		if (jskip(j, depth + 1) != 0) return -1;
		if (jeat(j, close)) return 0;
		if (!jeat(j, ',')) return -1;
	}
}

static int jskip(jreader *j, int depth) {
	if (depth > JSON_DEPTH_MAX) return -1;
	jws(j);
	if (j->p >= j->end) return -1;
	char c = *j->p;
	if (c == '"') return jstring(j, NULL, 0, NULL);
	if (c == '{') {
		j->p++;
		return jskip_container(j, '}', 1, depth);
	}
	if (c == '[') {
		j->p++;
		return jskip_container(j, ']', 0, depth);
	}
	static const char *const words[] = {"true", "false", "null"};
	for (size_t i = 0; i < 3; i++) {
		size_t wl = strlen(words[i]);
		if ((size_t)(j->end - j->p) >= wl && memcmp(j->p, words[i], wl) == 0) {
			j->p += wl;
			return 0;
		}
	}
	const char *start = j->p;
	while (j->p < j->end && (isdigit((unsigned char)*j->p) || *j->p == '-' || *j->p == '+' || *j->p == '.' ||
	                         *j->p == 'e' || *j->p == 'E')) {
		j->p++;
	}
	return j->p > start ? 0 : -1;
}

// A mark: a JSON integer, 1..0xFFFFFFFF, written plainly (no sign, fraction or exponent).
static int jmark(jreader *j, uint32_t *out) {
	jws(j);
	uint64_t v = 0;
	const char *start = j->p;
	while (j->p < j->end && isdigit((unsigned char)*j->p)) {
		v = v * 10 + (uint64_t)(*j->p - '0');
		if (v > 0xFFFFFFFFULL) return -1;
		j->p++;
	}
	if (j->p == start || v == 0) return -1;
	if (j->p < j->end && (*j->p == '.' || *j->p == 'e' || *j->p == 'E')) return -1;
	*out = (uint32_t)v;
	return 0;
}

static int name_ok(const char *name, size_t len) {
	if (len < 1 || len >= HW_WARP_NAME_MAX) return 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char ch = (unsigned char)name[i];
		if (!isalnum(ch) && ch != '_' && ch != '.' && ch != '-') return 0;
	}
	return 1;
}

static int jtunnel(jreader *j, hw_warp_tunnel *t) {
	if (!jeat(j, '{')) {
		j->err = "a tunnel is not an object";
		return -1;
	}
	int have_name = 0, have_mark = 0;
	if (!jeat(j, '}')) {
		for (;;) {
			char key[8];
			size_t kl;
			if (jstring(j, key, sizeof(key), &kl) != 0 || !jeat(j, ':')) {
				j->err = "malformed tunnel";
				return -1;
			}
			if (kl == 4 && !memcmp(key, "name", 4)) {
				size_t nl;
				if (jstring(j, t->name, sizeof(t->name), &nl) != 0 || nl == (size_t)-1 || !name_ok(t->name, nl)) {
					j->err = "a tunnel's name is not an interface name";
					return -1;
				}
				have_name = 1;
			} else if (kl == 4 && !memcmp(key, "mark", 4)) {
				if (jmark(j, &t->mark) != 0) {
					j->err = "a tunnel's mark is not an integer 1..0xFFFFFFFF";
					return -1;
				}
				have_mark = 1;
			} else if (jskip(j, 2) != 0) {
				j->err = "malformed tunnel";
				return -1;
			}
			if (jeat(j, '}')) break;
			if (!jeat(j, ',')) {
				j->err = "malformed tunnel";
				return -1;
			}
		}
	}
	if (!have_name || !have_mark) {
		j->err = "a tunnel needs a name and a mark";
		return -1;
	}
	return 0;
}

static int jfamily(jreader *j, hw_warp_tunnel *list, int *n) {
	*n = 0;
	if (!jeat(j, '[')) {
		j->err = "a family is not a list";
		return -1;
	}
	if (jeat(j, ']')) return 0;
	for (;;) {
		if (*n == HW_WARP_MAX_TUNNELS) {
			j->err = "too many tunnels in one family";
			return -1;
		}
		hw_warp_tunnel *t = &list[*n];
		memset(t, 0, sizeof(*t));
		if (jtunnel(j, t) != 0) return -1;
		for (int i = 0; i < *n; i++) {
			if (!strcmp(list[i].name, t->name) || list[i].mark == t->mark) {
				j->err = "a tunnel name or mark is listed twice";
				return -1;
			}
		}
		(*n)++;
		if (jeat(j, ']')) return 0;
		if (!jeat(j, ',')) {
			j->err = "malformed list";
			return -1;
		}
	}
}

int hw_warp_state_parse(const char *json, size_t len, hw_warp_state *out, char *err, size_t err_cap) {
	memset(out, 0, sizeof(*out));
	jreader j = {json, json + len, "not a JSON object"};
	int ok = jeat(&j, '{');
	if (ok && !jeat(&j, '}')) {
		for (;;) {
			char key[4];
			size_t kl;
			if (jstring(&j, key, sizeof(key), &kl) != 0 || !jeat(&j, ':')) {
				j.err = "malformed object";
				ok = 0;
				break;
			}
			if (kl == 2 && !memcmp(key, "v4", 2)) {
				ok = jfamily(&j, out->v4, &out->n4) == 0;
			} else if (kl == 2 && !memcmp(key, "v6", 2)) {
				ok = jfamily(&j, out->v6, &out->n6) == 0;
			} else {
				ok = jskip(&j, 1) == 0;
				if (!ok) j.err = "malformed value";
			}
			if (!ok || jeat(&j, '}')) break;
			if (!jeat(&j, ',')) {
				j.err = "malformed object";
				ok = 0;
				break;
			}
		}
	}
	if (ok) {
		jws(&j);
		if (j.p != j.end) {
			j.err = "something follows the object";
			ok = 0;
		}
	}
	if (!ok) {
		memset(out, 0, sizeof(*out));
		if (err && err_cap) snprintf(err, err_cap, "%s", j.err);
		return -1;
	}
	return 0;
}

static int restrict_list(hw_warp_tunnel *list, int *n, const uint32_t *marks, int nmarks) {
	int kept = 0, dropped = 0;
	for (int i = 0; i < *n; i++) {
		int allowed = 0;
		for (int k = 0; k < nmarks && !allowed; k++) allowed = list[i].mark == marks[k];
		if (allowed) {
			list[kept++] = list[i];
		} else {
			dropped++;
		}
	}
	// What is left past the end is zeroed, as hw_warp_state_parse leaves it: two states holding the
	// same tunnels are then the same bytes.
	memset(list + kept, 0, (size_t)(*n - kept) * sizeof(*list));
	*n = kept;
	return dropped;
}

int hw_warp_state_restrict(hw_warp_state *st, const uint32_t *marks, int n) {
	return restrict_list(st->v4, &st->n4, marks, n) + restrict_list(st->v6, &st->n6, marks, n);
}

int hw_warp_marks_parse(const char *text, uint32_t *marks, int cap) {
	int n = 0;
	const char *p = text;
	for (;;) {
		while (*p == ' ' || *p == '\t') p++;
		if (!isdigit((unsigned char)*p)) return -1;
		char *end;
		errno = 0;
		unsigned long long v = strtoull(p, &end, 0); // 0x... hex, else decimal (a leading 0 is octal)
		if (errno || end == p || v == 0 || v > 0xFFFFFFFFULL) return -1;
		p = end;
		while (*p == ' ' || *p == '\t') p++;
		if (n == cap) return -1;
		for (int i = 0; i < n; i++) {
			if (marks[i] == (uint32_t)v) return -1;
		}
		marks[n++] = (uint32_t)v;
		if (*p == '\0') return n;
		if (*p != ',') return -1;
		p++;
	}
}

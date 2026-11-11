/*
 * holywisp/reputation.h implementation. The store is a JSON object of our own shape:
 *   {"sources":{"<ip>":{"score":N,"firstSeen":MS,"lastSeen":MS,"events":{"<name>":N}}},
 *    "destinations":{"<ip:port>":{...,"distinctSources":N,"seenSources":["<ip>",...]}}}
 * Timestamps are unix milliseconds. The parser below understands exactly that and nothing more.
 */
#include "holywisp/reputation.h"

#include "holywisp/buf.h"
#include "holywisp/hw.h"
#include "holywisp/smap.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>

typedef struct rep_entry {
	int score;
	int64_t first_seen;
	int64_t last_seen;
	uint32_t events[HW_REP_EVENT_COUNT];
	int distinct_sources; // destinations only
	hw_smap seen_sources; // destinations only; value unused
} rep_entry;

struct hw_reputation {
	hw_reputation_config cfg;
	pthread_mutex_t lock;
	hw_smap sources;
	hw_smap dests;
	uint64_t last_decay_ms;
};

static const char *const EVENT_NAMES[HW_REP_EVENT_COUNT] = {
    "privateEgress",    "synSignature",        "twispNoAuth", "burstRate",
    "successfulStream", "requestKnownBadDest", "authFailure", "protocolViolation",
};

static int64_t wall_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void hw_reputation_config_defaults(hw_reputation_config *cfg) {
	memset(cfg, 0, sizeof(*cfg));
	cfg->save_interval_s = 30;
	cfg->decay_per_hour = 1;
	cfg->evict_after_days = 7;
	cfg->warn = 21;
	cfg->throttle = 51;
	cfg->strict = 81;
	// A CONNECT to a private address is refused and costs the server nothing, and it is what a
	// client sends for every page that names localhost or a router: a client is not scored for it
	// by default (it was 15, and half a dozen subresources of somebody else's page got the client
	// that loaded it refused for hours). reputation-weight privateEgress:N brings it back.
	cfg->source_weights[HW_REP_PRIVATE_EGRESS] = 0;
	cfg->source_weights[HW_REP_SYN_SIGNATURE] = 25;
	cfg->source_weights[HW_REP_TWISP_NO_AUTH] = 40;
	cfg->source_weights[HW_REP_BURST_RATE] = 5;
	cfg->source_weights[HW_REP_SUCCESSFUL_STREAM] = -2;
	cfg->source_weights[HW_REP_KNOWN_BAD_DEST] = 2;
	cfg->source_weights[HW_REP_AUTH_FAILURE] = 10;
	cfg->source_weights[HW_REP_PROTOCOL_VIOLATION] = 5;
	cfg->dest_weights[HW_REP_PRIVATE_EGRESS] = 20;
	cfg->dest_weights[HW_REP_SYN_SIGNATURE] = 30;
	cfg->dest_weights[HW_REP_BURST_RATE] = 5;
	cfg->dest_distinct_sources_escalation = 1;
}

const char *hw_rep_event_name(enum hw_rep_event e) {
	return e >= 0 && e < HW_REP_EVENT_COUNT ? EVENT_NAMES[e] : "?";
}

int hw_rep_event_parse(const char *name) {
	for (int i = 0; i < HW_REP_EVENT_COUNT; i++) {
		if (strcmp(name, EVENT_NAMES[i]) == 0) return i;
	}
	return -1;
}

const char *hw_rep_tier_name(enum hw_rep_tier t) {
	switch (t) {
	case HW_TIER_NORMAL:
		return "normal";
	case HW_TIER_WARN:
		return "warn";
	case HW_TIER_THROTTLE:
		return "throttle";
	case HW_TIER_STRICT:
		return "strict";
	}
	return "?";
}

// ---------------------------------------------------------------------------------- lifecycle

hw_reputation *hw_reputation_new(const hw_reputation_config *cfg) {
	hw_reputation *r = calloc(1, sizeof(*r));
	if (!r) return NULL;
	r->cfg = *cfg;
	pthread_mutex_init(&r->lock, NULL);
	hw_smap_init(&r->sources);
	hw_smap_init(&r->dests);
	r->last_decay_ms = hw_now_ms();
	return r;
}

static void entry_free(rep_entry *e) {
	hw_smap_free(&e->seen_sources);
	free(e);
}

static int free_visit(const char *key, void *value, void *ud) {
	entry_free(value);
	return 0;
}

void hw_reputation_free(hw_reputation *r) {
	if (!r) return;
	hw_smap_each(&r->sources, free_visit, NULL);
	hw_smap_each(&r->dests, free_visit, NULL);
	hw_smap_free(&r->sources);
	hw_smap_free(&r->dests);
	pthread_mutex_destroy(&r->lock);
	free(r);
}

// ---------------------------------------------------------------------------------- scoring

static int clamp(int v) {
	return v < 0 ? 0 : v > 100 ? 100 : v;
}

// Lock held.
static rep_entry *entry_get_or_create(hw_smap *m, const char *key) {
	rep_entry *e = hw_smap_get(m, key);
	if (e) return e;
	e = calloc(1, sizeof(*e));
	if (!e) return NULL;
	hw_smap_init(&e->seen_sources);
	e->first_seen = wall_ms();
	if (hw_smap_put(m, key, e) != 0) {
		entry_free(e);
		return NULL;
	}
	return e;
}

void hw_reputation_add_source(hw_reputation *r, const char *ip, enum hw_rep_event e) {
	if (!r || e < 0 || e >= HW_REP_EVENT_COUNT) return;
	pthread_mutex_lock(&r->lock);
	rep_entry *en = entry_get_or_create(&r->sources, ip);
	if (en) {
		en->last_seen = wall_ms();
		en->events[e]++;
		en->score = clamp(en->score + r->cfg.source_weights[e]);
	}
	pthread_mutex_unlock(&r->lock);
}

void hw_reputation_add_dest(hw_reputation *r, const char *dest, enum hw_rep_event e, const char *src_ip) {
	if (!r || e < 0 || e >= HW_REP_EVENT_COUNT) return;
	pthread_mutex_lock(&r->lock);
	rep_entry *en = entry_get_or_create(&r->dests, dest);
	if (en) {
		en->last_seen = wall_ms();
		en->events[e]++;
		en->score = clamp(en->score + r->cfg.dest_weights[e]);
		if (src_ip && hw_smap_put(&en->seen_sources, src_ip, en) == 0) {
			en->distinct_sources++;
			en->score = clamp(en->score + r->cfg.dest_distinct_sources_escalation);
		}
	}
	pthread_mutex_unlock(&r->lock);
}

int hw_reputation_source_score(hw_reputation *r, const char *ip) {
	if (!r) return 0;
	pthread_mutex_lock(&r->lock);
	rep_entry *e = hw_smap_get(&r->sources, ip);
	int s = e ? e->score : 0;
	pthread_mutex_unlock(&r->lock);
	return s;
}

int hw_reputation_dest_score(hw_reputation *r, const char *dest) {
	if (!r) return 0;
	pthread_mutex_lock(&r->lock);
	rep_entry *e = hw_smap_get(&r->dests, dest);
	int s = e ? e->score : 0;
	pthread_mutex_unlock(&r->lock);
	return s;
}

enum hw_rep_tier hw_reputation_tier(const hw_reputation *r, int score) {
	if (!r) return HW_TIER_NORMAL;
	if (r->cfg.strict > 0 && score >= r->cfg.strict) return HW_TIER_STRICT;
	if (r->cfg.throttle > 0 && score >= r->cfg.throttle) return HW_TIER_THROTTLE;
	if (r->cfg.warn > 0 && score >= r->cfg.warn) return HW_TIER_WARN;
	return HW_TIER_NORMAL;
}

// ---------------------------------------------------------------------------------- maintenance

static int decay_visit(const char *key, void *value, void *ud) {
	rep_entry *e = value;
	e->score = clamp(e->score - *(int *)ud);
	return 0;
}

void hw_reputation_decay(hw_reputation *r) {
	if (!r || r->cfg.decay_per_hour <= 0) return;
	uint64_t now = hw_now_ms();
	pthread_mutex_lock(&r->lock);
	uint64_t elapsed = now - r->last_decay_ms;
	int delta = (int)((uint64_t)r->cfg.decay_per_hour * elapsed / 3600000u);
	if (delta > 0) {
		hw_smap_each(&r->sources, decay_visit, &delta);
		hw_smap_each(&r->dests, decay_visit, &delta);
		// Keep the remainder so slow decay still happens when called often.
		r->last_decay_ms = now - (elapsed - (uint64_t)delta * 3600000u / (uint64_t)r->cfg.decay_per_hour);
	}
	pthread_mutex_unlock(&r->lock);
}

typedef struct evict_ctx {
	hw_smap *map;
	int64_t cutoff;
} evict_ctx;

static int evict_visit(const char *key, void *value, void *ud) {
	evict_ctx *ctx = ud;
	rep_entry *e = value;
	if (e->score < 5 && e->last_seen < ctx->cutoff) {
		hw_smap_remove(ctx->map, key);
		entry_free(e);
	}
	return 0;
}

void hw_reputation_evict(hw_reputation *r) {
	if (!r || r->cfg.evict_after_days <= 0) return;
	int64_t cutoff = wall_ms() - (int64_t)r->cfg.evict_after_days * 86400000LL;
	pthread_mutex_lock(&r->lock);
	evict_ctx s = {.map = &r->sources, .cutoff = cutoff};
	hw_smap_each(&r->sources, evict_visit, &s);
	evict_ctx d = {.map = &r->dests, .cutoff = cutoff};
	hw_smap_each(&r->dests, evict_visit, &d);
	pthread_mutex_unlock(&r->lock);
}

void hw_reputation_counts(hw_reputation *r, size_t *sources, size_t *dests) {
	if (!r) {
		*sources = *dests = 0;
		return;
	}
	pthread_mutex_lock(&r->lock);
	*sources = hw_smap_count(&r->sources);
	*dests = hw_smap_count(&r->dests);
	pthread_mutex_unlock(&r->lock);
}

// ---------------------------------------------------------------------------------- JSON out

// The store is formatted into memory (see hw_reputation_save), so the writer is a buffer.
typedef struct writer {
	hw_buf buf;
	int failed; // an append could not allocate
} writer;

static void out_put(writer *o, const char *data, size_t n) {
	if (hw_buf_append(&o->buf, data, n) != 0) o->failed = 1;
}

static void out_str(writer *o, const char *s) {
	out_put(o, s, strlen(s));
}

static void out_fmt(writer *o, const char *fmt, ...) HW_PRINTF(2, 3);
static void out_fmt(writer *o, const char *fmt, ...) {
	char tmp[256];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(tmp)) {
		o->failed = 1;
		return;
	}
	out_put(o, tmp, (size_t)n);
}

static void json_string(writer *o, const char *s) {
	out_put(o, "\"", 1);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\') {
			out_put(o, "\\", 1);
			out_put(o, s, 1);
		} else if (c < 0x20) {
			out_fmt(o, "\\u%04x", c);
		} else {
			out_put(o, s, 1);
		}
	}
	out_put(o, "\"", 1);
}

typedef struct write_ctx {
	writer *o;
	int first;
	int with_sources;
} write_ctx;

static int seen_visit(const char *key, void *value, void *ud) {
	write_ctx *w = ud;
	if (!w->first) out_put(w->o, ",", 1);
	w->first = 0;
	json_string(w->o, key);
	return 0;
}

static int entry_visit(const char *key, void *value, void *ud) {
	write_ctx *w = ud;
	rep_entry *e = value;
	if (!w->first) out_str(w->o, ",\n");
	w->first = 0;
	out_str(w->o, "    ");
	json_string(w->o, key);
	out_fmt(w->o, ": {\"score\": %d, \"firstSeen\": %lld, \"lastSeen\": %lld, \"events\": {", e->score,
	        (long long)e->first_seen, (long long)e->last_seen);
	int first = 1;
	for (int i = 0; i < HW_REP_EVENT_COUNT; i++) {
		if (!e->events[i]) continue;
		out_fmt(w->o, "%s\"%s\": %u", first ? "" : ", ", EVENT_NAMES[i], e->events[i]);
		first = 0;
	}
	out_put(w->o, "}", 1);
	if (w->with_sources) {
		out_fmt(w->o, ", \"distinctSources\": %d, \"seenSources\": [", e->distinct_sources);
		write_ctx inner = {.o = w->o, .first = 1};
		hw_smap_each(&e->seen_sources, seen_visit, &inner);
		out_put(w->o, "]", 1);
	}
	out_put(w->o, "}", 1);
	return 0;
}

// The table is formatted into memory under the lock and written to disk after it is released: every
// worker takes this lock when a stream opens, and a slow or stalled disk must not stop them all.
int hw_reputation_save(hw_reputation *r) {
	if (!r || !r->cfg.store_path[0]) return 0;
	char dir[512];
	snprintf(dir, sizeof(dir), "%s", r->cfg.store_path);
	char *d = dirname(dir);
	if (d && strcmp(d, ".") != 0 && mkdir(d, 0755) != 0 && errno != EEXIST) return -1;

	writer o = {.failed = 0};
	hw_buf_init(&o.buf);
	pthread_mutex_lock(&r->lock);
	out_str(&o, "{\n  \"sources\": {\n");
	write_ctx w = {.o = &o, .first = 1, .with_sources = 0};
	hw_smap_each(&r->sources, entry_visit, &w);
	out_str(&o, "\n  },\n  \"destinations\": {\n");
	write_ctx wd = {.o = &o, .first = 1, .with_sources = 1};
	hw_smap_each(&r->dests, entry_visit, &wd);
	out_str(&o, "\n  }\n}\n");
	pthread_mutex_unlock(&r->lock);
	if (o.failed) {
		hw_buf_free(&o.buf);
		errno = ENOMEM;
		return -1;
	}

	// The temporary file is made here and by nobody else: whatever stands at its name (the rest
	// of a save that was cut short, or a link someone put there to have this process write
	// through it) is removed, and O_EXCL then refuses to open anything that is not a new file,
	// a symbolic link included. It is 0600 from the first byte, not after a chmod.
	char tmp[600];
	snprintf(tmp, sizeof(tmp), "%s.tmp", r->cfg.store_path);
	unlink(tmp);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		hw_buf_free(&o.buf);
		return -1;
	}
	(void)hw_set_cloexec(fd); // a Twisp child has no business with it
	FILE *f = fdopen(fd, "w");
	if (!f) {
		int saved = errno;
		close(fd);
		unlink(tmp);
		hw_buf_free(&o.buf);
		errno = saved;
		return -1;
	}
	size_t len = hw_buf_avail(&o.buf);
	size_t wrote = fwrite(hw_buf_head(&o.buf), 1, len, f);
	hw_buf_free(&o.buf);
	if (fclose(f) != 0 || wrote != len) {
		unlink(tmp);
		return -1;
	}
	return rename(tmp, r->cfg.store_path);
}

// ---------------------------------------------------------------------------------- JSON in

// How deep a value we do not understand may nest before the file is called malformed. Our own
// shape is four levels deep; skip_value recurses once per level, and a file of nothing but "["
// would otherwise take the stack with it.
#define JSON_MAX_DEPTH 32

typedef struct parser {
	const char *p;
	const char *end;
	int err;
	int depth; // of the values skip_value is inside
} parser;

static void skip_ws(parser *ps) {
	while (ps->p < ps->end && isspace((unsigned char)*ps->p)) ps->p++;
}

static int expect(parser *ps, char c) {
	skip_ws(ps);
	if (ps->p < ps->end && *ps->p == c) {
		ps->p++;
		return 1;
	}
	ps->err = 1;
	return 0;
}

static int peek(parser *ps, char c) {
	skip_ws(ps);
	return ps->p < ps->end && *ps->p == c;
}

// Reads a JSON string into out (truncating); \uXXXX is decoded only for ASCII.
static int parse_string(parser *ps, char *out, size_t cap) {
	if (!expect(ps, '"')) return 0;
	size_t n = 0;
	while (ps->p < ps->end && *ps->p != '"') {
		char c = *ps->p++;
		if (c == '\\') {
			if (ps->p >= ps->end) break;
			char e = *ps->p++;
			if (e == 'u') {
				if (ps->end - ps->p < 4) break;
				char hex[5] = {ps->p[0], ps->p[1], ps->p[2], ps->p[3], 0};
				c = (char)strtol(hex, NULL, 16);
				ps->p += 4;
			} else if (e == 'n') {
				c = '\n';
			} else if (e == 't') {
				c = '\t';
			} else {
				c = e;
			}
		}
		if (n + 1 < cap) out[n++] = c;
	}
	out[n] = '\0';
	return expect(ps, '"');
}

static int parse_number(parser *ps, long long *out) {
	skip_ws(ps);
	char *end;
	long long v = strtoll(ps->p, &end, 10);
	if (end == ps->p) {
		ps->err = 1;
		return 0;
	}
	ps->p = end;
	*out = v;
	return 1;
}

// Skip any JSON value we do not understand.
static void skip_value(parser *ps) {
	skip_ws(ps);
	if (ps->p >= ps->end) return;
	char c = *ps->p;
	if (c == '"') {
		char tmp[8];
		parse_string(ps, tmp, sizeof(tmp));
	} else if (c == '{' || c == '[') {
		if (ps->depth >= JSON_MAX_DEPTH) {
			ps->err = 1;
			return;
		}
		ps->depth++;
		char close = c == '{' ? '}' : ']';
		ps->p++;
		while (!ps->err && !peek(ps, close)) {
			if (c == '{') {
				char tmp[8];
				parse_string(ps, tmp, sizeof(tmp));
				expect(ps, ':');
			}
			skip_value(ps);
			if (!peek(ps, ',')) break;
			ps->p++;
		}
		expect(ps, close);
		ps->depth--;
	} else {
		while (ps->p < ps->end && !strchr(",}] \n\r\t", *ps->p)) ps->p++;
	}
}

static int parse_entry(parser *ps, rep_entry *e) {
	if (!expect(ps, '{')) return 0;
	while (!ps->err && !peek(ps, '}')) {
		char name[32];
		if (!parse_string(ps, name, sizeof(name)) || !expect(ps, ':')) return 0;
		long long v;
		if (!strcmp(name, "score")) {
			if (!parse_number(ps, &v)) return 0;
			e->score = clamp((int)v);
		} else if (!strcmp(name, "firstSeen")) {
			if (!parse_number(ps, &v)) return 0;
			e->first_seen = v;
		} else if (!strcmp(name, "lastSeen")) {
			if (!parse_number(ps, &v)) return 0;
			e->last_seen = v;
		} else if (!strcmp(name, "distinctSources")) {
			if (!parse_number(ps, &v)) return 0;
			e->distinct_sources = (int)v;
		} else if (!strcmp(name, "events")) {
			if (!expect(ps, '{')) return 0;
			while (!ps->err && !peek(ps, '}')) {
				char ev[32];
				if (!parse_string(ps, ev, sizeof(ev)) || !expect(ps, ':') || !parse_number(ps, &v)) return 0;
				int idx = hw_rep_event_parse(ev);
				if (idx >= 0 && idx < HW_REP_EVENT_COUNT) e->events[idx] = (uint32_t)v;
				if (!peek(ps, ',')) break;
				ps->p++;
			}
			if (!expect(ps, '}')) return 0;
		} else if (!strcmp(name, "seenSources")) {
			if (!expect(ps, '[')) return 0;
			while (!ps->err && !peek(ps, ']')) {
				char ip[64];
				if (!parse_string(ps, ip, sizeof(ip))) return 0;
				hw_smap_put(&e->seen_sources, ip, e);
				if (!peek(ps, ',')) break;
				ps->p++;
			}
			if (!expect(ps, ']')) return 0;
		} else {
			skip_value(ps);
		}
		if (!peek(ps, ',')) break;
		ps->p++;
	}
	return expect(ps, '}');
}

// Lock held.
static int parse_table(parser *ps, hw_smap *m) {
	if (!expect(ps, '{')) return 0;
	while (!ps->err && !peek(ps, '}')) {
		char key[128];
		if (!parse_string(ps, key, sizeof(key)) || !expect(ps, ':')) return 0;
		rep_entry *e = calloc(1, sizeof(*e));
		if (!e) return 0;
		hw_smap_init(&e->seen_sources);
		if (!parse_entry(ps, e)) {
			entry_free(e);
			return 0;
		}
		if (hw_smap_put(m, key, e) != 0) entry_free(e);
		if (!peek(ps, ',')) break;
		ps->p++;
	}
	return expect(ps, '}');
}

int hw_reputation_load(hw_reputation *r) {
	if (!r || !r->cfg.store_path[0]) return 0;
	FILE *f = fopen(r->cfg.store_path, "r");
	if (!f) return errno == ENOENT ? 0 : -1;
	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (len < 0 || len > 256L * 1024 * 1024) {
		fclose(f);
		errno = EFBIG;
		return -1;
	}
	size_t cap = (size_t)len + 1;
	char *data = malloc(cap);
	if (!data) {
		fclose(f);
		return -1;
	}
	size_t got = fread(data, 1, cap - 1, f);
	fclose(f);
	if (got >= cap) got = cap - 1; // fread never exceeds cap-1; makes the bound explicit for analysis
	// len is range-checked to [0,256MiB] above, so cap = len+1 never overflows and got <= cap-1; the
	// analyzer cannot follow that constraint through ftell(), so suppress its false positive here.
	data[got] = '\0'; // NOLINT(clang-analyzer-security.ArrayBound)
	parser ps = {.p = data, .end = data + got, .err = 0};
	int ok = 0;
	pthread_mutex_lock(&r->lock);
	if (expect(&ps, '{')) {
		ok = 1;
		while (ok && !ps.err && !peek(&ps, '}')) {
			char name[32];
			if (!parse_string(&ps, name, sizeof(name)) || !expect(&ps, ':')) {
				ok = 0;
				break;
			}
			if (!strcmp(name, "sources")) {
				ok = parse_table(&ps, &r->sources);
			} else if (!strcmp(name, "destinations")) {
				ok = parse_table(&ps, &r->dests);
			} else {
				skip_value(&ps);
			}
			if (!peek(&ps, ',')) break;
			ps.p++;
		}
		if (ok) ok = expect(&ps, '}');
	}
	pthread_mutex_unlock(&r->lock);
	free(data);
	if (!ok || ps.err) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

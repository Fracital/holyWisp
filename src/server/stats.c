/*
 * GET /stats: hw_server_stats as JSON. Fields are only ever added, never renamed or moved to
 * another object, because the edges' wispstats and anything else that polls it read them by name.
 * Nothing in it names a file, a mark or a secret: on a deploy that is not an edge it may be public.
 */
#include "holywisp/buf.h"
#include "holywisp/hw.h"

#include "internal.h"

#include <stdarg.h>
#include <stdio.h>

typedef struct {
	hw_buf *b;
	int failed;
} json_out;

static void jprintf(json_out *j, const char *fmt, ...) HW_PRINTF(2, 3);

// printf onto the end of the body, growing it; a failure is remembered and ends the writing.
static void jprintf(json_out *j, const char *fmt, ...) {
	while (!j->failed) {
		va_list ap;
		va_start(ap, fmt);
		size_t room = hw_buf_room(j->b);
		int n = vsnprintf((char *)hw_buf_tail(j->b), room, fmt, ap);
		va_end(ap);
		if (n < 0) {
			j->failed = 1;
		} else if ((size_t)n < room) {
			hw_buf_commit(j->b, (size_t)n);
			return;
		} else if (hw_buf_reserve(j->b, (size_t)n + 1) != 0) {
			j->failed = 1;
		}
	}
}

static unsigned long long ull(uint64_t v) {
	return (unsigned long long)v;
}

static const char *warp_status_str(int status) {
	switch (status) {
	case HW_WARP_STATUS_NO_MARK:
		return "noCapability";
	case HW_WARP_STATUS_OK:
		return "ok";
	case HW_WARP_STATUS_MISSING:
		return "missing";
	case HW_WARP_STATUS_UNREADABLE:
		return "unreadable";
	case HW_WARP_STATUS_MALFORMED:
		return "malformed";
	case HW_WARP_STATUS_STALE:
		return "stale";
	default:
		return "off";
	}
}

int stats_json(const hw_worker *w, hw_buf *out) {
	hw_server_stats st;
	hw_server_stats_get(w->server, &st);
	json_out j = {out, 0};
	jprintf(&j, "{\"uptimeSeconds\":%llu,", ull(st.uptime_s));
	jprintf(&j, "\"connections\":{\"total\":%llu,\"active\":%llu,\"perWorkerMin\":%llu,\"perWorkerMax\":%llu},",
	        ull(st.connections_total), ull(st.connections_active), ull(st.worker_connections_min),
	        ull(st.worker_connections_max));
	jprintf(&j, "\"streams\":{\"total\":%llu,\"active\":%llu},", ull(st.streams_total), ull(st.streams_active));
	jprintf(&j, "\"bytes\":{\"in\":%llu,\"out\":%llu},", ull(st.bytes_in), ull(st.bytes_out));
	jprintf(&j, "\"refused\":{\"connectionRate\":%llu,\"connectionLimit\":%llu,\"reputation\":%llu},",
	        ull(st.refused_connection_rate), ull(st.refused_connection_limit), ull(st.refused_reputation));
	jprintf(&j, "\"blocked\":{\"filter\":%llu,\"egress\":%llu},", ull(st.blocked_filter), ull(st.blocked_egress));
	jprintf(&j, "\"throttled\":{\"source\":%llu,\"dest\":%llu,\"syns\":%llu,\"lookups\":%llu},",
	        ull(st.throttled_source), ull(st.throttled_dest), ull(st.throttled_syns), ull(st.throttled_lookups));
	jprintf(&j, "\"queueBudget\":{\"held\":%llu,\"pauses\":%llu},", ull(st.queue_budget_held),
	        ull(st.queue_budget_pauses));
	jprintf(&j, "\"udpWarp\":{\"marked\":%llu,\"direct\":%llu,\"refused\":%llu,\"bypassed\":%llu},",
	        ull(st.udp_warp_marked), ull(st.udp_warp_direct), ull(st.udp_warp_refused), ull(st.udp_warp_bypassed));
	jprintf(&j, "\"tcpWarp\":{\"marked\":%llu,\"direct\":%llu,\"refused\":%llu,\"bypassed\":%llu},",
	        ull(st.tcp_warp_marked), ull(st.tcp_warp_direct), ull(st.tcp_warp_refused), ull(st.tcp_warp_bypassed));
	jprintf(&j, "\"tcpRoute\":{\"proxied\":%llu,\"direct\":%llu},", ull(st.tcp_proxied), ull(st.tcp_direct));
	jprintf(&j, "\"synSignatures\":%llu,\"wsClosedViolations\":%llu,\"authFailures\":%llu,", ull(st.syn_signatures),
	        ull(st.ws_closed_violations), ull(st.auth_failures));
	jprintf(&j, "\"dnsCacheEntries\":%llu,\"reputation\":{\"sources\":%llu,\"destinations\":%llu},",
	        ull(st.dns_cache_entries), ull(st.reputation_sources), ull(st.reputation_dests));
	jprintf(&j,
	        "\"webTransport\":{\"sessions\":{\"total\":%llu,\"active\":%llu},\"handshakes\":%llu,"
	        "\"retries\":%llu,\"refusedHandshakes\":%llu,\"dropped\":%llu}",
	        ull(st.wt_sessions_total), ull(st.wt_sessions_active), ull(st.wt_handshakes), ull(st.wt_retries),
	        ull(st.wt_refused_handshakes), ull(st.wt_dropped));
	// Which build answers, and whether UDP and TCP go through WARP right now: the state the
	// workers were given at the last look (once a second), not the file's path or its marks.
	jprintf(&j, ",\"version\":\"%s%s\"", HW_VERSION, HW_VERSION_SUFFIX);
	int on = st.warp_state != HW_WARP_STATUS_OFF;
	jprintf(&j, ",\"warpState\":{\"configured\":%s,\"canMark\":%s,\"usable\":%s,\"state\":\"%s\",\"ageSeconds\":",
	        on ? "true" : "false", on && st.warp_state != HW_WARP_STATUS_NO_MARK ? "true" : "false",
	        st.warp_state == HW_WARP_STATUS_OK ? "true" : "false", warp_status_str(st.warp_state));
	if (st.warp_state_age_s >= 0) {
		jprintf(&j, "%lld", (long long)st.warp_state_age_s);
	} else {
		jprintf(&j, "null");
	}
	jprintf(&j, ",\"tunnels\":{\"v4\":%llu,\"v6\":%llu}}", ull(st.warp_tunnels_v4), ull(st.warp_tunnels_v6));
	jprintf(&j, "}\n");
	return j.failed ? -1 : 0;
}

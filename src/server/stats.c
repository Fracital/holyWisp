/*
 * GET /stats: hw_server_stats as JSON. Fields are only ever added, never renamed or moved to
 * another object, because the edges' wispstats and anything else that polls it read them by name.
 * Nothing in it names a file, a mark or a secret: on a deploy that is not an edge it may be public.
 */
#include "holywisp/buf.h"
#include "holywisp/hw.h"
#include "holywisp/wisp.h"

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
		if (n >= 0 && (size_t)n < room) {
			hw_buf_commit(j->b, (size_t)n);
			return;
		}
		if (n < 0 || hw_buf_reserve(j->b, (size_t)n + 1) != 0) j->failed = 1;
	}
}

const uint32_t HW_STATS_HIST_BOUNDS_MS[HW_STATS_HIST_BUCKETS - 1] = {1,   2,   5,    10,   20,   50,   100,
                                                                     200, 500, 1000, 2000, 5000, 10000};

void stats_hist_add(hw_whist *h, uint64_t us) {
	int i = 0;
	while (i < HW_STATS_HIST_BUCKETS - 1 && us > (uint64_t)HW_STATS_HIST_BOUNDS_MS[i] * 1000) i++;
	HW_WSTAT_ADD(h->n[i], 1);
	HW_WSTAT_ADD(h->sum_us, us);
}

int stats_reason(uint8_t reason) {
	switch (reason) {
	case HW_CLOSE_VOLUNTARY:
		return HW_STATS_REASON_VOLUNTARY;
	case HW_CLOSE_NETWORK_ERROR:
		return HW_STATS_REASON_NETWORK;
	case HW_CLOSE_INVALID_INFO:
		return HW_STATS_REASON_INVALID;
	case HW_CLOSE_UNREACHABLE:
		return HW_STATS_REASON_UNREACHABLE;
	case HW_CLOSE_NO_RESPONSE:
		return HW_STATS_REASON_NO_RESPONSE;
	case HW_CLOSE_REFUSED:
		return HW_STATS_REASON_REFUSED;
	case HW_CLOSE_BLOCKED:
		return HW_STATS_REASON_BLOCKED;
	case HW_CLOSE_THROTTLED:
		return HW_STATS_REASON_THROTTLED;
	default:
		return HW_STATS_REASON_OTHER;
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

static const char *const REASON_KEYS[HW_STATS_REASONS] = {
    "voluntary", "networkError", "invalid", "unreachable", "noResponse", "refused", "blocked", "throttled", "other"};

static void json_reasons(json_out *j, const char *key, const uint64_t *n) {
	jprintf(j, "\"%s\":{", key);
	for (int i = 0; i < HW_STATS_REASONS; i++) jprintf(j, "%s\"%s\":%llu", i ? "," : "", REASON_KEYS[i], ull(n[i]));
	jprintf(j, "}");
}

static void json_hist(json_out *j, const char *key, const hw_stats_hist *h) {
	jprintf(j, "\"%s\":{\"count\":%llu,\"sumUs\":%llu,\"buckets\":[", key, ull(h->count), ull(h->sum_us));
	for (int i = 0; i < HW_STATS_HIST_BUCKETS; i++) jprintf(j, "%s%llu", i ? "," : "", ull(h->buckets[i]));
	jprintf(j, "]}");
}

// The tunnel's name in the worker's own copy of the state (the stats are answered on its loop),
// or NULL when that does not list the mark now.
static const char *tunnel_name(const hw_worker *w, uint32_t mark) {
	const hw_warp_state *st = w->warp;
	if (!st) return NULL;
	for (int i = 0; i < st->n4; i++) {
		if (st->v4[i].mark == mark) return st->v4[i].name;
	}
	for (int i = 0; i < st->n6; i++) {
		if (st->v6[i].mark == mark) return st->v6[i].name;
	}
	return NULL;
}

int stats_json(const hw_worker *w, hw_buf *out) {
	hw_server_stats st; // some 8 KiB, with every tunnel's histograms
	hw_server_stats_get(w->server, &st);
	json_out j = {out, 0};
	jprintf(&j, "{\"uptimeSeconds\":%llu,", ull(st.uptime_s));
	jprintf(&j, "\"connections\":{\"total\":%llu,\"active\":%llu,\"perWorkerMin\":%llu,\"perWorkerMax\":%llu",
	        ull(st.connections_total), ull(st.connections_active), ull(st.worker_connections_min),
	        ull(st.worker_connections_max));
	// total and active count every socket, the /health and /stats polls with the rest: these say
	// how many were Wisp clients, and over which transport.
	jprintf(&j, ",\"webSocket\":{\"total\":%llu,\"active\":%llu},\"webTransport\":{\"total\":%llu,\"active\":%llu}",
	        ull(st.ws_connections_total), ull(st.ws_connections_active), ull(st.wt_sessions_total),
	        ull(st.wt_sessions_active));
	jprintf(&j, ",\"httpReplies\":%llu},", ull(st.http_replies));
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
	        "\"retries\":%llu,\"refusedHandshakes\":%llu,\"dropped\":%llu",
	        ull(st.wt_sessions_total), ull(st.wt_sessions_active), ull(st.wt_handshakes), ull(st.wt_retries),
	        ull(st.wt_refused_handshakes), ull(st.wt_dropped));
	jprintf(&j,
	        ",\"quic\":{\"sessionsEnded\":%llu,\"packetsSent\":%llu,\"packetsReceived\":%llu,\"packetsLost\":%llu,"
	        "\"spuriousLost\":%llu,\"bytesSent\":%llu,\"bytesReceived\":%llu,\"congestionEvents\":%llu,"
	        "\"ptos\":%llu,\"srttUsSum\":%llu}}",
	        ull(st.wt_quic_sessions), ull(st.wt_quic_packets_sent), ull(st.wt_quic_packets_received),
	        ull(st.wt_quic_packets_lost), ull(st.wt_quic_spurious_lost), ull(st.wt_quic_bytes_sent),
	        ull(st.wt_quic_bytes_received), ull(st.wt_quic_congestion_events), ull(st.wt_quic_ptos),
	        ull(st.wt_quic_srtt_us));
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
	// Why streams ended, and how long their steps took: overall and per WARP tunnel.
	jprintf(&j, ",\"streamEnds\":{");
	json_reasons(&j, "ended", st.streams_ended);
	jprintf(&j, ",");
	json_reasons(&j, "failed", st.streams_failed);
	jprintf(&j, ",");
	json_reasons(&j, "refused", st.streams_refused);
	jprintf(&j,
	        ",\"clientClose\":{\"beforeOpen\":%llu,\"afterOpen\":%llu},"
	        "\"connectionEnd\":{\"beforeOpen\":%llu,\"afterOpen\":%llu}}",
	        ull(st.streams_client_closed[0]), ull(st.streams_client_closed[1]), ull(st.streams_conn_closed[0]),
	        ull(st.streams_conn_closed[1]));
	jprintf(&j, ",\"timing\":{\"boundsMs\":[");
	for (int i = 0; i < HW_STATS_HIST_BUCKETS - 1; i++) jprintf(&j, "%s%u", i ? "," : "", HW_STATS_HIST_BOUNDS_MS[i]);
	jprintf(&j, "],");
	json_hist(&j, "resolve", &st.resolve);
	jprintf(&j, ",");
	json_hist(&j, "tcpConnect", &st.tcp_connect);
	jprintf(&j, ",");
	json_hist(&j, "tcpFirstByte", &st.tcp_first_byte);
	jprintf(&j, ",");
	json_hist(&j, "proxiedConnect", &st.proxied_connect);
	jprintf(&j, ",");
	json_hist(&j, "proxiedFirstByte", &st.proxied_first_byte);
	jprintf(&j, ",");
	json_hist(&j, "udpFirstByte", &st.udp_first_byte);
	jprintf(&j, "},\"warpTunnels\":[");
	for (int i = 0; i < st.warp_tunnel_count; i++) {
		const hw_stats_tunnel *t = &st.warp_tunnels[i];
		// By position in udp-warp-marks, and the router's name for it when the state lists it now:
		// never the mark. Names are interface names, nothing that needs escaping.
		const char *name = tunnel_name(w, w->server->cfg.udp_warp_marks[i]);
		jprintf(&j, "%s{\"index\":%d,\"name\":", i ? "," : "", i);
		if (name) {
			jprintf(&j, "\"%s\"", name);
		} else {
			jprintf(&j, "null");
		}
		jprintf(&j, ",\"tcp\":{\"streams\":%llu,\"connectFailed\":%llu,", ull(t->tcp_streams),
		        ull(t->tcp_connect_failed));
		json_hist(&j, "connect", &t->tcp_connect);
		jprintf(&j, ",");
		json_hist(&j, "firstByte", &t->tcp_first_byte);
		jprintf(&j, "},\"udp\":{\"streams\":%llu,", ull(t->udp_streams));
		json_hist(&j, "firstByte", &t->udp_first_byte);
		jprintf(&j, "}}");
	}
	jprintf(&j, "]}\n");
	return j.failed ? -1 : 0;
}

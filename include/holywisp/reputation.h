/*
 * holywisp/reputation.h - IP reputation: a 0..100 score per source IP and per destination
 * ip:port, raised by weighted events, lowered by decay, persisted as JSON.
 *
 * Shared by every worker; each call takes one lock. Tiers turn scores into policy: WARN is logged,
 * THROTTLE tightens a client's limits, STRICT refuses the client or the destination.
 */
#ifndef HOLYWISP_REPUTATION_H
#define HOLYWISP_REPUTATION_H

#include <stddef.h>
#include <stdint.h>

enum hw_rep_event {
	HW_REP_PRIVATE_EGRESS = 0,
	HW_REP_SYN_SIGNATURE,
	HW_REP_TWISP_NO_AUTH,
	HW_REP_BURST_RATE,
	HW_REP_SUCCESSFUL_STREAM,
	HW_REP_KNOWN_BAD_DEST,
	HW_REP_AUTH_FAILURE,
	HW_REP_PROTOCOL_VIOLATION,
	HW_REP_EVENT_COUNT
};

enum hw_rep_tier {
	HW_TIER_NORMAL = 0,
	HW_TIER_WARN,
	HW_TIER_THROTTLE,
	HW_TIER_STRICT
};

typedef struct hw_reputation_config {
	char store_path[512]; // "" = memory only
	int save_interval_s;
	int decay_per_hour;
	int evict_after_days;
	int warn;     // thresholds; 0 disables a tier
	int throttle; //
	int strict;   //
	int source_weights[HW_REP_EVENT_COUNT];
	int dest_weights[HW_REP_EVENT_COUNT];
	int dest_distinct_sources_escalation; // added to a destination per new source IP seen
} hw_reputation_config;

typedef struct hw_reputation hw_reputation;

void hw_reputation_config_defaults(hw_reputation_config *cfg);
const char *hw_rep_event_name(enum hw_rep_event e);
int hw_rep_event_parse(const char *name); // -1 unknown
const char *hw_rep_tier_name(enum hw_rep_tier t);

hw_reputation *hw_reputation_new(const hw_reputation_config *cfg);
void hw_reputation_free(hw_reputation *r);

void hw_reputation_add_source(hw_reputation *r, const char *ip, enum hw_rep_event e);
// src_ip may be NULL; when given, a first-time source raises the destination further.
void hw_reputation_add_dest(hw_reputation *r, const char *dest, enum hw_rep_event e, const char *src_ip);
int hw_reputation_source_score(hw_reputation *r, const char *ip);
int hw_reputation_dest_score(hw_reputation *r, const char *dest);
enum hw_rep_tier hw_reputation_tier(const hw_reputation *r, int score);

// Maintenance: decay by elapsed time since the last decay, drop stale low scores, write the file.
void hw_reputation_decay(hw_reputation *r);
void hw_reputation_evict(hw_reputation *r);
int hw_reputation_save(hw_reputation *r); // 0 ok, -1 errno
int hw_reputation_load(hw_reputation *r); // 0 ok (missing file is ok), -1 errno/EINVAL
void hw_reputation_counts(hw_reputation *r, size_t *sources, size_t *dests);

#endif

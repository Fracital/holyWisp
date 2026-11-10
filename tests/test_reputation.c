#include "holywisp/reputation.h"

#include "test.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void test_scoring_and_tiers(void) {
	hw_reputation_config cfg;
	hw_reputation_config_defaults(&cfg);
	hw_reputation *r = hw_reputation_new(&cfg);
	CHECK(r != NULL, "new");

	CHECK_EQ(hw_reputation_source_score(r, "1.2.3.4"), 0);
	hw_reputation_add_source(r, "1.2.3.4", HW_REP_SYN_SIGNATURE); // +25
	CHECK_EQ(hw_reputation_source_score(r, "1.2.3.4"), 25);
	CHECK_EQ(hw_reputation_tier(r, 25), HW_TIER_WARN);
	hw_reputation_add_source(r, "1.2.3.4", HW_REP_TWISP_NO_AUTH); // +40 -> 65
	CHECK_EQ(hw_reputation_source_score(r, "1.2.3.4"), 65);
	CHECK_EQ(hw_reputation_tier(r, 65), HW_TIER_THROTTLE);
	hw_reputation_add_source(r, "1.2.3.4", HW_REP_TWISP_NO_AUTH); // +40 -> clamps at 100
	CHECK_EQ(hw_reputation_source_score(r, "1.2.3.4"), 100);
	CHECK_EQ(hw_reputation_tier(r, 100), HW_TIER_STRICT);
	// Success lowers the score (negative weight), clamped at 0.
	hw_reputation_add_source(r, "5.5.5.5", HW_REP_SUCCESSFUL_STREAM);
	CHECK_EQ(hw_reputation_source_score(r, "5.5.5.5"), 0);

	// Destination scoring escalates with distinct sources.
	hw_reputation_add_dest(r, "9.9.9.9:443", HW_REP_SYN_SIGNATURE, "1.1.1.1"); // +30 +1
	hw_reputation_add_dest(r, "9.9.9.9:443", HW_REP_SYN_SIGNATURE, "2.2.2.2"); // +30 +1
	hw_reputation_add_dest(r, "9.9.9.9:443", HW_REP_SYN_SIGNATURE, "1.1.1.1"); // same source: no escalation
	CHECK_EQ(hw_reputation_dest_score(r, "9.9.9.9:443"), 92); // 30+1, +30+1, +30 (repeat source: no escalation)
	hw_reputation_free(r);
}

static void test_decay(void) {
	hw_reputation_config cfg;
	hw_reputation_config_defaults(&cfg);
	// 100 points per second: a short sleep decays visibly, and one that overruns by half a second (a
	// loaded CI machine) still leaves some of the 80.
	cfg.decay_per_hour = 360000;
	hw_reputation *r = hw_reputation_new(&cfg);
	hw_reputation_add_source(r, "1.2.3.4", HW_REP_TWISP_NO_AUTH);
	hw_reputation_add_source(r, "1.2.3.4", HW_REP_TWISP_NO_AUTH); // 80
	CHECK(hw_reputation_source_score(r, "1.2.3.4") >= 80, "before decay");
	usleep(100000); // 10 points, or more
	hw_reputation_decay(r);
	int after = hw_reputation_source_score(r, "1.2.3.4");
	CHECK(after < 80 && after > 0, "decayed partially: %d", after);
	hw_reputation_free(r);
}

static void test_persistence(void) {
	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-rep");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	close(fd);

	hw_reputation_config cfg;
	hw_reputation_config_defaults(&cfg);
	snprintf(cfg.store_path, sizeof(cfg.store_path), "%s", path);
	hw_reputation *r = hw_reputation_new(&cfg);
	hw_reputation_add_source(r, "203.0.113.1", HW_REP_SYN_SIGNATURE);
	hw_reputation_add_source(r, "203.0.113.1", HW_REP_BURST_RATE);
	hw_reputation_add_dest(r, "8.8.8.8:53", HW_REP_BURST_RATE, "203.0.113.1");
	int src_score = hw_reputation_source_score(r, "203.0.113.1");
	CHECK_EQ(hw_reputation_save(r), 0);
	hw_reputation_free(r);

	// Load into a fresh instance and confirm the scores survived.
	hw_reputation *r2 = hw_reputation_new(&cfg);
	CHECK_EQ(hw_reputation_load(r2), 0);
	CHECK_EQ(hw_reputation_source_score(r2, "203.0.113.1"), src_score);
	CHECK(hw_reputation_dest_score(r2, "8.8.8.8:53") > 0, "dest survived");
	size_t sources, dests;
	hw_reputation_counts(r2, &sources, &dests);
	CHECK_EQ(sources, 1);
	CHECK_EQ(dests, 1);
	hw_reputation_free(r2);
	unlink(path);
}

static void test_event_names(void) {
	for (int i = 0; i < HW_REP_EVENT_COUNT; i++) {
		const char *name = hw_rep_event_name(i);
		CHECK_EQ(hw_rep_event_parse(name), i);
	}
	CHECK_EQ(hw_rep_event_parse("nonsense"), -1);
}

int main(void) {
	RUN(test_scoring_and_tiers);
	RUN(test_decay);
	RUN(test_persistence);
	RUN(test_event_names);
	return 0;
}

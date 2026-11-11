#include "holywisp/reputation.h"

#include "test.h"

#include <errno.h>
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

// A new store path in the temporary directory, with nothing at it.
static void store_path(char *path, size_t cap) {
	hw_test_tmp(path, cap, "hw-rep");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	close(fd);
	unlink(path);
}

// The temporary file a save writes is a new file every time. Whatever already stands at its
// name is not opened and written through: it used to be, with fopen("w"), and a symbolic link
// put there by another user of the directory made the server overwrite the file it pointed at.
// The stand-in for the link's target here is a file that is held open across the save.
static void test_save_makes_its_own_temp_file(void) {
	char path[512], tmp[600];
	store_path(path, sizeof(path));
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	FILE *planted = fopen(tmp, "w+");
	CHECK(planted != NULL, "plant %s", tmp);
	CHECK(fputs("not the server's to write", planted) >= 0 && fflush(planted) == 0, "plant");

	hw_reputation_config cfg;
	hw_reputation_config_defaults(&cfg);
	snprintf(cfg.store_path, sizeof(cfg.store_path), "%s", path);
	hw_reputation *r = hw_reputation_new(&cfg);
	hw_reputation_add_source(r, "203.0.113.1", HW_REP_SYN_SIGNATURE);
	int saved = hw_reputation_save(r);

	// What was planted is as it was, read through the handle that was open before the save.
	char buf[64];
	CHECK_EQ(fseek(planted, 0, SEEK_SET), 0);
	size_t n = fread(buf, 1, sizeof(buf) - 1, planted);
	buf[n] = '\0';
	CHECK_STR(buf, "not the server's to write");
	fclose(planted);
	// Where a file that is open cannot be removed (Windows) the save has failed instead, and
	// works once the file is nobody's.
	if (saved != 0) {
		CHECK_EQ(hw_reputation_save(r), 0);
	}
	hw_reputation_free(r);

	// The store itself is the table, and the temporary name is free again.
	hw_reputation *r2 = hw_reputation_new(&cfg);
	CHECK_EQ(hw_reputation_load(r2), 0);
	CHECK_EQ(hw_reputation_source_score(r2, "203.0.113.1"), 25);
	hw_reputation_free(r2);
	FILE *left = fopen(tmp, "r");
	CHECK(left == NULL, "%s is still there", tmp);
	unlink(path);
}

// Write a store file: head, then `depth` times `open`, then tail.
static void write_nested(const char *path, const char *head, const char *open, int depth, const char *tail) {
	FILE *f = fopen(path, "w");
	CHECK(f != NULL, "write %s", path);
	fputs(head, f);
	for (int i = 0; i < depth; i++) fputs(open, f);
	fputs(tail, f);
	fclose(f);
}

static int load_file(const char *path, int *score) {
	hw_reputation_config cfg;
	hw_reputation_config_defaults(&cfg);
	snprintf(cfg.store_path, sizeof(cfg.store_path), "%s", path);
	hw_reputation *r = hw_reputation_new(&cfg);
	errno = 0;
	int rc = hw_reputation_load(r);
	int saved = errno;
	if (score) *score = hw_reputation_source_score(r, "203.0.113.1");
	hw_reputation_free(r);
	errno = saved;
	return rc;
}

// The reader skips values it does not know by recursion. 200 kB of "[" in the store took the
// stack, and the server with it, at startup; now it is a malformed file like any other.
static void test_load_depth_is_bounded(void) {
	char path[512];
	store_path(path, sizeof(path));
	static const char *const heads[] = {"{\"x\":", "{\"sources\":{\"k\":{\"zz\":", "{\"destinations\":{\"k\":{\"zz\":"};
	for (size_t i = 0; i < sizeof(heads) / sizeof(heads[0]); i++) {
		write_nested(path, heads[i], "[", 200000, "");
		CHECK_EQ(load_file(path, NULL), -1);
		CHECK_EQ(errno, EINVAL);
		write_nested(path, heads[i], "{\"a\":", 200000, "");
		CHECK_EQ(load_file(path, NULL), -1);
		CHECK_EQ(errno, EINVAL);
	}
	// 32 levels of something unknown are skipped and the rest of the file is read...
	const char *tail = "1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]],"
	                   "\"sources\":{\"203.0.113.1\":{\"score\":42,\"future\":{\"a\":[1,{\"b\":[]}]}}}}";
	int score = -1;
	write_nested(path, "{\"x\":", "[", 32, tail);
	CHECK_EQ(load_file(path, &score), 0);
	CHECK_EQ(score, 42);
	// ...and one level more is not, though the file is well-formed.
	write_nested(path, "{\"x\":", "[", 33, "1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}");
	CHECK_EQ(load_file(path, &score), -1);
	CHECK_EQ(errno, EINVAL);
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
	RUN(test_save_makes_its_own_temp_file);
	RUN(test_load_depth_is_bounded);
	RUN(test_event_names);
	return 0;
}

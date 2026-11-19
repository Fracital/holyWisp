/*
 * tests/test_quic.c - the QUIC connection (holywisp/quic.h). First the parts that need no
 * cryptography (frames, range sets, stream buffers, RTT and NewReno, the stream map), then a
 * client and a server connection against each other through a simulated path with its own
 * clock: loss, reordering, duplication, delay and bandwidth, all drawn from a seeded generator,
 * so that every run of a case is the same run.
 *
 * `test_quic --bench [MiB]` runs only the single-stream throughput measurement, and
 * `test_quic --loss-table` only the goodput under loss and reordering, as a fraction of the link.
 */
#include "holywisp/cert.h"
#include "holywisp/ecc.h"
#include "holywisp/quic.h"
#include "holywisp/sha256.h"
#include "holywisp/sys.h"

#include "quic/quic_internal.h"
#include "quic/tls13_internal.h"
#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// ---- Frames and containers -----------------------------------------------------------------

static void test_varint(void) {
	static const uint64_t vals[] = {0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, HW_QW_VARINT_MAX};
	for (size_t i = 0; i < HW_ARRAY_LEN(vals); i++) {
		uint8_t b[8];
		uint8_t *e = hw_qc_vput(b, vals[i]);
		CHECK_EQ((size_t)(e - b), hw_qc_vlen(vals[i]));
		CHECK_EQ(hw_qw_varint_len(vals[i]), hw_qc_vlen(vals[i]));
		uint64_t v = 0;
		CHECK_EQ(hw_qc_vget(b, e, &v), hw_qc_vlen(vals[i]));
		CHECK_EQ(v, vals[i]);
		CHECK_EQ(hw_qc_vget(b, e - 1, &v), 0);
	}
}

static void test_ranges(void) {
	hw_qc_ranges s;
	hw_qc_ranges_init(&s, 0, 0);
	CHECK_EQ(hw_qc_ranges_add(&s, 10, 20), 0);
	CHECK_EQ(hw_qc_ranges_add(&s, 30, 40), 0);
	CHECK_EQ(hw_qc_ranges_add(&s, 0, 5), 0);
	CHECK_EQ(s.n, 3);
	CHECK(hw_qc_ranges_contains(&s, 10) && hw_qc_ranges_contains(&s, 19) && !hw_qc_ranges_contains(&s, 20), "edges");
	CHECK_EQ(hw_qc_ranges_add(&s, 20, 30), 0); // touches both neighbours
	CHECK_EQ(s.n, 2);
	CHECK_EQ(s.r[1].lo, 10);
	CHECK_EQ(s.r[1].hi, 40);
	CHECK_EQ(hw_qc_ranges_add(&s, 3, 12), 0);
	CHECK_EQ(s.n, 1);
	CHECK_EQ(s.r[0].lo, 0);
	CHECK_EQ(s.r[0].hi, 40);
	CHECK_EQ(hw_qc_ranges_remove(&s, 10, 20), 0); // split
	CHECK_EQ(s.n, 2);
	CHECK(!hw_qc_ranges_contains(&s, 15) && hw_qc_ranges_contains(&s, 9) && hw_qc_ranges_contains(&s, 20), "split");
	CHECK_EQ(hw_qc_ranges_remove(&s, 5, 25), 0);
	CHECK_EQ(s.r[0].hi, 5);
	CHECK_EQ(s.r[1].lo, 25);
	hw_qc_ranges_clear(&s);

	// Bounded, dropping the oldest: the floor then covers what was forgotten.
	hw_qc_ranges_init(&s, 3, 1);
	for (uint64_t i = 0; i < 10; i++) CHECK_EQ(hw_qc_ranges_add(&s, i * 10, i * 10 + 5), 0);
	CHECK_EQ(s.n, 3);
	CHECK_EQ(s.r[0].lo, 70);
	CHECK(hw_qc_ranges_contains(&s, 64) && !hw_qc_ranges_contains(&s, 66) && !hw_qc_ranges_contains(&s, 76), "floor");
	hw_qc_ranges_prune_below(&s, 85);
	CHECK_EQ(s.n, 1);
	CHECK(hw_qc_ranges_contains(&s, 84), "pruned below is seen");
	CHECK_EQ(hw_qc_ranges_add(&s, 90, 95), 0);
	hw_qc_ranges_forget_below(&s, 95); // forgotten, not seen: it may come again
	CHECK(s.n == 0 && s.floor == 85 && !hw_qc_ranges_contains(&s, 90), "forgotten");
	CHECK_EQ(hw_qc_ranges_add(&s, 88, 89), 0);
	CHECK(s.n == 1 && hw_qc_ranges_contains(&s, 88), "added again");
	hw_qc_ranges_clear(&s);

	// Bounded without dropping: the add fails.
	hw_qc_ranges_init(&s, 2, 0);
	CHECK_EQ(hw_qc_ranges_add(&s, 0, 1), 0);
	CHECK_EQ(hw_qc_ranges_add(&s, 2, 3), 0);
	CHECK_EQ(hw_qc_ranges_add(&s, 4, 5), -1);
	CHECK_EQ(hw_qc_ranges_add(&s, 1, 2), 0); // a merge needs no new range
	CHECK_EQ(s.n, 1);
	hw_qc_ranges_clear(&s);
}

static void test_frames_roundtrip(void) {
	uint8_t buf[512];
	hw_qc_frame f;
	const uint8_t *end;
	size_t n;

	// ACK with three ranges: {0-4, 10-12, 20}.
	hw_qc_ranges r;
	hw_qc_ranges_init(&r, 0, 0);
	hw_qc_ranges_add(&r, 0, 5);
	hw_qc_ranges_add(&r, 10, 13);
	hw_qc_ranges_add(&r, 20, 21);
	size_t nr = 0;
	n = hw_qc_put_ack(buf, sizeof(buf), &r, 77, &nr);
	CHECK(n > 0 && nr == 3, "ack written");
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	CHECK_EQ(f.type, HW_QC_F_ACK);
	CHECK_EQ(f.ack_largest, 20);
	CHECK_EQ(f.ack_delay, 77);
	hw_qc_ack_iter it;
	hw_qc_ack_iter_init(&it, &f);
	CHECK(it.lo == 20 && it.hi == 20, "first range");
	CHECK(hw_qc_ack_iter_next(&it) && it.lo == 10 && it.hi == 12, "second range");
	CHECK(hw_qc_ack_iter_next(&it) && it.lo == 0 && it.hi == 4, "third range");
	CHECK(!hw_qc_ack_iter_next(&it), "no fourth");
	// Too little room: fewer ranges, still valid.
	n = hw_qc_put_ack(buf, 8, &r, 0, &nr);
	CHECK(n > 0 && nr < 3, "ack cut to fit (%zu ranges)", nr);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	hw_qc_ranges_clear(&r);

	static const uint8_t abc[3] = {'a', 'b', 'c'};
	n = hw_qc_put_stream_header(buf, sizeof(buf), 4, 1000, 3, 1);
	memcpy(buf + n, abc, 3);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n + 3, &f), n + 3);
	CHECK(f.type == HW_QC_F_STREAM && f.stream_id == 4 && f.offset == 1000 && f.len == 3 && f.fin, "stream");
	CHECK(memcmp(f.data, abc, 3) == 0, "stream data");
	n = hw_qc_put_stream_header(buf, sizeof(buf), 0, 0, 0, 1);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	CHECK(f.offset == 0 && f.len == 0 && f.fin, "fin only");
	CHECK_EQ(hw_qc_put_stream_header(buf, 4, 0, 0, 10, 0), 0);

	n = hw_qc_put_crypto_header(buf, sizeof(buf), 70000, 2);
	memcpy(buf + n, abc, 2);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n + 2, &f), n + 2);
	CHECK(f.type == HW_QC_F_CRYPTO && f.offset == 70000 && f.len == 2, "crypto");

	n = hw_qc_put_reset_stream(buf, sizeof(buf), 8, 0x42, 123456);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	CHECK(f.type == HW_QC_F_RESET_STREAM && f.stream_id == 8 && f.error == 0x42 && f.value == 123456, "reset");

	static const uint64_t simple[] = {HW_QC_F_MAX_DATA,
	                                  HW_QC_F_DATA_BLOCKED,
	                                  HW_QC_F_MAX_STREAMS_BIDI,
	                                  HW_QC_F_MAX_STREAMS_UNI,
	                                  HW_QC_F_STREAMS_BLOCKED_BIDI,
	                                  HW_QC_F_STREAMS_BLOCKED_UNI,
	                                  HW_QC_F_RETIRE_CONNECTION_ID};
	for (size_t i = 0; i < HW_ARRAY_LEN(simple); i++) {
		n = hw_qc_put_simple(buf, sizeof(buf), simple[i], 99999);
		CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
		CHECK(f.type == simple[i] && f.value == 99999, "simple %llx", (unsigned long long)simple[i]);
	}
	static const uint64_t pair[] = {HW_QC_F_MAX_STREAM_DATA, HW_QC_F_STREAM_DATA_BLOCKED};
	for (size_t i = 0; i < HW_ARRAY_LEN(pair); i++) {
		n = hw_qc_put_pair(buf, sizeof(buf), pair[i], 13, 1u << 20);
		CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
		CHECK(f.type == pair[i] && f.stream_id == 13 && f.value == 1u << 20, "pair");
	}
	n = hw_qc_put_pair(buf, sizeof(buf), HW_QC_F_STOP_SENDING, 13, 7);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	CHECK(f.type == HW_QC_F_STOP_SENDING && f.stream_id == 13 && f.error == 7, "stop");

	uint8_t cid[8] = {1, 2, 3, 4, 5, 6, 7, 8}, tok[16];
	memset(tok, 0xaa, sizeof(tok));
	n = hw_qc_put_new_cid(buf, sizeof(buf), 5, 2, cid, 8, tok);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	CHECK(f.type == HW_QC_F_NEW_CONNECTION_ID && f.value == 5 && f.value2 == 2 && f.len == 8, "new cid");
	CHECK(memcmp(f.data, cid, 8) == 0 && memcmp(f.token, tok, 16) == 0, "new cid bytes");

	n = hw_qc_put_path(buf, sizeof(buf), HW_QC_F_PATH_CHALLENGE, cid);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	CHECK(f.type == HW_QC_F_PATH_CHALLENGE && memcmp(f.data, cid, 8) == 0, "path");

	n = hw_qc_put_close(buf, sizeof(buf), 0, HW_QUIC_PROTOCOL_VIOLATION, 0x08, "bad", 3);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	CHECK(f.type == HW_QC_F_CONNECTION_CLOSE && f.error == 0xa && f.value == 8 && f.len == 3, "close");
	n = hw_qc_put_close(buf, sizeof(buf), 1, 0x1234, 0, "bye", 3);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	CHECK(f.type == HW_QC_F_CONNECTION_CLOSE_APP && f.error == 0x1234 && memcmp(f.data, "bye", 3) == 0, "app close");
	n = hw_qc_put_close(buf, 10, 1, 0x1234, 0, "a long reason that does not fit", 31);
	CHECK(n > 0 && n <= 10, "reason cut");
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);

	n = hw_qc_put_datagram(buf, sizeof(buf), (const uint8_t *)"xyz", 3);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + n, &f), n);
	CHECK(f.type == HW_QC_F_DATAGRAM && f.len == 3, "datagram");
	buf[0] = HW_QC_F_DATAGRAM;
	memcpy(buf + 1, abc, 3);
	buf[4] = 'd';
	CHECK_EQ(hw_qc_frame_parse(buf, buf + 5, &f), 5);
	CHECK(f.type == HW_QC_F_DATAGRAM && f.len == 4, "datagram to the end");

	memset(buf, 0, 20);
	CHECK_EQ(hw_qc_frame_parse(buf, buf + 20, &f), 20); // one run of padding
	buf[0] = HW_QC_F_HANDSHAKE_DONE;
	CHECK_EQ(hw_qc_frame_parse(buf, buf + 1, &f), 1);
	end = buf;
	(void)end;
}

static void test_frames_malformed(void) {
	uint8_t b[64] = {0};
	hw_qc_frame f;
	// Unknown type.
	b[0] = 0x21;
	CHECK_EQ(hw_qc_frame_parse(b, b + 1, &f), 0);
	CHECK_EQ(f.type, 0x21);
	b[0] = 0x40; // a type cut short
	CHECK_EQ(hw_qc_frame_parse(b, b + 1, &f), 0);
	// ACK whose first range runs below zero.
	uint8_t a1[] = {0x02, 5, 0, 0, 6};
	CHECK_EQ(hw_qc_frame_parse(a1, a1 + sizeof(a1), &f), 0);
	// ACK whose gap runs below zero.
	uint8_t a2[] = {0x02, 5, 0, 1, 0, 4, 0};
	CHECK_EQ(hw_qc_frame_parse(a2, a2 + sizeof(a2), &f), 0);
	// STREAM longer than the packet.
	uint8_t s1[] = {0x0a, 0, 10, 'a'};
	CHECK_EQ(hw_qc_frame_parse(s1, s1 + sizeof(s1), &f), 0);
	// NEW_CONNECTION_ID with length 0, 21, retire_prior_to past the sequence.
	uint8_t n1[40] = {0x18, 1, 0, 0};
	CHECK_EQ(hw_qc_frame_parse(n1, n1 + sizeof(n1), &f), 0);
	n1[3] = 21;
	CHECK_EQ(hw_qc_frame_parse(n1, n1 + sizeof(n1), &f), 0);
	uint8_t n2[40] = {0x18, 1, 2, 8};
	CHECK_EQ(hw_qc_frame_parse(n2, n2 + sizeof(n2), &f), 0);
	// MAX_STREAMS over 2^60.
	uint8_t m1[9] = {0x12};
	hw_qc_vput(m1 + 1, (1ull << 60) + 1);
	CHECK_EQ(hw_qc_frame_parse(m1, m1 + sizeof(m1), &f), 0);
	// NEW_TOKEN with an empty token, CONNECTION_CLOSE whose reason runs past the end.
	uint8_t t1[] = {0x07, 0};
	CHECK_EQ(hw_qc_frame_parse(t1, t1 + sizeof(t1), &f), 0);
	uint8_t c1[] = {0x1d, 0, 9, 'x'};
	CHECK_EQ(hw_qc_frame_parse(c1, c1 + sizeof(c1), &f), 0);
	// PATH_CHALLENGE short of 8 bytes.
	uint8_t p1[] = {0x1a, 1, 2, 3};
	CHECK_EQ(hw_qc_frame_parse(p1, p1 + sizeof(p1), &f), 0);
}

static void test_sendbuf(void) {
	hw_qc_sendbuf b;
	hw_qc_sendbuf_init(&b);
	uint8_t data[10000], out[10000];
	for (size_t i = 0; i < sizeof(data); i++) data[i] = (uint8_t)(i * 7);
	CHECK_EQ(hw_qc_sendbuf_write(&b, data, 6000), 0);
	CHECK_EQ(hw_qc_sendbuf_write(&b, data + 6000, 4000), 0);
	b.fin = 1;
	uint64_t off;
	size_t len;
	int fin;
	// Send it in 1000-byte frames.
	for (int i = 0; i < 10; i++) {
		CHECK(hw_qc_sendbuf_next(&b, 1000, &off, &len, &fin), "next %d", i);
		CHECK_EQ(off, (uint64_t)i * 1000);
		CHECK_EQ(len, 1000);
		CHECK_EQ(fin, i == 9);
		hw_qc_sendbuf_copy(&b, off, len, out + off);
		hw_qc_sendbuf_sent(&b, off, len, fin);
	}
	CHECK(memcmp(out, data, sizeof(data)) == 0, "copied");
	CHECK(!hw_qc_sendbuf_pending(&b), "all sent");
	// Acks out of order, a loss in the middle.
	CHECK_EQ(hw_qc_sendbuf_ack(&b, 1000, 1000, 0), 0);
	CHECK_EQ(hw_qc_sendbuf_ack(&b, 0, 1000, 0), 2000);
	CHECK_EQ(b.base, 2000);
	hw_qc_sendbuf_lost(&b, 2000, 3000, 0); // 2000..5000, of which 3000..4000 is acked next
	CHECK_EQ(hw_qc_sendbuf_ack(&b, 3000, 1000, 0), 0);
	hw_qc_sendbuf_lost(&b, 9000, 1000, 1);
	CHECK(hw_qc_sendbuf_pending(&b), "lost to send");
	CHECK(hw_qc_sendbuf_next(&b, 5000, &off, &len, &fin) && off == 2000 && len == 1000 && !fin, "first loss");
	hw_qc_sendbuf_sent(&b, off, len, fin);
	CHECK(hw_qc_sendbuf_next(&b, 5000, &off, &len, &fin) && off == 4000 && len == 1000, "second loss");
	hw_qc_sendbuf_sent(&b, off, len, fin);
	CHECK(hw_qc_sendbuf_next(&b, 5000, &off, &len, &fin) && off == 9000 && len == 1000 && fin, "fin resent");
	hw_qc_sendbuf_sent(&b, off, len, fin);
	CHECK(!hw_qc_sendbuf_pending(&b), "caught up");
	hw_qc_sendbuf_ack(&b, 2000, 1000, 0);
	hw_qc_sendbuf_ack(&b, 4000, 6000, 1);
	CHECK(hw_qc_sendbuf_done(&b), "done");
	// The ring wraps and grows with bytes held.
	CHECK_EQ(hw_qc_sendbuf_write(&b, data, 3000), 0);
	CHECK_EQ(hw_qc_sendbuf_write(&b, data, 9000), 0);
	hw_qc_sendbuf_copy(&b, 10000 + 3000, 9000, out);
	CHECK(memcmp(out, data, 9000) == 0, "after growth");
	hw_qc_sendbuf_clear(&b);
}

static void test_recvbuf(void) {
	hw_qc_recvbuf b;
	hw_qc_recvbuf_init(&b, 4);
	uint8_t data[20000];
	for (size_t i = 0; i < sizeof(data); i++) data[i] = (uint8_t)(i * 13 + 1);
	const uint8_t *d;
	size_t dl;
	// In order: straight through, nothing copied.
	CHECK_EQ(hw_qc_recvbuf_push(&b, 0, data, 100, &d, &dl), 0);
	CHECK(d == data && dl == 100 && !b.cap, "direct");
	hw_qc_recvbuf_advance(&b, dl);
	// Ahead: buffered.
	CHECK_EQ(hw_qc_recvbuf_push(&b, 300, data + 300, 200, &d, &dl), 0);
	CHECK(!dl, "nothing in order");
	CHECK_EQ(hw_qc_recvbuf_push(&b, 5000, data + 5000, 9000, &d, &dl), 0);
	// Overlapping the delivered offset: the new part only.
	CHECK_EQ(hw_qc_recvbuf_push(&b, 50, data + 50, 250, &d, &dl), 0);
	CHECK(d == data + 100 && dl == 200, "overlap");
	hw_qc_recvbuf_advance(&b, dl);
	const uint8_t *p;
	size_t n = hw_qc_recvbuf_peek(&b, &p);
	CHECK(n == 200 && memcmp(p, data + 300, 200) == 0, "buffered next");
	hw_qc_recvbuf_advance(&b, n);
	CHECK_EQ(hw_qc_recvbuf_peek(&b, &p), 0);
	CHECK_EQ(hw_qc_recvbuf_push(&b, 500, data + 500, 4600, &d, &dl), 0);
	CHECK(d == data + 500 && dl == 4600, "fills the gap");
	hw_qc_recvbuf_advance(&b, dl);
	uint64_t at = b.off;
	while ((n = hw_qc_recvbuf_peek(&b, &p))) {
		CHECK(memcmp(p, data + at, n) == 0, "content at %llu", (unsigned long long)at);
		at += n;
		hw_qc_recvbuf_advance(&b, n);
	}
	CHECK_EQ(at, 14000);
	// Fragment bound.
	for (int i = 0; i < 4; i++) CHECK_EQ(hw_qc_recvbuf_push(&b, 15000 + 10 * i, data, 1, &d, &dl), 0);
	CHECK_EQ(hw_qc_recvbuf_push(&b, 16000, data, 1, &d, &dl), -1);
	hw_qc_recvbuf_clear(&b);
}

static void test_rtt_cc(void) {
	hw_qc_rtt r;
	hw_qc_rtt_init(&r);
	CHECK_EQ(r.smoothed, HW_QC_INITIAL_RTT_US);
	hw_qc_rtt_sample(&r, 100000, 0, 5);
	CHECK(r.smoothed == 100000 && r.var == 50000 && r.min == 100000, "first sample");
	hw_qc_rtt_sample(&r, 120000, 10000, 6); // adjusted to 110000
	CHECK_EQ(r.smoothed, (7 * 100000 + 110000) / 8);
	CHECK_EQ(r.var, (3 * 50000 + 10000) / 4);
	hw_qc_rtt_sample(&r, 100000, 50000, 7); // the delay would take it under min: not subtracted
	CHECK_EQ(r.latest, 100000);
	CHECK_EQ(hw_qc_rtt_pto(&r), r.smoothed + 4 * r.var);
	CHECK_EQ(hw_qc_rtt_loss_delay(&r, HW_QC_TIME_SHIFT), HW_MAX(r.latest, r.smoothed) * 9 / 8);
	CHECK_EQ(hw_qc_rtt_loss_delay(&r, 0), HW_MAX(r.latest, r.smoothed) * 2);

	hw_qc_cc c;
	hw_qc_cc_init(&c, 1200, 0);
	CHECK_EQ(c.cwnd, 12000);
	hw_qc_cc_on_sent(&c, 1200);
	hw_qc_cc_on_acked(&c, 1200, 10, 0);
	CHECK_EQ(c.cwnd, 13200); // slow start
	CHECK_EQ(c.in_flight, 0);
	hw_qc_cc_on_sent(&c, 1200);
	hw_qc_cc_on_acked(&c, 1200, 10, 1);
	CHECK_EQ(c.cwnd, 13200); // app-limited: no growth
	hw_qc_cc_congestion_event(&c, 100, 1, 200);
	CHECK_EQ(c.cwnd, 6600);
	CHECK_EQ(c.ssthresh, 6600);
	hw_qc_cc_congestion_event(&c, 150, 1, 300); // sent inside the recovery period
	CHECK_EQ(c.cwnd, 6600);
	hw_qc_cc_on_acked(&c, 1200, 150, 0); // nor does it grow then
	CHECK_EQ(c.cwnd, 6600);
	for (int i = 0; i < 6; i++) hw_qc_cc_on_acked(&c, 1200, 250, 0); // congestion avoidance
	CHECK_EQ(c.cwnd, 7800);
	hw_qc_cc_persistent(&c);
	CHECK_EQ(c.cwnd, 2400);

	// A spurious period is undone once every packet it declared lost came back, and only then.
	hw_qc_cc_init(&c, 1200, 0);
	hw_qc_cc_congestion_event(&c, 100, 2, 200);
	CHECK_EQ(c.cwnd, 6000);
	uint16_t e = c.epoch;
	CHECK_EQ(hw_qc_cc_spurious(&c, e), 0);                 // one of two
	CHECK_EQ(hw_qc_cc_spurious(&c, (uint16_t)(e - 1)), 0); // an older period's proves nothing
	CHECK_EQ(c.cwnd, 6000);
	hw_qc_cc_congestion_event(&c, 150, 1, 250); // a third loss in the same period
	CHECK_EQ(hw_qc_cc_spurious(&c, e), 0);
	CHECK_EQ(hw_qc_cc_spurious(&c, e), 1);
	CHECK(c.cwnd == 12000 && c.ssthresh == UINT64_MAX && !c.in_recovery_valid, "undone");
	CHECK_EQ(hw_qc_cc_spurious(&c, e), 0); // once
	// A new period replaces the old one's undo; persistent congestion is never undone.
	hw_qc_cc_congestion_event(&c, 300, 1, 400);
	hw_qc_cc_congestion_event(&c, 500, 1, 600);
	CHECK_EQ(c.cwnd, 3000);
	CHECK_EQ(hw_qc_cc_spurious(&c, (uint16_t)(c.epoch - 1)), 0);
	CHECK_EQ(c.cwnd, 3000);
	hw_qc_cc_persistent(&c);
	CHECK_EQ(hw_qc_cc_spurious(&c, c.epoch), 0);
	CHECK_EQ(c.cwnd, 2400);

	// The pacer: the initial burst, then the rate.
	hw_qc_cc_init(&c, 1200, 0);
	hw_qc_rtt_init(&r);
	hw_qc_rtt_sample(&r, 10000, 0, 0);
	int sent = 0;
	while (hw_qc_pacer_next(&c, &r, 0) == 0 && sent < 100) {
		hw_qc_pacer_on_sent(&c, 1200);
		sent++;
	}
	CHECK_EQ(sent, 10);
	uint64_t t = hw_qc_pacer_next(&c, &r, 0);
	// 12000 bytes per 10 ms * 5/4 = 1500 bytes per ms: the next 1200 bytes in under a ms.
	CHECK(t > 0 && t <= 1000, "pacer wait %llu", (unsigned long long)t);
	CHECK_EQ(hw_qc_pacer_next(&c, &r, t), t);
}

// A path for the congestion controller alone: a bottleneck of g_cclink.rate bytes per microsecond
// (CCSIM_RATE when 0; from rate2_at on, rate2) with a queue of g_ccsim.queue_us, g_ccsim.rtt_us of
// propagation, an ACK for every packet, a loss detected when the packet three after it is
// acknowledged, and random loss of one packet in loss_in (0: none). Time is in microseconds and the
// run is deterministic. The sender's clock ticks every g_ccsim.tick_us: what the controller is told
// is the time of the last tick, and it is woken at a tick, as a caller of the hw_quic_* calls with a
// millisecond clock is. bbr: 0 NewReno, 1 BBR, 2 bbr2.
#define CCSIM_RATE 5u // 5 MB/s
#define CCSIM_MDS  1200u
#define CCSIM_RING (1u << 18) // packets the run may have in flight or unresolved at once

typedef struct {
	uint64_t rtt_us, queue_us, tick_us;
} ccsim_path;
static const ccsim_path CCSIM_DEFAULT = {40000, 40000, 1};
static ccsim_path g_ccsim = {40000, 40000, 1};
typedef struct {
	uint64_t rate, rate2, rate2_at;
} ccsim_link;
static const ccsim_link CCLINK_DEFAULT = {0, 0, 0};
static ccsim_link g_cclink = {0, 0, 0};
#define CCSIM_RTT_US (g_ccsim.rtt_us)

typedef struct {
	hw_qc_sent rec;
	uint64_t ack_at; // 0: lost
	int done;
} ccsim_pkt;

typedef struct {
	uint64_t delivered_after; // bytes acknowledged after t_measure
	uint64_t max_cwnd, min_cwnd_late;
	int saw_probe_rtt;
	uint64_t bw_after_app_limited;   // BBR's estimate when the app-limited stretch ended
	uint64_t bw_max_after;           // BBR's highest estimate after t_measure
	uint64_t sent_after, lost_after; // packets sent after t_measure, and how many of them the queue dropped
	uint64_t sent, lost;             // the same over the whole run
	uint64_t startup_end;            // when BBR first left STARTUP (0: never)
	uint64_t lost_at_startup_end;    // packets the queue had dropped by then
	uint64_t inflight_hi_at_startup_end, inflight_hi_end; // bbr2's bound then, and at the end
	int saw_up;                                           // bbr2 probed (PROBE_BW UP) after t_measure
} ccsim_result;

static uint64_t ccsim_rand(uint64_t *x) {
	*x ^= *x << 13;
	*x ^= *x >> 7;
	*x ^= *x << 17;
	return *x;
}

// Runs for `end` us. Between app_from and app_to the sender has only a tenth of the path's rate
// to send (it is app-limited); otherwise it always has data.
static void ccsim_run(int bbr, uint64_t loss_in, uint64_t end, uint64_t t_measure, uint64_t app_from, uint64_t app_to,
                      ccsim_result *out) {
	static ccsim_pkt pk[CCSIM_RING];
#define CCSIM_PK(i) (&pk[(i) & (CCSIM_RING - 1)])
	const uint64_t tick = g_ccsim.tick_us;
#define CCSIM_CLOCK(t) ((t) / tick * tick)
	memset(out, 0, sizeof(*out));
	out->min_cwnd_late = UINT64_MAX;
	hw_qc_cc c;
	hw_qc_rtt r;
	hw_qc_cc_init(&c, CCSIM_MDS, 0);
	if (bbr == 1) hw_qc_cc_use_bbr(&c, 0);
	if (bbr == 2) hw_qc_cc_use_bbr2(&c, 0);
	hw_qc_rtt_init(&r);
	uint64_t seed = 0x9e3779b97f4a7c15ull, now = 0, link_free_ns = 0, app_credit = 0, app_last = 0;
	uint64_t n = 0, next_ack = 0, scan = 0;
	while (now < end && n - scan < CCSIM_RING) {
		uint64_t rate = g_cclink.rate ? g_cclink.rate : CCSIM_RATE;
		if (g_cclink.rate2 && now >= g_cclink.rate2_at) rate = g_cclink.rate2;
		// Acknowledgments due by now, in order (the link is FIFO and the RTT constant).
		// A lost packet is passed over (loss detection declares it below); ACK times grow with the
		// send order, so the first one still due later ends the pass.
		while (next_ack < n && (!CCSIM_PK(next_ack)->ack_at || CCSIM_PK(next_ack)->ack_at <= now)) {
			uint64_t me = next_ack++;
			ccsim_pkt *p = CCSIM_PK(me);
			if (p->done || !p->ack_at) continue;
			p->done = 1;
			uint64_t at = CCSIM_CLOCK(p->ack_at);
			hw_qc_rs_on_acked(&c, &p->rec, at);
			hw_qc_cc_on_acked(&c, p->rec.size, p->rec.time, 0);
			uint64_t rtt = at - p->rec.time;
			if (!rtt) rtt = 1; // as quic.c: 0 is no sample
			hw_qc_rtt_sample(&r, rtt, 0, at);
			if (p->ack_at >= t_measure) out->delivered_after += p->rec.size;
			// Packet threshold 3: what was sent three or more before this one and not acked is lost.
			for (; scan + 3 <= me; scan++) {
				ccsim_pkt *l = CCSIM_PK(scan);
				if (l->done) continue;
				if (!l->ack_at) {
					l->done = 1;
					hw_qc_cc_on_lost(&c, &l->rec, scan);
					hw_qc_cc_remove(&c, l->rec.size);
					hw_qc_cc_congestion_event(&c, l->rec.time, 1, at);
				}
			}
			hw_qc_cc_on_ack_done(&c, rtt, at);
		}
		if (bbr && now >= t_measure && c.b.bw > out->bw_max_after) out->bw_max_after = c.b.bw;
		if (bbr && c.b.mode == HW_QC_BBR_PROBE_RTT) out->saw_probe_rtt = 1;
		if (bbr && !out->startup_end && c.b.mode != HW_QC_BBR_STARTUP) {
			out->startup_end = now;
			out->lost_at_startup_end = out->lost;
			out->inflight_hi_at_startup_end = c.b.inflight_hi;
		}
		if (bbr == 2 && now >= t_measure && c.b.mode == HW_QC_BBR_PROBE_BW && c.b.phase == HW_QC_BBR2_UP) {
			out->saw_up = 1;
		}
		if (c.cwnd > out->max_cwnd) out->max_cwnd = c.cwnd;
		if (now > end / 2 && c.cwnd < out->min_cwnd_late) out->min_cwnd_late = c.cwnd;
		if (bbr && app_to && now >= app_to && !out->bw_after_app_limited) out->bw_after_app_limited = c.b.bw;
		// Send what the window, the pacer and the application allow.
		int app_limited = now >= app_from && now < app_to;
		if (app_limited) {
			app_credit += (now - app_last) * rate / 10;
			if (app_credit > 4 * CCSIM_MDS) app_credit = 4 * CCSIM_MDS;
		}
		app_last = now;
		uint64_t wake = UINT64_MAX;
		while (hw_qc_cc_can_send(&c) && n - scan < CCSIM_RING) {
			uint64_t t = hw_qc_pacer_next(&c, &r, CCSIM_CLOCK(now));
			if (t > CCSIM_CLOCK(now)) {
				wake = (t + tick - 1) / tick * tick;
				break;
			}
			if (app_limited && app_credit < CCSIM_MDS) {
				hw_qc_cc_app_limited(&c);
				wake = now + CCSIM_MDS * 10 / rate;
				break;
			}
			if (app_limited) app_credit -= CCSIM_MDS;
			ccsim_pkt *p = CCSIM_PK(n++);
			memset(p, 0, sizeof(*p));
			p->rec.time = CCSIM_CLOCK(now);
			p->rec.size = CCSIM_MDS;
			hw_qc_rs_on_sent(&c, &p->rec, p->rec.time);
			hw_qc_cc_on_sent(&c, CCSIM_MDS);
			hw_qc_pacer_on_sent(&c, CCSIM_MDS);
			uint64_t start = HW_MAX(now * 1000, link_free_ns);
			int full = start - now * 1000 > g_ccsim.queue_us * 1000;
			int dropped = full || (loss_in && ccsim_rand(&seed) % loss_in == 0);
			if (!full) link_free_ns = start + CCSIM_MDS * 1000 / rate;
			p->ack_at = dropped ? 0 : link_free_ns / 1000 + CCSIM_RTT_US;
			out->sent++;
			out->lost += (uint64_t)full;
			if (now >= t_measure) {
				out->sent_after++;
				out->lost_after += (uint64_t)full;
			}
		}
		// On to the next thing that happens.
		uint64_t t = wake;
		if (next_ack < n && CCSIM_PK(next_ack)->ack_at < t) t = CCSIM_PK(next_ack)->ack_at;
		if (t == UINT64_MAX) t = now + 1000; // stalled: what is in flight is all lost
		now = t > now ? t : now + 1;
	}
	out->inflight_hi_end = c.b.inflight_hi;
#undef CCSIM_CLOCK
#undef CCSIM_PK
}

// BBR on a path that drops one packet in a hundred at random: it fills the bottleneck, where
// NewReno, halving its window at each loss, does not reach a quarter of it. Its model is the
// path's: the bandwidth within 10%, the minimum RTT within a millisecond.
static void test_bbr_random_loss(void) {
	ccsim_result b, nr;
	ccsim_run(1, 100, 20000000, 5000000, 0, 0, &b);
	ccsim_run(0, 100, 20000000, 5000000, 0, 0, &nr);
	uint64_t full = (uint64_t)CCSIM_RATE * 15000000; // the bottleneck's bytes over the 15 s measured
	CHECK(b.delivered_after > full * 85 / 100, "bbr delivered %llu of %llu", (unsigned long long)b.delivered_after,
	      (unsigned long long)full);
	CHECK(nr.delivered_after < full / 4, "newreno delivered %llu of %llu", (unsigned long long)nr.delivered_after,
	      (unsigned long long)full);
	hw_qc_cc c;
	hw_qc_cc_init(&c, CCSIM_MDS, 0);
	hw_qc_cc_use_bbr(&c, 0);
	// And a loss by itself changes nothing.
	uint64_t w = c.cwnd;
	hw_qc_cc_congestion_event(&c, 10, 3, 20);
	CHECK_EQ(c.cwnd, w);
	CHECK_EQ(c.ssthresh, UINT64_MAX);
}

// The model: after startup the estimate is the bottleneck's rate, the min RTT the path's, the
// window about two BDPs; after 10 s it goes to PROBE_RTT (4 packets) and comes back.
static void test_bbr_model(void) {
	ccsim_result b;
	ccsim_run(1, 0, 12000000, 1000000, 0, 0, &b);
	CHECK(b.saw_probe_rtt, "probe_rtt after 10 s");
	CHECK(b.min_cwnd_late <= 4 * CCSIM_MDS, "probe_rtt window %llu", (unsigned long long)b.min_cwnd_late);
	uint64_t bdp = (uint64_t)CCSIM_RATE * CCSIM_RTT_US;
	CHECK(b.max_cwnd >= 2 * bdp && b.max_cwnd <= 4 * bdp, "window %llu, bdp %llu", (unsigned long long)b.max_cwnd,
	      (unsigned long long)bdp);
	CHECK(b.delivered_after > (uint64_t)CCSIM_RATE * 11000000 * 85 / 100, "delivered %llu",
	      (unsigned long long)b.delivered_after);
}

// Sending a tenth of the path's rate for 3 s does not lower the estimate: those samples say
// what the application had, not what the path can do.
// The min RTT expires (10 s) while the application sends a tenth of the path: those samples are
// app-limited and skipped, so the filter's samples are all older than its window when PROBE_RTT
// cuts the window to four packets, which the application then outpaces. That probe's sample is
// not app-limited, and it replaced the estimate whole: after the probe the window was twice the
// BDP of four packets, and the rate took many seconds to come back. Now a sample in PROBE_RTT
// can only raise the estimate.
static void test_bbr_probe_rtt_stale(void) {
	ccsim_result b;
	ccsim_run(1, 0, 12000000, 0, 1000000, 11000000, &b);
	uint64_t rate = (uint64_t)CCSIM_RATE * 1000000;
	CHECK(b.saw_probe_rtt, "no PROBE_RTT");
	CHECK(b.bw_after_app_limited > rate * 85 / 100, "bw %llu of %llu after the probe",
	      (unsigned long long)b.bw_after_app_limited, (unsigned long long)rate);
}

// The sender's clock. BBR's rate sample is the bytes delivered over a round trip's interval; on a
// clock of whole milliseconds a 30 ms interval is known to 3%, and the filter keeps the highest
// sample, so it kept the ones the clock made high: the estimate sat 3% over the path, and behind
// a queue of 5 ms that is a standing queue and loss at every round (5 to 8% of the packets of a
// WebTransport download, netns 440 Mbit/s, 30 ms, 2026-11-19). The stack takes the time in
// microseconds (hw_quic_*_us) for that reason: on that clock the estimate is the path's.
static void test_bbr_clock_tick(void) {
	ccsim_result us, ms;
	uint64_t rate = (uint64_t)CCSIM_RATE * 1000000;
	g_ccsim = (ccsim_path){30000, 5000, 1};
	ccsim_run(1, 0, 10000000, 3000000, 0, 0, &us);
	g_ccsim.tick_us = 1000;
	ccsim_run(1, 0, 10000000, 3000000, 0, 0, &ms);
	g_ccsim = CCSIM_DEFAULT;
	CHECK(us.bw_max_after <= rate * 101 / 100, "bw %llu of %llu on a microsecond clock",
	      (unsigned long long)us.bw_max_after, (unsigned long long)rate);
	CHECK(us.lost_after * 100 < us.sent_after * 2, "lost %llu of %llu on a microsecond clock",
	      (unsigned long long)us.lost_after, (unsigned long long)us.sent_after);
	CHECK(us.delivered_after > rate * 7 * 95 / 100, "delivered %llu", (unsigned long long)us.delivered_after);
	// What the millisecond clock did, so that this test keeps showing it.
	CHECK(ms.bw_max_after > rate * 102 / 100, "bw %llu of %llu on a millisecond clock",
	      (unsigned long long)ms.bw_max_after, (unsigned long long)rate);
	CHECK(ms.lost_after > 2 * us.lost_after, "lost %llu on a millisecond clock, %llu on a microsecond one",
	      (unsigned long long)ms.lost_after, (unsigned long long)us.lost_after);
}

// A path shorter than a tick of the timers. The model's min RTT is floored to the tick (BBR paces
// and probes no finer), but a rate sample is judged against the RTT as measured: judged against
// the tick, every sample of a 200 us path with a queue of one packet was discarded but those
// that spanned a stall: the estimate stayed at half the path (on loopback, WebTransport at a fifth
// of its speed).
static void test_bbr_sub_tick_rtt(void) {
	ccsim_result b;
	g_ccsim = (ccsim_path){200, 300, 1};
	ccsim_run(1, 0, 3000000, 1000000, 0, 0, &b);
	g_ccsim = CCSIM_DEFAULT;
	uint64_t rate = (uint64_t)CCSIM_RATE * 1000000;
	CHECK(b.bw_max_after > rate * 90 / 100, "bw %llu of %llu", (unsigned long long)b.bw_max_after,
	      (unsigned long long)rate);
	CHECK(b.delivered_after > rate * 2 * 90 / 100, "delivered %llu of %llu", (unsigned long long)b.delivered_after,
	      (unsigned long long)(rate * 2));
}

static void test_bbr_app_limited(void) {
	ccsim_result b;
	ccsim_run(1, 0, 6000000, 0, 2000000, 5000000, &b);
	uint64_t rate = (uint64_t)CCSIM_RATE * 1000000;
	CHECK(b.bw_after_app_limited > rate * 85 / 100 && b.bw_after_app_limited < rate * 115 / 100, "bw %llu of %llu",
	      (unsigned long long)b.bw_after_app_limited, (unsigned long long)rate);
}

// bbr2 behind a shallow buffer at the path's rate (440 Mbit/s, 30 ms, 5 ms of queue): BBR's 1.25
// probes every eight rounds overfill a queue that small, and it never answers the loss, so it
// loses a packet in a hundred for as long as it sends. bbr2 bounds its flight where the loss
// began (inflight_hi) and probes above it only every 2 to 3 s, slowly: a fifth of that loss
// or less, at nearly the same goodput.
static void test_bbr2_shallow_buffer(void) {
	ccsim_result v1, v2;
	g_ccsim = (ccsim_path){30000, 5000, 1};
	g_cclink = (ccsim_link){55, 0, 0};
	ccsim_run(1, 0, 10000000, 2000000, 0, 0, &v1);
	ccsim_run(2, 0, 10000000, 2000000, 0, 0, &v2);
	g_ccsim = CCSIM_DEFAULT;
	g_cclink = CCLINK_DEFAULT;
	uint64_t path = 55ull * 8000000;
	CHECK(v2.lost_after * 5 < v1.lost_after, "dropped after startup: bbr2 %llu, bbr %llu of %llu sent",
	      (unsigned long long)v2.lost_after, (unsigned long long)v1.lost_after, (unsigned long long)v1.sent_after);
	CHECK(v2.lost_after * 1000 < v2.sent_after * 3, "bbr2 dropped %llu of %llu", (unsigned long long)v2.lost_after,
	      (unsigned long long)v2.sent_after);
	CHECK(v2.lost * 4 < v1.lost, "dropped in all: bbr2 %llu, bbr %llu", (unsigned long long)v2.lost,
	      (unsigned long long)v1.lost);
	CHECK(v2.delivered_after > path * 96 / 100 && v2.delivered_after + path * 2 / 100 > v1.delivered_after,
	      "delivered: bbr2 %llu, bbr %llu of %llu", (unsigned long long)v2.delivered_after,
	      (unsigned long long)v1.delivered_after, (unsigned long long)path);
	CHECK(v2.saw_up, "bbr2 probed");
}

// Random loss under the threshold is not congestion. On a long fat path that loses 0.3% at
// random (400 Mbit/s, 138 ms: the edge's long path, scaled) bbr2 keeps the path as BBR does.
// On a short one that loses 1% (40 Mbit/s, 40 ms; test_bbr_random_loss's path) a round of a
// hundred and seventy packets is over 2% by chance now and then; the short-term bounds wait for
// a second such round in a row, or each of those cut the window to a BDP and the goodput to 81%.
static void test_bbr2_random_loss(void) {
	ccsim_result v1, v2;
	g_ccsim = (ccsim_path){138000, 20000, 1};
	g_cclink = (ccsim_link){50, 0, 0};
	ccsim_run(1, 333, 20000000, 5000000, 0, 0, &v1);
	ccsim_run(2, 333, 20000000, 5000000, 0, 0, &v2);
	g_ccsim = CCSIM_DEFAULT;
	g_cclink = CCLINK_DEFAULT;
	uint64_t path = 50ull * 15000000;
	CHECK(v1.delivered_after > path * 85 / 100, "bbr delivered %llu of %llu", (unsigned long long)v1.delivered_after,
	      (unsigned long long)path);
	CHECK(v2.delivered_after > path * 90 / 100, "bbr2 delivered %llu of %llu", (unsigned long long)v2.delivered_after,
	      (unsigned long long)path);
	CHECK(v2.inflight_hi_end > 50ull * 138000, "inflight_hi %llu under the BDP",
	      (unsigned long long)v2.inflight_hi_end);
	ccsim_run(2, 100, 20000000, 5000000, 0, 0, &v2);
	path = (uint64_t)CCSIM_RATE * 15000000;
	CHECK(v2.delivered_after > path * 90 / 100, "1%%: bbr2 delivered %llu of %llu",
	      (unsigned long long)v2.delivered_after, (unsigned long long)path);
}

// Startup ends on loss: past the path's BDP and queue, a round with more than 2% lost in six
// places or more is the end of it, and inflight_hi is what was in flight where the loss began,
// the BDP and the queue. BBR waits for three rounds without growth, sending at 2.89 times the
// path into the queue's drops all that while.
static void test_bbr2_startup_loss(void) {
	ccsim_result v1, v2;
	g_ccsim = (ccsim_path){30000, 5000, 1};
	g_cclink = (ccsim_link){55, 0, 0};
	ccsim_run(1, 0, 2000000, 1000000, 0, 0, &v1);
	ccsim_run(2, 0, 2000000, 1000000, 0, 0, &v2);
	g_ccsim = CCSIM_DEFAULT;
	g_cclink = CCLINK_DEFAULT;
	uint64_t holds = 55ull * (30000 + 5000);
	CHECK(v2.startup_end && v2.startup_end < v1.startup_end, "startup over at %llu us, bbr's at %llu",
	      (unsigned long long)v2.startup_end, (unsigned long long)v1.startup_end);
	CHECK(v2.inflight_hi_at_startup_end > holds * 9 / 10 && v2.inflight_hi_at_startup_end < holds * 11 / 10,
	      "inflight_hi %llu when startup ended, the path holds %llu", (unsigned long long)v2.inflight_hi_at_startup_end,
	      (unsigned long long)holds);
	CHECK(v2.lost * 4 < v1.lost, "dropped in the first 2 s: bbr2 %llu, bbr %llu", (unsigned long long)v2.lost,
	      (unsigned long long)v1.lost);
}

// The path's capacity halves (440 to 220 Mbit/s at 5 s). The max filter remembers the old rate
// for two probe cycles; a round of too much loss outside a probe lowers bw_lo and inflight_lo,
// and a probe starts from bw_lo, so the loss ends within a second and does not come back.
static void test_bbr2_capacity_drop(void) {
	ccsim_result v2;
	g_ccsim = (ccsim_path){30000, 5000, 1};
	g_cclink = (ccsim_link){55, 27, 5000000};
	ccsim_run(2, 0, 14000000, 6000000, 0, 0, &v2);
	g_ccsim = CCSIM_DEFAULT;
	g_cclink = CCLINK_DEFAULT;
	uint64_t path = 27ull * 8000000;
	CHECK(v2.lost_after * 1000 < v2.sent_after * 3, "dropped %llu of %llu after the drop",
	      (unsigned long long)v2.lost_after, (unsigned long long)v2.sent_after);
	CHECK(v2.delivered_after > path * 93 / 100, "delivered %llu of %llu", (unsigned long long)v2.delivered_after,
	      (unsigned long long)path);
	CHECK(v2.bw_max_after < 27000000ull * 105 / 100, "bw %llu after the drop", (unsigned long long)v2.bw_max_after);
}

// What BBR's app-limited tests hold, for bbr2: an app-limited stretch does not lower the
// estimate, and PROBE_RTT's samples cannot replace one it left stale.
static void test_bbr2_app_limited(void) {
	ccsim_result b;
	uint64_t rate = (uint64_t)CCSIM_RATE * 1000000;
	ccsim_run(2, 0, 6000000, 0, 2000000, 5000000, &b);
	CHECK(b.bw_after_app_limited > rate * 85 / 100 && b.bw_after_app_limited < rate * 115 / 100, "bw %llu of %llu",
	      (unsigned long long)b.bw_after_app_limited, (unsigned long long)rate);
	ccsim_run(2, 0, 12000000, 0, 1000000, 11000000, &b);
	CHECK(b.saw_probe_rtt, "no PROBE_RTT");
	CHECK(b.bw_after_app_limited > rate * 85 / 100, "bw %llu of %llu after the probe",
	      (unsigned long long)b.bw_after_app_limited, (unsigned long long)rate);
	// PROBE_RTT every 5 s with half the BDP in flight, not four packets.
	ccsim_run(2, 0, 12000000, 1000000, 0, 0, &b);
	uint64_t bdp = (uint64_t)CCSIM_RATE * CCSIM_RTT_US;
	CHECK(b.saw_probe_rtt, "probe_rtt");
	CHECK(b.min_cwnd_late >= bdp / 2 * 9 / 10, "probe_rtt window %llu, bdp %llu", (unsigned long long)b.min_cwnd_late,
	      (unsigned long long)bdp);
	CHECK(b.delivered_after > (uint64_t)CCSIM_RATE * 11000000 * 90 / 100, "delivered %llu",
	      (unsigned long long)b.delivered_after);
}

// --cc-table: BBR and bbr2 (and NewReno) side by side on the simulated paths the tests use, for
// comparing them by hand: goodput after the warm-up as a share of the path, the queue's drops
// after it and over the whole run, and how startup ended.
static void cc_table(int only_row, int only_v) {
	static const struct {
		const char *name;
		ccsim_path path;
		ccsim_link link;
		uint64_t loss_in, end, t_measure;
	} rows[] = {
	    {"440 Mbit/s, 30 ms, 5 ms queue", {30000, 5000, 1}, {55, 0, 0}, 0, 10000000, 2000000},
	    {"440 Mbit/s, 30 ms, 10 ms queue", {30000, 10000, 1}, {55, 0, 0}, 0, 10000000, 2000000},
	    {"40 Mbit/s, 30 ms, 5 ms queue", {30000, 5000, 1}, {5, 0, 0}, 0, 10000000, 2000000},
	    {"400 Mbit/s, 138 ms, 20 ms queue, 0.3% loss", {138000, 20000, 1}, {50, 0, 0}, 333, 20000000, 5000000},
	    {"40 Mbit/s, 138 ms, 20 ms queue, 0.3% loss", {138000, 20000, 1}, {5, 0, 0}, 333, 20000000, 5000000},
	    {"440 -> 220 Mbit/s at 5 s, 30 ms, 5 ms queue", {30000, 5000, 1}, {55, 27, 5000000}, 0, 12000000, 6000000},
	    {"40 Mbit/s, 40 ms, 40 ms queue, 1% loss", {40000, 40000, 1}, {5, 0, 0}, 100, 20000000, 5000000},
	};
	static const char *const names[] = {"newreno", "bbr", "bbr2"};
	for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
		if (only_row >= 0 && (size_t)only_row != i) continue;
		printf("%s\n", rows[i].name);
		g_ccsim = rows[i].path;
		g_cclink = rows[i].link;
		for (int v = 1; v <= 2; v++) {
			if (only_v >= 0 && only_v != v) continue;
			ccsim_result r;
			ccsim_run(v, rows[i].loss_in, rows[i].end, rows[i].t_measure, 0, 0, &r);
			uint64_t rate = g_cclink.rate2 ? g_cclink.rate2 : g_cclink.rate;
			double path = (double)rate * (double)(rows[i].end - rows[i].t_measure);
			printf("  %-7s goodput %5.1f%%  dropped %5.2f%% after, %5.2f%% in all (%llu)  startup over at %llu ms with "
			       "%llu dropped, inflight_hi %lld\n",
			       names[v], 100.0 * (double)r.delivered_after / path,
			       r.sent_after ? 100.0 * (double)r.lost_after / (double)r.sent_after : 0.0,
			       r.sent ? 100.0 * (double)r.lost / (double)r.sent : 0.0, (unsigned long long)r.lost,
			       (unsigned long long)(r.startup_end / 1000), (unsigned long long)r.lost_at_startup_end,
			       r.inflight_hi_at_startup_end == UINT64_MAX ? -1LL : (long long)r.inflight_hi_at_startup_end);
		}
	}
	g_ccsim = CCSIM_DEFAULT;
	g_cclink = CCLINK_DEFAULT;
}

static void test_smap(void) {
	hw_qc_smap m;
	hw_qc_smap_init(&m);
	enum {
		N = 500
	};
	hw_qc_stream *st = calloc(N, sizeof(*st));
	CHECK(st, "alloc");
	for (int i = 0; i < N; i++) {
		st[i].id = (uint64_t)i * 4 + (i & 3);
		CHECK_EQ(hw_qc_smap_put(&m, &st[i]), 0);
	}
	CHECK_EQ(m.count, N);
	for (int i = 0; i < N; i += 2) hw_qc_smap_remove(&m, st[i].id);
	for (int i = 0; i < N; i++) {
		hw_qc_stream *s = hw_qc_smap_get(&m, st[i].id);
		CHECK(i % 2 ? s == &st[i] : s == NULL, "after removal %d", i);
	}
	hw_qc_smap_clear(&m);
	free(st);
}

// ---- The simulated network ----------------------------------------------------------------------

#define SIM_MAX_STREAMS 4096 // ids below this are tracked by the test application

typedef struct sim sim;

typedef struct {
	uint64_t target, written;
	int fin_written;
	uint64_t received;
	int fin_received, reset, stopped, opened;
	uint64_t fin_at; // simulated ms when the FIN arrived
} app_stream;

typedef struct {
	sim *s;
	int server;
	hw_quic_conn *q;
	int established, closed;
	uint64_t close_err;
	int close_app;
	char reason[128];
	int consume;    // call hw_quic_stream_consumed for what arrives
	uint64_t reply; // server: answer every new stream of the peer with this many bytes and FIN
	app_stream st[SIM_MAX_STREAMS];
	uint64_t dgram_rx;
	uint8_t *dgram_seen; // by datagram number
	int cids_issued, cids_retired;
	uint64_t bytes_rx;
} app;

typedef struct {
	uint64_t at, seq;
	int to_server;
	struct sockaddr_in from;
	size_t len;
	uint8_t *data;
} sim_pkt;

struct sim {
	uint64_t now;
	uint64_t rng;
	uint32_t loss_ppm, reorder_ppm, dup_ppm;
	uint64_t delay_ms, jitter_ms;
	uint64_t bw; // bytes per ms per direction, 0 = unlimited
	uint64_t link_free_us[2];
	sim_pkt *heap;
	size_t hn, hcap;
	uint64_t seq;
	app c, sv;
	hw_quic_config ccfg, scfg;
	struct sockaddr_in caddr, saddr;
	int retry, gone, hrr;
	uint8_t token_key[32], reset_key[32];
	uint64_t c2s, s2c, dropped;
	int block_c2s, block_s2c;
	int check_amp; // assert the server's 3x limit at every send
	size_t mtu;    // datagrams longer than this vanish without a word (0 = none): ICMP that never comes back
	uint64_t mtu_dropped;
	// Per side (0 client, 1 server): when its handshake was first seen confirmed, and when it sent
	// its first datagram that goes alone (a PMTU probe). 0: not yet.
	uint64_t confirmed_ms[2], first_alone_ms[2];
	uint64_t steps;
};

static uint64_t sim_rand(sim *s) {
	s->rng ^= s->rng >> 12;
	s->rng ^= s->rng << 25;
	s->rng ^= s->rng >> 27;
	return s->rng * 0x2545f4914f6cdd1dull;
}

static int sim_chance(sim *s, uint32_t ppm) {
	return ppm && (sim_rand(s) % 1000000) < ppm;
}

static int pkt_before(const sim_pkt *a, const sim_pkt *b) {
	return a->at < b->at || (a->at == b->at && a->seq < b->seq);
}

static void heap_push(sim *s, sim_pkt p) {
	if (s->hn == s->hcap) {
		size_t cap = s->hcap ? s->hcap * 2 : 256;
		sim_pkt *h = realloc(s->heap, cap * sizeof(*h));
		CHECK(h, "heap");
		s->heap = h;
		s->hcap = cap;
	}
	size_t i = s->hn++;
	s->heap[i] = p;
	while (i && pkt_before(&s->heap[i], &s->heap[(i - 1) / 2])) {
		sim_pkt t = s->heap[i];
		s->heap[i] = s->heap[(i - 1) / 2];
		s->heap[(i - 1) / 2] = t;
		i = (i - 1) / 2;
	}
}

static sim_pkt heap_pop(sim *s) {
	sim_pkt top = s->heap[0];
	s->heap[0] = s->heap[--s->hn];
	size_t i = 0;
	for (;;) {
		size_t l = 2 * i + 1, r = l + 1, m = i;
		if (l < s->hn && pkt_before(&s->heap[l], &s->heap[m])) m = l;
		if (r < s->hn && pkt_before(&s->heap[r], &s->heap[m])) m = r;
		if (m == i) break;
		sim_pkt t = s->heap[i];
		s->heap[i] = s->heap[m];
		s->heap[m] = t;
		i = m;
	}
	return top;
}

// A datagram onto the path: bandwidth, then loss, delay, reordering and duplication.
static void sim_send(sim *s, int to_server, const uint8_t *data, size_t len) {
	if (to_server) {
		s->c2s += len;
	} else {
		s->s2c += len;
	}
	if ((to_server && s->block_c2s) || (!to_server && s->block_s2c)) return;
	if (s->mtu && len > s->mtu) {
		s->mtu_dropped++;
		return;
	}
	int dir = to_server ? 0 : 1;
	uint64_t depart = s->now * 1000;
	if (s->bw) {
		if (s->link_free_us[dir] > depart) depart = s->link_free_us[dir];
		s->link_free_us[dir] = depart + len * 1000 / s->bw;
		depart = s->link_free_us[dir];
	}
	if (sim_chance(s, s->loss_ppm)) {
		s->dropped++;
		return;
	}
	int copies = sim_chance(s, s->dup_ppm) ? 2 : 1;
	for (int i = 0; i < copies; i++) {
		sim_pkt p;
		memset(&p, 0, sizeof(p));
		p.at = (depart + 999) / 1000 + s->delay_ms;
		if (s->jitter_ms && sim_chance(s, s->reorder_ppm)) p.at += 1 + sim_rand(s) % s->jitter_ms;
		p.seq = s->seq++;
		p.to_server = to_server;
		p.from = to_server ? s->caddr : s->saddr;
		p.len = len;
		p.data = malloc(len);
		CHECK(p.data, "alloc");
		memcpy(p.data, data, len);
		heap_push(s, p);
	}
}

static hw_quic_callbacks g_ccb, g_scb;

// The listener's part: a server connection for a client's first Initial, Retry when asked, a
// stateless reset once the server is gone.
static void sim_to_server(sim *s, sim_pkt *p) {
	const struct sockaddr *from = (const struct sockaddr *)&p->from;
	if (s->gone) {
		hw_quic_header h;
		uint8_t out[128];
		if (hw_quic_parse_header(p->data, p->len, &h) == 0 && !h.long_header && h.dcid_len == HW_QUIC_CID_LEN) {
			size_t n = hw_quic_stateless_reset(h.dcid, s->reset_key, p->len, out, sizeof(out));
			if (n) sim_send(s, 0, out, n);
		}
		return;
	}
	if (!s->sv.q) {
		hw_quic_header h;
		if (hw_quic_parse_header(p->data, p->len, &h) < 0 || !h.long_header || h.type != 0) return;
		int validated = 0;
		uint8_t odcid[20], odcid_len = 0;
		if (s->retry) {
			if (!h.token_len) {
				uint8_t scid[HW_QUIC_CID_LEN], out[512];
				for (size_t i = 0; i < sizeof(scid); i++) scid[i] = (uint8_t)sim_rand(s);
				size_t n = hw_quic_retry(&h, from, s->token_key, s->now, scid, out, sizeof(out));
				CHECK(n > 0, "retry made");
				sim_send(s, 0, out, n);
				return;
			}
			if (!hw_quic_token_valid(h.token, h.token_len, from, s->token_key, s->now, 30000, odcid, &odcid_len)) {
				return;
			}
			validated = 1;
		}
		s->sv.q = hw_quic_accept(&s->scfg, &g_scb, &h, from, sizeof(p->from), validated, odcid, odcid_len, s->now);
		CHECK(s->sv.q, "accept");
	}
	hw_quic_input(s->sv.q, p->data, p->len, from, sizeof(p->from), s->now);
}

static void sim_flush(sim *s) {
	uint8_t out[HW_QUIC_MAX_DGRAM];
	struct sockaddr_storage to;
	socklen_t to_len;
	for (int side = 0; side < 2; side++) {
		app *a = side ? &s->sv : &s->c;
		if (!a->q || (side && s->gone)) continue;
		size_t n;
		while ((n = hw_quic_output(a->q, out, sizeof(out), &to, &to_len, s->now)) > 0) {
			CHECK(n <= sizeof(out), "datagram size");
			// A probe, and only a probe, is larger than the datagram size in use, and only it goes alone.
			int alone = hw_quic_output_alone(a->q);
			CHECK(alone == (n > a->q->mds), "side %d: %zu bytes (mds %llu) alone %d", side, n,
			      (unsigned long long)a->q->mds, alone);
			if (a->q->handshake_confirmed && !s->confirmed_ms[side]) s->confirmed_ms[side] = s->now ? s->now : 1;
			if (alone && !s->first_alone_ms[side]) s->first_alone_ms[side] = s->now;
			if (side) {
				CHECK(to.ss_family == AF_INET, "server destination");
				sim_send(s, 0, out, n);
				if (s->check_amp && !a->q->path_validated) {
					CHECK(a->q->amp_tx <= 3 * a->q->amp_rx, "amplification %llu > 3 * %llu",
					      (unsigned long long)a->q->amp_tx, (unsigned long long)a->q->amp_rx);
				}
			} else {
				sim_send(s, 1, out, n);
			}
		}
	}
}

static uint64_t sim_next(sim *s) {
	uint64_t t = UINT64_MAX;
	if (s->hn) t = s->heap[0].at;
	if (s->c.q) t = HW_MIN(t, hw_quic_timeout(s->c.q));
	if (s->sv.q && !s->gone) t = HW_MIN(t, hw_quic_timeout(s->sv.q));
	return t;
}

// One step: deliver what is due and run due timers. 0 when nothing will ever happen again.
static int sim_step(sim *s) {
	sim_flush(s);
	uint64_t t = sim_next(s);
	if (t == UINT64_MAX) return 0;
	if (t > s->now) s->now = t;
	s->steps++;
	while (s->hn && s->heap[0].at <= s->now) {
		sim_pkt p = heap_pop(s);
		if (p.to_server) {
			sim_to_server(s, &p);
		} else if (s->c.q) {
			hw_quic_input(s->c.q, p.data, p.len, (const struct sockaddr *)&p.from, sizeof(p.from), s->now);
		}
		free(p.data);
	}
	if (s->c.q && hw_quic_timeout(s->c.q) <= s->now) hw_quic_on_timeout(s->c.q, s->now);
	if (s->sv.q && !s->gone && hw_quic_timeout(s->sv.q) <= s->now) hw_quic_on_timeout(s->sv.q, s->now);
	sim_flush(s);
	return 1;
}

typedef int (*sim_cond)(sim *s, void *ud);

static int sim_run(sim *s, sim_cond done, void *ud, uint64_t max_ms) {
	uint64_t end = s->now + max_ms;
	uint64_t last_now = s->now, same = 0;
	while (!done(s, ud)) {
		if (s->now > end) return 0;
		if (!sim_step(s)) return done(s, ud);
		if (s->now == last_now) {
			CHECK(++same < 2000000, "the simulation spins at %llu ms", (unsigned long long)s->now);
		} else {
			last_now = s->now;
			same = 0;
		}
	}
	return 1;
}

static void sim_advance(sim *s, uint64_t ms) {
	uint64_t end = s->now + ms;
	while (s->now < end) {
		sim_flush(s);
		uint64_t t = sim_next(s);
		if (t > end) {
			s->now = end;
			break;
		}
		sim_step(s);
	}
}

// ---- The test application ----------------------------------------------------------------------

static uint8_t g_pattern[4096];
static int g_bench; // --bench: no pattern written or checked, so the figure is the stack's alone

// Byte o of what side `server` sends on stream id.
static uint8_t pattern_at(int server, uint64_t id, uint64_t o) {
	return (uint8_t)(g_pattern[(o + id * 977 + (uint64_t)server * 1913) & 4095] ^ (uint8_t)(o >> 12));
}

static app_stream *app_st(app *a, uint64_t id) {
	CHECK(id < SIM_MAX_STREAMS, "stream id %llu", (unsigned long long)id);
	return &a->st[id];
}

static void app_pump(app *a, uint64_t id) {
	app_stream *st = app_st(a, id);
	static uint8_t buf[16384];
	while (!st->fin_written) {
		uint64_t left = st->target - st->written;
		size_t n = (size_t)HW_MIN(left, (uint64_t)sizeof(buf));
		if (!g_bench) {
			for (size_t i = 0; i < n; i++) buf[i] = pattern_at(a->server, id, st->written + i);
		}
		int fin = st->written + n == st->target;
		int64_t w = hw_quic_stream_write(a->q, id, buf, n, fin);
		CHECK(w >= 0, "write on %llu", (unsigned long long)id);
		st->written += (uint64_t)w;
		if ((size_t)w == n && fin) st->fin_written = 1;
		if ((size_t)w < n || !n) break;
	}
}

static void app_send(app *a, uint64_t id, uint64_t bytes) {
	app_stream *st = app_st(a, id);
	st->target = bytes;
	st->opened = 1;
	app_pump(a, id);
}

static void cb_established(void *ud) {
	app *a = ud;
	a->established = 1;
}

static void cb_stream_data(void *ud, uint64_t id, const uint8_t *data, size_t len, int fin) {
	app *a = ud;
	app_stream *st = app_st(a, id);
	CHECK(!st->fin_received, "data after FIN on %llu", (unsigned long long)id);
	for (size_t i = 0; i < len && !g_bench; i++) {
		if (data[i] != pattern_at(!a->server, id, st->received + i)) {
			CHECK(0, "stream %llu byte %llu differs", (unsigned long long)id, (unsigned long long)(st->received + i));
		}
	}
	st->received += len;
	a->bytes_rx += len;
	if (fin) {
		st->fin_received = 1;
		st->fin_at = a->s->now;
	}
	if (a->consume && len) hw_quic_stream_consumed(a->q, id, len);
	if (a->reply != UINT64_MAX && !st->opened && (id & 2) == 0) app_send(a, id, a->reply);
}

static void cb_stream_reset(void *ud, uint64_t id, uint64_t err) {
	app *a = ud;
	(void)err;
	app_st(a, id)->reset = 1;
}

static void cb_stream_stop(void *ud, uint64_t id, uint64_t err) {
	app *a = ud;
	(void)err;
	app_st(a, id)->stopped = 1;
}

static void cb_writable(void *ud, uint64_t id) {
	app *a = ud;
	app_pump(a, id);
}

static void cb_datagram(void *ud, const uint8_t *data, size_t len) {
	app *a = ud;
	CHECK(len >= 4, "datagram length");
	uint32_t n;
	memcpy(&n, data, 4);
	CHECK(n < 100000 && a->dgram_seen, "datagram number");
	CHECK(!a->dgram_seen[n], "datagram %u twice", n);
	a->dgram_seen[n] = 1;
	a->dgram_rx++;
}

static void cb_cid(void *ud, const uint8_t cid[HW_QUIC_CID_LEN], int retire) {
	app *a = ud;
	if (a->server) CHECK_EQ(cid[0], 0x17); // the steering byte
	if (retire) {
		a->cids_retired++;
	} else {
		a->cids_issued++;
	}
}

static void cb_closed(void *ud, uint64_t err, int is_app, const char *reason) {
	app *a = ud;
	CHECK(!a->closed, "closed twice");
	a->closed = 1;
	a->close_err = err;
	a->close_app = is_app;
	snprintf(a->reason, sizeof(a->reason), "%s", reason ? reason : "");
}

static hw_der g_cert;
static uint8_t g_key[HW_P256_PRIV_LEN];
static uint8_t g_pin[HW_SHA256_LEN];
static hw_der g_chain[HW_CERT_CHAIN_MAX];
static const char *const ALPN[] = {"h3"};

static void make_cert(void) {
	uint8_t pub[HW_P256_PUB_LEN];
	CHECK_EQ(hw_p256_keygen(g_key, pub), 0);
	int64_t now = (int64_t)time(NULL);
	CHECK_EQ(hw_cert_selfsigned(g_key, pub, "localhost", now - 3600, now + 13 * 86400, &g_cert), 0);
	hw_sha256(g_cert.der, g_cert.len, g_pin);
	for (size_t i = 0; i < HW_CERT_CHAIN_MAX; i++) g_chain[i] = g_cert;
}

static int g_sim_cc = HW_QUIC_CC_BBR; // the congestion control sim_new's connections get

static void sim_config(hw_quic_config *c, int server) {
	memset(c, 0, sizeof(*c));
	c->congestion = g_sim_cc;
	c->is_server = server;
	c->tls.is_server = server;
	c->tls.alpn = ALPN;
	c->tls.alpn_count = 1;
	if (server) {
		c->tls.chain = g_chain;
		c->tls.chain_len = 1;
		c->tls.key = g_key;
	} else {
		c->tls.server_name = "localhost";
		c->tls.pin_sha256 = g_pin;
	}
	c->max_idle_ms = 30000;
	c->initial_max_data = 4u << 20;
	c->initial_max_stream_data = 1u << 20;
	c->initial_max_streams_bidi = 100;
	c->initial_max_streams_uni = 100;
	c->max_datagram_frame_size = 1400;
	c->stream_send_max = 1u << 20;
	c->conn_send_max = 16u << 20;
	c->datagram_queue_max = 64;
}

static sim *sim_new(uint64_t seed) {
	sim *s = calloc(1, sizeof(*s));
	CHECK(s, "alloc");
	s->rng = seed * 0x9e3779b97f4a7c15ull + 1;
	s->now = 1000;
	s->delay_ms = 5;
	s->c.s = s->sv.s = s;
	s->sv.server = 1;
	s->c.consume = s->sv.consume = 1;
	s->c.reply = UINT64_MAX;
	s->sv.reply = UINT64_MAX;
	s->caddr.sin_family = AF_INET;
	s->caddr.sin_port = htons(40000);
	s->caddr.sin_addr.s_addr = htonl(0x0a000001);
	s->saddr.sin_family = AF_INET;
	s->saddr.sin_port = htons(443);
	s->saddr.sin_addr.s_addr = htonl(0x0a000002);
	for (size_t i = 0; i < sizeof(s->token_key); i++) {
		s->token_key[i] = (uint8_t)sim_rand(s);
		s->reset_key[i] = (uint8_t)sim_rand(s);
	}
	sim_config(&s->ccfg, 0);
	sim_config(&s->scfg, 1);
	s->scfg.cid_prefix = 0x17;
	s->scfg.reset_key = s->reset_key;
	return s;
}

static void sim_start(sim *s) {
	g_ccb = (hw_quic_callbacks){.ud = &s->c,
	                            .established = cb_established,
	                            .stream_data = cb_stream_data,
	                            .stream_reset = cb_stream_reset,
	                            .stream_stop = cb_stream_stop,
	                            .stream_writable = cb_writable,
	                            .datagram = cb_datagram,
	                            .cid = cb_cid,
	                            .closed = cb_closed};
	g_scb = g_ccb;
	g_scb.ud = &s->sv;
	// The server's connection is made by sim_to_server with these callbacks.
	s->scfg.tls.chain = g_chain;
	s->c.q = hw_qc_connect_unstarted(&s->ccfg, &g_ccb, (const struct sockaddr *)&s->saddr, sizeof(s->saddr), s->now);
	CHECK(s->c.q, "connect");
	if (s->hrr) hw_tls_test_omit_key_share(s->c.q->tls);
	CHECK_EQ(hw_qc_start(s->c.q), 0);
}

static void sim_free(sim *s) {
	hw_quic_free(s->c.q);
	hw_quic_free(s->sv.q);
	while (s->hn) free(heap_pop(s).data);
	free(s->heap);
	free(s->c.dgram_seen);
	free(s->sv.dgram_seen);
	free(s);
}

static int cond_established(sim *s, void *ud) {
	(void)ud;
	return s->c.established && s->sv.established;
}

static int cond_closed_both(sim *s, void *ud) {
	(void)ud;
	return s->c.closed && s->sv.closed;
}

static int cond_closed_one_client(sim *s, void *ud) {
	(void)ud;
	return s->c.closed;
}

static int cond_drained_both(sim *s, void *ud) {
	(void)ud;
	return hw_quic_is_drained(s->c.q) && s->sv.q && hw_quic_is_drained(s->sv.q);
}

typedef struct {
	uint64_t id, bytes_c2s, bytes_s2c;
} xfer;

static int cond_xfer(sim *s, void *ud) {
	const xfer *x = ud;
	const app_stream *srx = &s->sv.st[x->id], *crx = &s->c.st[x->id];
	return srx->fin_received && srx->received == x->bytes_c2s && crx->fin_received && crx->received == x->bytes_s2c;
}

// The handshake, with the server's connection hooked to its callbacks once it exists.
static void sim_handshake(sim *s) {
	sim_start(s);
	CHECK(sim_run(s, cond_established, NULL, 20000), "handshake");
}

// ---- Connection cases ----------------------------------------------------------------------------

static void test_handshake(void) {
	sim *s = sim_new(1);
	sim_handshake(s);
	CHECK(!strcmp(hw_quic_alpn(s->c.q), "h3") && !strcmp(hw_quic_alpn(s->sv.q), "h3"), "alpn");
	CHECK(hw_quic_server_name(s->sv.q) && !strcmp(hw_quic_server_name(s->sv.q), "localhost"), "sni");
	socklen_t pl;
	const struct sockaddr *peer = hw_quic_peer(s->sv.q, &pl);
	CHECK(pl == sizeof(struct sockaddr_in) && memcmp(peer, &s->caddr, sizeof(s->caddr)) == 0, "peer");
	CHECK(s->sv.q->handshake_confirmed && s->c.q->handshake_confirmed, "confirmed");
	CHECK(s->sv.q->sp[HW_QC_SP_INITIAL].discarded && s->sv.q->sp[HW_QC_SP_HANDSHAKE].discarded, "server keys");
	CHECK(s->c.q->sp[HW_QC_SP_INITIAL].discarded && s->c.q->sp[HW_QC_SP_HANDSHAKE].discarded, "client keys");
	// One RTT for the handshake plus the HANDSHAKE_DONE: a few delays, no timers.
	CHECK(s->now <= 1000 + 4 * s->delay_ms + 2, "handshake took %llu ms", (unsigned long long)(s->now - 1000));
	sim_advance(s, 200);
	// Connection IDs: the first plus three more each way, the server's with its prefix.
	CHECK_EQ(s->sv.cids_issued, 4);
	CHECK_EQ(s->c.cids_issued, 4);
	int peers = 0;
	for (size_t i = 0; i < HW_QC_PEER_CIDS; i++) peers += s->c.q->peers[i].used;
	CHECK_EQ(peers, 4);
	CHECK(hw_quic_datagram_max(s->c.q) > 1000, "datagram max %zu", hw_quic_datagram_max(s->c.q));
	hw_quic_stats st;
	hw_quic_get_stats(s->c.q, &st);
	CHECK(st.srtt_us >= 2 * s->delay_ms * 1000 && st.srtt_us < 4 * s->delay_ms * 1000, "srtt %llu",
	      (unsigned long long)st.srtt_us);
	sim_free(s);
}

static double cpu_seconds(void) {
	struct timespec ts;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void bulk(sim *s, uint64_t c2s, uint64_t s2c, uint64_t max_ms) {
	s->sv.reply = s2c;
	int64_t id = hw_quic_stream_open(s->c.q, 1);
	CHECK(id >= 0, "open");
	app_send(&s->c, (uint64_t)id, c2s);
	xfer x = {(uint64_t)id, c2s, s2c};
	CHECK(sim_run(s, cond_xfer, &x, max_ms), "transfer: c2s %llu/%llu s2c %llu/%llu at %llu ms",
	      (unsigned long long)s->sv.st[id].received, (unsigned long long)c2s, (unsigned long long)s->c.st[id].received,
	      (unsigned long long)s2c, (unsigned long long)s->now);
}

// The microsecond calls: a round trip of 250 us is measured as 250 us, and BBR keeps it for its
// rate samples while its model's min RTT stays at a tick (quic_recovery.c). On the millisecond
// calls the same exchange is 0 or 1 ms, depending on where the ticks fall.
static void test_clock_us(void) {
	sim *s = sim_new(29);
	sim_handshake(s);
	sim_advance(s, 200);
	CHECK_EQ(s->hn, 0);
	int64_t id = hw_quic_stream_open(s->c.q, 1);
	CHECK(id >= 0, "open");
	app_send(&s->c, (uint64_t)id, 3000); // three datagrams: the server acknowledges at once
	uint64_t t0 = (s->now + 1) * 1000 + 300;
	uint8_t d[8][HW_QUIC_MAX_DGRAM];
	size_t len[8], n = 0;
	struct sockaddr_storage to;
	socklen_t to_len;
	while (n < 8 && (len[n] = hw_quic_output_us(s->c.q, d[n], sizeof(d[n]), &to, &to_len, t0)) > 0) n++;
	CHECK(n >= 2, "client sent %zu datagrams", n);
	for (size_t i = 0; i < n; i++) {
		hw_quic_input_us(s->sv.q, d[i], len[i], (const struct sockaddr *)&s->caddr, sizeof(s->caddr), t0 + 100);
	}
	size_t acks = 0;
	while (n < 8 && (len[n] = hw_quic_output_us(s->sv.q, d[n], sizeof(d[n]), &to, &to_len, t0 + 100)) > 0) {
		hw_quic_input_us(s->c.q, d[n], len[n], (const struct sockaddr *)&s->saddr, sizeof(s->saddr), t0 + 250);
		acks++;
	}
	CHECK(acks > 0, "the server answered");
	CHECK_EQ(s->c.q->rtt.latest, 250);
	CHECK_EQ(s->c.q->cc.b.min_rtt_raw, 250);
	CHECK_EQ(s->c.q->cc.b.min_rtt, HW_QC_GRANULARITY_US);
	hw_quic_on_timeout_us(s->c.q, t0 + 250); // nothing is due: a no-op on the same clock
	CHECK(hw_quic_timeout(s->c.q) > (t0 + 250) / 1000, "a timer is due at once");
	sim_free(s);
}

// A sender that waits for room in its send buffer (or for the peer's credit) is not app-limited:
// the buffer is a limit of the path's kind, as a full socket buffer is to TCP. Marked
// app-limited, every sample of a bulk download behind a full buffer was dropped, and BBR never
// left startup: it paced at 2.89 times the path, and a third of what it sent was lost (the edge,
// 2026-11-19). A buffer of 4 KB under a first window of ten datagrams: the window and the pacer
// have room, the stream has none.
static void test_bbr_buffer_limited(void) {
	sim *s = sim_new(23);
	s->ccfg.stream_send_max = s->ccfg.conn_send_max = 4096;
	sim_handshake(s);
	int64_t id = hw_quic_stream_open(s->c.q, 1);
	CHECK(id >= 0, "open");
	app_send(&s->c, (uint64_t)id, 1u << 20);
	CHECK(s->c.q->blk_head != NULL, "the writer waits for room");
	uint64_t mark = s->c.q->cc.app_limited; // the idle handshake's, if any
	uint8_t out[HW_QUIC_MAX_DGRAM];
	struct sockaddr_storage to;
	socklen_t to_len;
	size_t sent = 0, n;
	while ((n = hw_quic_output(s->c.q, out, sizeof(out), &to, &to_len, s->now)) > 0) sent += n;
	CHECK(sent > 0 && hw_qc_cc_can_send(&s->c.q->cc), "the window has room after %zu bytes", sent);
	CHECK_EQ(s->c.q->cc.app_limited, mark); // no new mark: the buffer, not the application
	sim_free(s);
}

static void test_bulk_64m(void) {
	sim *s = sim_new(2);
	sim_handshake(s);
	double t0 = cpu_seconds();
	bulk(s, 64u << 20, 64u << 20, 600000);
	double t = cpu_seconds() - t0;
	sim_advance(s, 100); // the last ACKs
	hw_quic_stats cs, ss;
	hw_quic_get_stats(s->c.q, &cs);
	hw_quic_get_stats(s->sv.q, &ss);
	CHECK_EQ(cs.packets_lost, 0);
	CHECK_EQ(ss.packets_lost, 0);
	CHECK_EQ(hw_quic_queued(s->c.q), 0);
	printf("  64 MiB each way: %.0f MB/s of payload per CPU second (both endpoints, %.2f s CPU, %llu ms simulated)\n",
	       2 * 64.0 * 1048576 / 1e6 / t, t, (unsigned long long)(s->now - 1000));
	sim_free(s);
}

// PMTU discovery: both ends start at the floor and find what the path carries, whatever it
// drops in silence, without a loss counted against the window.
static void test_pmtu(void) {
	static const struct {
		size_t mtu;
		uint64_t lo, hi;
	} paths[] = {
	    {0, HW_QUIC_MAX_DGRAM, HW_QUIC_MAX_DGRAM},
	    {1500, HW_QUIC_MAX_DGRAM, HW_QUIC_MAX_DGRAM},
	    {1360, 1360 - HW_QC_PMTU_STEP, 1360},
	    {1280, 1280 - HW_QC_PMTU_STEP, 1280},
	    {HW_QUIC_MIN_DGRAM, HW_QUIC_MIN_DGRAM, HW_QUIC_MIN_DGRAM},
	};
	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		sim *s = sim_new(60 + i);
		s->mtu = paths[i].mtu;
		s->delay_ms = 20;
		sim_handshake(s);
		hw_quic_stats cs, ss;
		hw_quic_get_stats(s->c.q, &cs);
		CHECK(cs.mds <= HW_QUIC_MAX_DGRAM, "mds bounded");
		bulk(s, 2u << 20, 2u << 20, 120000);
		// Neither side probes before a round trip (40 ms) has passed since its handshake was
		// confirmed: what follows the handshake goes first. On the edge a probe sent at once
		// shared a write with HANDSHAKE_DONE and SETTINGS, and a hop too narrow for it dropped both.
		for (int side = 0; side < 2 && paths[i].mtu != HW_QUIC_MIN_DGRAM; side++) {
			CHECK(s->first_alone_ms[side] && s->confirmed_ms[side] &&
			          s->first_alone_ms[side] >= s->confirmed_ms[side] + 40,
			      "path %zu side %d: confirmed at %llu, first probe at %llu", paths[i].mtu, side,
			      (unsigned long long)s->confirmed_ms[side], (unsigned long long)s->first_alone_ms[side]);
		}
		sim_advance(s, 2000);
		hw_quic_get_stats(s->c.q, &cs);
		hw_quic_get_stats(s->sv.q, &ss);
		CHECK(cs.mds >= paths[i].lo && cs.mds <= paths[i].hi, "path %zu: client mds %llu", paths[i].mtu,
		      (unsigned long long)cs.mds);
		CHECK(ss.mds >= paths[i].lo && ss.mds <= paths[i].hi, "path %zu: server mds %llu", paths[i].mtu,
		      (unsigned long long)ss.mds);
		CHECK_EQ(cs.packets_lost, 0);
		CHECK_EQ(ss.packets_lost, 0);
		if (!paths[i].mtu || paths[i].mtu >= HW_QUIC_MAX_DGRAM) CHECK_EQ(s->mtu_dropped, 0);
		// A probe at most every round trip, and the search is over: a few of them, not a stream.
		CHECK(s->mtu_dropped <= 2 * HW_QC_PMTU_TRIES * 8, "path %zu: %llu dropped", paths[i].mtu,
		      (unsigned long long)s->mtu_dropped);
		uint64_t dropped = s->mtu_dropped;
		sim_advance(s, 10000);
		CHECK_EQ(s->mtu_dropped, dropped);
		sim_free(s);
	}
	// A path that loses one datagram in twenty still finds its size: a lost probe is retried.
	sim *s = sim_new(70);
	s->mtu = 1400;
	s->loss_ppm = 50000;
	s->delay_ms = 10;
	sim_handshake(s);
	bulk(s, 1u << 20, 1u << 20, 120000);
	sim_advance(s, 3000);
	hw_quic_stats cs;
	hw_quic_get_stats(s->c.q, &cs);
	CHECK(cs.mds > HW_QUIC_MIN_DGRAM && cs.mds <= 1400, "lossy path: mds %llu", (unsigned long long)cs.mds);
	sim_free(s);
}

// A HelloRetryRequest: two ClientHellos in the Initial space, under loss.
static void test_handshake_hrr(void) {
	for (uint64_t seed = 30; seed < 36; seed++) {
		sim *s = sim_new(seed);
		s->hrr = 1;
		s->loss_ppm = seed == 30 ? 0 : 150000;
		s->check_amp = 1;
		sim_handshake(s);
		bulk(s, 64 * 1024, 64 * 1024, 30000);
		sim_free(s);
	}
	// And a plain handshake under loss, Retry included.
	for (uint64_t seed = 40; seed < 46; seed++) {
		sim *s = sim_new(seed);
		s->loss_ppm = 200000;
		s->retry = seed & 1;
		s->check_amp = 1;
		sim_handshake(s);
		sim_free(s);
	}
}

typedef struct {
	uint64_t first, n, bytes;
} many;

static int cond_many(sim *s, void *ud) {
	const many *m = ud;
	for (uint64_t i = 0; i < m->n; i++) {
		uint64_t id = (m->first + i) * 4;
		if (!s->sv.st[id].fin_received || s->sv.st[id].received != m->bytes) return 0;
		if (!s->c.st[id].fin_received || s->c.st[id].received != m->bytes) return 0;
	}
	return 1;
}

static void test_many_streams(void) {
	sim *s = sim_new(3);
	s->loss_ppm = 10000;
	sim_handshake(s);
	s->sv.reply = 64 * 1024;
	for (int round = 0; round < 3; round++) {
		for (int i = 0; i < 100; i++) {
			int64_t id = hw_quic_stream_open(s->c.q, 1);
			// The last streams of the round before may still be waiting for an ACK of their
			// FIN, and the MAX_STREAMS their freeing sends for its round trip.
			for (int wait = 0; id < 0 && wait < 1000; wait++) {
				sim_advance(s, 10);
				id = hw_quic_stream_open(s->c.q, 1);
			}
			CHECK(id == (int64_t)(round * 100 + i) * 4, "open %d.%d: %lld", round, i, (long long)id);
			app_send(&s->c, (uint64_t)id, 64 * 1024);
		}
		// The 101st waits for the server to grant more.
		if (round == 0) {
			int64_t extra = hw_quic_stream_open(s->c.q, 1);
			CHECK_EQ(extra, -1);
		}
		many m = {(uint64_t)round * 100, 100, 64 * 1024};
		CHECK(sim_run(s, cond_many, &m, 120000), "round %d", round);
		sim_advance(s, 100); // the last ACKs, the streams freed, MAX_STREAMS
	}
	// Every stream finished both ways was freed on both sides.
	CHECK(s->c.q->streams.count == 0 && s->sv.q->streams.count == 0, "streams left: %zu %zu", s->c.q->streams.count,
	      s->sv.q->streams.count);
	CHECK(s->sv.q->rx_max_streams[0] >= 300, "MAX_STREAMS raised");
	sim_free(s);
}

static void test_datagrams(void) {
	sim *s = sim_new(4);
	s->loss_ppm = 50000;
	sim_handshake(s);
	enum {
		N = 400
	};
	s->c.dgram_seen = calloc(N, 1);
	s->sv.dgram_seen = calloc(N, 1);
	size_t max = hw_quic_datagram_max(s->c.q);
	CHECK(max >= 1000 && max == hw_quic_datagram_max(s->sv.q), "datagram max");
	uint8_t big[2048] = {0};
	CHECK_EQ(hw_quic_datagram_send(s->c.q, big, max + 1), -1);
	for (uint32_t i = 0; i < N; i++) {
		uint8_t d[600];
		memset(d, (int)i, sizeof(d));
		memcpy(d, &i, 4);
		size_t len = 4 + i % 500;
		while (hw_quic_datagram_send(s->c.q, d, len) < 0) sim_advance(s, 1);
		while (hw_quic_datagram_send(s->sv.q, d, len) < 0) sim_advance(s, 1);
	}
	sim_advance(s, 2000);
	CHECK_EQ(s->c.q->dgram_frames_sent, N);
	CHECK_EQ(s->sv.q->dgram_frames_sent, N);
	// Lost ones stay lost; every one arrives at most once (cb_datagram checks).
	CHECK(s->sv.dgram_rx < N && s->sv.dgram_rx > N * 85 / 100, "server got %llu", (unsigned long long)s->sv.dgram_rx);
	CHECK(s->c.dgram_rx < N && s->c.dgram_rx > N * 85 / 100, "client got %llu", (unsigned long long)s->c.dgram_rx);
	// A full queue drops the newest.
	int refused = 0;
	for (int i = 0; i < 100; i++) refused += hw_quic_datagram_send(s->c.q, big, 10) < 0;
	CHECK_EQ(refused, 100 - 64);
	sim_free(s);
}

// One bulk transfer each way on a 2 MB/s path with 20 ms of RTT, reordering and duplicates.
// Returns the simulated ms it took.
static uint64_t lossy(uint64_t seed, uint32_t loss_ppm, uint64_t bytes, hw_quic_stats *cs, hw_quic_stats *ss,
                      uint64_t *spurious_out) {
	sim *s = sim_new(seed);
	s->loss_ppm = loss_ppm;
	s->reorder_ppm = 100000;
	s->jitter_ms = 8;
	s->dup_ppm = 10000;
	s->delay_ms = 10;
	s->bw = 2000; // 2 MB/s
	sim_handshake(s);
	uint64_t t0 = s->now;
	bulk(s, bytes, bytes, 1200000);
	uint64_t took = s->now - t0;
	hw_quic_get_stats(s->c.q, cs);
	hw_quic_get_stats(s->sv.q, ss);
	CHECK(loss_ppm == 0 || cs->packets_lost > 0, "losses seen");
	uint64_t spurious = s->c.q->spurious_lost + s->sv.q->spurious_lost;
	if (spurious_out) *spurious_out = spurious;
	printf("  %u%% loss: %llu MiB each way in %llu ms simulated, %llu + %llu packets lost, %llu of them spuriously\n",
	       loss_ppm / 10000, (unsigned long long)(bytes >> 20), (unsigned long long)took,
	       (unsigned long long)cs->packets_lost, (unsigned long long)ss->packets_lost, (unsigned long long)spurious);
	sim_free(s);
	return took;
}

static void test_loss(void) {
	hw_quic_stats a, b, c, d;
	// Reordering alone: the thresholds adapt and the spurious losses are undone, so the link
	// stays nearly full (4 MiB at 2 MB/s is 2.1 s; with the fixed threshold of 3 it took 13 s).
	// BBR takes 2.5 s where NewReno took 2.2: both directions are busy and the path's queues have
	// no end, so each side's ACKs wait behind the other's data, and BBR's window of two BDPs
	// runs out where NewReno's fills the queue. One way, both take 2.2 s.
	uint64_t spurious;
	uint64_t took = lossy(9, 0, 4u << 20, &a, &b, &spurious);
	CHECK(took < 2700, "reordering alone: %llu ms", (unsigned long long)took);
	CHECK(spurious > 0 && spurious == a.packets_lost + b.packets_lost, "every loss declared came back: %llu of %llu",
	      (unsigned long long)spurious, (unsigned long long)(a.packets_lost + b.packets_lost));
	// 1% random loss: BBR does not slow down for it (2.6 s); NewReno halves its window at each
	// (6.2 s; 14.8 s with the fixed threshold).
	took = lossy(10, 10000, 4u << 20, &a, &b, NULL);
	CHECK(took < 3200, "1%% loss: %llu ms", (unsigned long long)took);
	g_sim_cc = HW_QUIC_CC_NEWRENO;
	took = lossy(10, 10000, 4u << 20, &a, &b, NULL);
	g_sim_cc = HW_QUIC_CC_BBR;
	CHECK(took < 8000, "1%% loss, NewReno: %llu ms", (unsigned long long)took);
	lossy(11, 50000, 4u << 20, &a, &b, NULL);
	lossy(12, 200000, 1u << 20, &a, &b, NULL);
	// The same seed is the same run.
	lossy(11, 50000, 1u << 20, &a, &b, NULL);
	lossy(11, 50000, 1u << 20, &c, &d, NULL);
	CHECK(a.packets_sent == c.packets_sent && b.packets_sent == d.packets_sent && a.packets_lost == c.packets_lost,
	      "repeatable: %llu/%llu vs %llu/%llu", (unsigned long long)a.packets_sent, (unsigned long long)b.packets_sent,
	      (unsigned long long)c.packets_sent, (unsigned long long)d.packets_sent);
}

// bbr2 through the stack: a writer waiting for the send buffer is not app-limited (as
// test_bbr_buffer_limited), the lossy, reordering path of test_loss is as fast as with BBR, its
// spurious losses undone, and the losses quic.c declares are bbr2's.
static void test_bbr2_stack(void) {
	g_sim_cc = HW_QUIC_CC_BBR2;
	test_bbr_buffer_limited();
	hw_quic_stats a, b;
	uint64_t spurious;
	uint64_t took = lossy(9, 0, 4u << 20, &a, &b, &spurious);
	CHECK(took < 2700, "reordering alone: %llu ms", (unsigned long long)took);
	took = lossy(10, 10000, 4u << 20, &a, &b, NULL);
	CHECK(took < 3200, "1%% loss: %llu ms", (unsigned long long)took);
	// Loss that quic.c detects reaches bbr2: 5% is too much, and bounds the flight.
	sim *s = sim_new(12);
	s->loss_ppm = 50000;
	s->delay_ms = 10;
	s->bw = 2000;
	sim_handshake(s);
	bulk(s, 0, 2u << 20, 1200000);
	CHECK(s->sv.q->cc.b.v2 && s->sv.q->cc.b.inflight_hi != UINT64_MAX, "no inflight_hi after 5%% loss");
	sim_free(s);
	g_sim_cc = HW_QUIC_CC_BBR;
}

// Goodput under loss and reordering on the lossy() path: each direction's payload over the
// time it took, as a fraction of the link's bandwidth, averaged over seeds.
static void loss_table(void) {
	static const uint32_t losses[] = {0, 10000, 50000, 200000};
	enum {
		SEEDS = 4
	};
	printf("loss  reorder  goodput (of link)  declared lost  dropped by the path  spurious\n");
	for (size_t li = 0; li < sizeof(losses) / sizeof(losses[0]); li++) {
		for (int reorder = 0; reorder < 2; reorder++) {
			double sum = 0;
			uint64_t lost = 0, dropped = 0, spurious = 0;
			uint64_t bytes = losses[li] >= 200000 ? 1u << 20 : 4u << 20;
			for (uint64_t seed = 0; seed < SEEDS; seed++) {
				sim *s = sim_new(100 + seed);
				s->loss_ppm = losses[li];
				s->reorder_ppm = reorder ? 100000 : 0;
				s->jitter_ms = 8;
				s->dup_ppm = 10000;
				s->delay_ms = 10;
				s->bw = 2000;
				sim_handshake(s);
				uint64_t t0 = s->now;
				bulk(s, bytes, bytes, 1200000);
				int64_t id = 0;
				double up = (double)bytes / (double)((s->sv.st[id].fin_at - t0) * s->bw);
				double down = (double)bytes / (double)((s->c.st[id].fin_at - t0) * s->bw);
				sum += (up + down) / 2;
				hw_quic_stats cs, ss;
				hw_quic_get_stats(s->c.q, &cs);
				hw_quic_get_stats(s->sv.q, &ss);
				lost += cs.packets_lost + ss.packets_lost;
				spurious += s->c.q->spurious_lost + s->sv.q->spurious_lost;
				dropped += s->dropped;
				sim_free(s);
			}
			printf("%3u%%  %-7s  %16.1f%%  %13llu  %19llu  %8llu\n", losses[li] / 10000, reorder ? "yes" : "no",
			       100 * sum / SEEDS, (unsigned long long)lost, (unsigned long long)dropped,
			       (unsigned long long)spurious);
		}
	}
}

typedef struct {
	uint64_t id, bytes;
} half;

static int cond_server_got(sim *s, void *ud) {
	const half *h = ud;
	return s->sv.st[h->id].received >= h->bytes;
}

static void test_migration(void) {
	sim *s = sim_new(5);
	s->bw = 5000;
	sim_handshake(s);
	s->sv.reply = 8u << 20;
	int64_t id = hw_quic_stream_open(s->c.q, 1);
	app_send(&s->c, (uint64_t)id, 8u << 20);
	half h = {(uint64_t)id, 2u << 20};
	CHECK(sim_run(s, cond_server_got, &h, 60000), "first part");
	// A NAT rebinding: the client's port changes under it.
	s->caddr.sin_port = htons(40001);
	xfer x = {(uint64_t)id, 8u << 20, 8u << 20};
	CHECK(sim_run(s, cond_xfer, &x, 120000), "after the rebinding");
	socklen_t pl;
	const struct sockaddr_in *peer = (const struct sockaddr_in *)hw_quic_peer(s->sv.q, &pl);
	CHECK(peer->sin_port == htons(40001), "server follows the new port");
	CHECK(s->sv.q->path_validated, "validated");
	CHECK(!s->c.closed && !s->sv.closed, "connection survives");
	// And an address change, which also resets the congestion controller.
	s->caddr.sin_addr.s_addr = htonl(0x0a000009);
	int64_t id2 = hw_quic_stream_open(s->c.q, 1);
	app_send(&s->c, (uint64_t)id2, 1u << 20);
	s->sv.reply = 1u << 20;
	xfer x2 = {(uint64_t)id2, 1u << 20, 1u << 20};
	CHECK(sim_run(s, cond_xfer, &x2, 60000), "after the address change");
	peer = (const struct sockaddr_in *)hw_quic_peer(s->sv.q, &pl);
	CHECK(peer->sin_addr.s_addr == htonl(0x0a000009), "new address");
	sim_free(s);
}

static void test_idle_timeout(void) {
	sim *s = sim_new(6);
	s->ccfg.max_idle_ms = 5000;
	s->scfg.max_idle_ms = 10000; // the smaller one wins
	sim_handshake(s);
	uint64_t t0 = s->now;
	s->block_c2s = s->block_s2c = 1;
	CHECK(sim_run(s, cond_closed_both, NULL, 30000), "both time out");
	CHECK(!strcmp(s->c.reason, "idle timeout") && !strcmp(s->sv.reason, "idle timeout"), "reason");
	CHECK(s->now - t0 >= 4900 && s->now - t0 <= 5100, "after %llu ms", (unsigned long long)(s->now - t0));
	CHECK(hw_quic_is_drained(s->c.q) && hw_quic_is_drained(s->sv.q), "drained");
	sim_free(s);

	// Keepalive PINGs hold a quiet connection open.
	s = sim_new(7);
	s->ccfg.max_idle_ms = s->scfg.max_idle_ms = 3000;
	s->scfg.keepalive_ms = 1000;
	sim_handshake(s);
	sim_advance(s, 20000);
	CHECK(!s->c.closed && !s->sv.closed, "kept alive");
	sim_free(s);
}

static void test_close_app(void) {
	for (int who = 0; who < 2; who++) {
		sim *s = sim_new(8 + (uint64_t)who);
		sim_handshake(s);
		app *closer = who ? &s->sv : &s->c, *other = who ? &s->c : &s->sv;
		hw_quic_close(closer->q, 0x42, "bye now");
		CHECK(!closer->closed, "the closed callback is not called from hw_quic_close");
		CHECK(hw_quic_timeout(closer->q) <= s->now, "it is due at once");
		CHECK(sim_run(s, cond_closed_both, NULL, 5000), "closed");
		CHECK(closer->close_app && closer->close_err == 0x42, "closer");
		CHECK(other->close_app && other->close_err == 0x42 && !strcmp(other->reason, "bye now"), "peer got it");
		CHECK(sim_run(s, cond_drained_both, NULL, 10000), "drained");
		CHECK_EQ(hw_quic_stream_open(closer->q, 1), -1);
		sim_free(s);
	}
}

static void test_close_transport(void) {
	// A client that sends HANDSHAKE_DONE: PROTOCOL_VIOLATION from the server.
	sim *s = sim_new(10);
	sim_handshake(s);
	uint8_t hsd = HW_QC_F_HANDSHAKE_DONE;
	hw_qc_test_inject(s->c.q, &hsd, 1);
	s->c.q->ping_pending = 1;
	CHECK(sim_run(s, cond_closed_both, NULL, 5000), "closed");
	CHECK(!s->sv.close_app && s->sv.close_err == HW_QUIC_PROTOCOL_VIOLATION, "server");
	CHECK(!s->c.close_app && s->c.close_err == HW_QUIC_PROTOCOL_VIOLATION, "client told %llu",
	      (unsigned long long)s->c.close_err);
	sim_free(s);

	// A server that sends an unknown frame type: FRAME_ENCODING_ERROR from the client.
	s = sim_new(11);
	sim_handshake(s);
	uint8_t unknown[] = {0x40, 0x21}; // 0x21 in two bytes
	hw_qc_test_inject(s->sv.q, unknown, sizeof(unknown));
	s->sv.q->ping_pending = 1;
	CHECK(sim_run(s, cond_closed_both, NULL, 5000), "closed");
	CHECK(!s->c.close_app && s->c.close_err == HW_QUIC_FRAME_ENCODING_ERROR, "client");
	CHECK(!s->sv.close_app && s->sv.close_err == HW_QUIC_FRAME_ENCODING_ERROR, "server told");
	sim_free(s);

	// A STREAM frame on the server's own unopened stream: STREAM_STATE_ERROR.
	s = sim_new(12);
	sim_handshake(s);
	uint8_t st[] = {0x0a, 0x01, 0x01, 'x'}; // stream 1: server-initiated, not opened
	hw_qc_test_inject(s->c.q, st, sizeof(st));
	s->c.q->ping_pending = 1;
	CHECK(sim_run(s, cond_closed_both, NULL, 5000), "closed");
	CHECK_EQ(s->sv.close_err, HW_QUIC_STREAM_STATE_ERROR);
	sim_free(s);

	// Opening a stream past the limit: STREAM_LIMIT_ERROR.
	s = sim_new(13);
	sim_handshake(s);
	uint8_t lim[] = {0x0a, 0x41, 0x90, 0x01, 'x'}; // stream 400 = index 100 of the client's bidi
	hw_qc_test_inject(s->c.q, lim, sizeof(lim));
	s->c.q->ping_pending = 1;
	CHECK(sim_run(s, cond_closed_both, NULL, 5000), "closed");
	CHECK_EQ(s->sv.close_err, HW_QUIC_STREAM_LIMIT_ERROR);
	sim_free(s);
}

// RFC 9000 table 3: Initial and Handshake packets carry PADDING, PING, ACK, CRYPTO and
// CONNECTION_CLOSE (0x1c) only. Anything else from a client there is PROTOCOL_VIOLATION, told to
// the client in the space it can read (an Initial one before its address is validated: the
// datagram that broke the rule counts toward the 3x it may be answered with), naming the frame.
static void test_frames_by_space(void) {
	static const struct {
		const char *name;
		uint64_t type;
		uint8_t bytes[8];
		size_t len;
	} frames[] = {
	    {"STREAM", HW_QC_F_STREAM, {0x0a, 0x00, 0x01, 'x'}, 4},
	    {"MAX_DATA", HW_QC_F_MAX_DATA, {0x10, 0x44, 0x00}, 3},
	    {"DATAGRAM", HW_QC_F_DATAGRAM, {0x31, 0x01, 'x'}, 3},
	    {"NEW_TOKEN", HW_QC_F_NEW_TOKEN, {0x07, 0x01, 0xaa}, 3},
	    {"HANDSHAKE_DONE", HW_QC_F_HANDSHAKE_DONE, {0x1e}, 1},
	    {"CONNECTION_CLOSE 0x1d", HW_QC_F_CONNECTION_CLOSE_APP, {0x1d, 0x00, 0x00}, 3},
	    {"MAX_STREAMS", HW_QC_F_MAX_STREAMS_BIDI, {0x12, 0x05}, 2},
	};
	for (size_t i = 0; i < sizeof(frames) / sizeof(frames[0]); i++) {
		for (int spi = HW_QC_SP_INITIAL; spi <= HW_QC_SP_HANDSHAKE; spi++) {
			sim *s = sim_new(60 + i * 2 + (uint64_t)spi);
			s->check_amp = 1; // the CONNECTION_CLOSE to an unvalidated client, too
			sim_start(s);
			hw_qc_test_inject_at(s->c.q, spi, frames[i].bytes, frames[i].len);
			CHECK(sim_run(s, cond_closed_both, NULL, 5000), "%s in space %d: closed", frames[i].name, spi);
			CHECK(!s->sv.close_app && s->sv.close_err == HW_QUIC_PROTOCOL_VIOLATION, "%s in space %d: server %llu",
			      frames[i].name, spi, (unsigned long long)s->sv.close_err);
			CHECK(s->sv.q->close_frame == frames[i].type, "%s in space %d: frame type %llu", frames[i].name, spi,
			      (unsigned long long)s->sv.q->close_frame);
			CHECK(!s->c.close_app && s->c.close_err == HW_QUIC_PROTOCOL_VIOLATION, "%s in space %d: client told %llu",
			      frames[i].name, spi, (unsigned long long)s->c.close_err);
			CHECK(!s->sv.established, "%s in space %d: never established", frames[i].name, spi);
			sim_free(s);
		}
	}
	// The same frame in a 1-RTT packet is fine.
	sim *s = sim_new(59);
	sim_handshake(s);
	hw_qc_test_inject(s->c.q, frames[1].bytes, frames[1].len);
	s->c.q->ping_pending = 1;
	sim_advance(s, 200);
	CHECK(!s->c.closed && !s->sv.closed, "MAX_DATA in 1-RTT");
	CHECK_EQ(s->c.q->inject_len, 0);
	sim_free(s);
}

// RFC 9001 6.6: packets that fail authentication are counted, and one past the integrity limit
// closes the connection with AEAD_LIMIT_REACHED; nothing is processed after it.
static void test_aead_limit(void) {
	sim *s = sim_new(23);
	sim_handshake(s);
	sim_advance(s, 100);
	uint8_t pkt[HW_QUIC_MAX_DGRAM], bad[HW_QUIC_MAX_DGRAM];
	struct sockaddr_storage to;
	socklen_t to_len;
	s->c.q->ping_pending = 1;
	size_t n = hw_quic_output(s->c.q, pkt, sizeof(pkt), &to, &to_len, s->now);
	CHECK(n > 0 && !(pkt[0] & 0x80), "a 1-RTT packet of the client's");
	const struct sockaddr *from = (const struct sockaddr *)&s->caddr;
	hw_quic_conn *sq = s->sv.q;
	uint64_t before = sq->auth_failures;
	for (size_t i = 0; i < 3; i++) {
		memcpy(bad, pkt, n);
		bad[n - 1 - i] ^= 0x80; // the tag
		hw_quic_input(sq, bad, n, from, sizeof(s->caddr), s->now);
	}
	CHECK_EQ(sq->auth_failures, before + 3);
	CHECK(sq->state == HW_QC_ST_ACTIVE && !s->sv.closed, "a few failures are dropped and counted");
	// A datagram too short to be a packet is not a failure.
	memcpy(bad, pkt, n);
	hw_quic_input(sq, bad, 1 + HW_QUIC_CID_LEN + 10, from, sizeof(s->caddr), s->now);
	CHECK_EQ(sq->auth_failures, before + 3);
	// At the limit it holds; one past it closes.
	sq->auth_failures = HW_QC_AEAD_INTEGRITY_LIMIT - 1;
	memcpy(bad, pkt, n);
	bad[n - 1] ^= 1;
	hw_quic_input(sq, bad, n, from, sizeof(s->caddr), s->now);
	CHECK(sq->auth_failures == HW_QC_AEAD_INTEGRITY_LIMIT && sq->state == HW_QC_ST_ACTIVE, "at the limit");
	memcpy(bad, pkt, n);
	bad[n - 1] ^= 1;
	hw_quic_input(sq, bad, n, from, sizeof(s->caddr), s->now);
	CHECK_EQ(sq->state, HW_QC_ST_CLOSING);
	uint64_t rx = sq->stats.packets_received;
	hw_quic_input(sq, pkt, n, from, sizeof(s->caddr), s->now); // the genuine one, too late
	CHECK_EQ(sq->stats.packets_received, rx);
	CHECK(sim_run(s, cond_closed_both, NULL, 5000), "closed");
	CHECK(!s->sv.close_app && s->sv.close_err == HW_QUIC_AEAD_LIMIT_REACHED, "server %llu",
	      (unsigned long long)s->sv.close_err);
	CHECK(!s->c.close_app && s->c.close_err == HW_QUIC_AEAD_LIMIT_REACHED, "client told");
	sim_free(s);
}

static void test_stateless_reset(void) {
	sim *s = sim_new(14);
	sim_handshake(s);
	sim_advance(s, 100);
	// The server loses its state; the listener answers what comes with stateless resets.
	hw_quic_free(s->sv.q);
	s->sv.q = NULL;
	s->gone = 1;
	int64_t id = hw_quic_stream_open(s->c.q, 1);
	app_send(&s->c, (uint64_t)id, 1000);
	CHECK(sim_run(s, cond_closed_one_client, NULL, 5000), "client closed");
	CHECK(!strcmp(s->c.reason, "stateless reset"), "reason %s", s->c.reason);
	CHECK(hw_quic_is_drained(s->c.q), "drained");
	sim_free(s);
}

typedef struct {
	uint64_t id;
} one;

static int cond_fin(sim *s, void *ud) {
	const one *o = ud;
	return s->sv.st[o->id].fin_received;
}

static void test_flow_control_holds(void) {
	sim *s = sim_new(15);
	sim_handshake(s);
	s->sv.consume = 0; // the server reads nothing
	int64_t id = hw_quic_stream_open(s->c.q, 1);
	app_send(&s->c, (uint64_t)id, 4u << 20);
	sim_advance(s, 3000);
	// The client got as far as the credit and no further; nothing waits anywhere.
	uint64_t credit = s->scfg.initial_max_stream_data;
	CHECK_EQ(s->c.st[id].written, credit);
	CHECK_EQ(s->sv.st[id].received, credit);
	CHECK_EQ(hw_quic_queued(s->c.q), 0);
	hw_qc_stream *ss = hw_qc_smap_get(&s->sv.q->streams, (uint64_t)id);
	CHECK(ss && ss->rx_max == credit && ss->rb.cap == 0 && ss->rb.have.n == 0, "nothing buffered past the credit");
	CHECK(s->sv.q->rx_max_data == s->scfg.initial_max_data, "no connection credit granted either");
	// Reading resumes it.
	s->sv.consume = 1;
	hw_quic_stream_consumed(s->sv.q, (uint64_t)id, credit);
	one o = {(uint64_t)id};
	CHECK(sim_run(s, cond_fin, &o, 30000), "resumed");
	CHECK_EQ(s->sv.st[id].received, 4u << 20);
	sim_free(s);
}

static void test_flow_control_violation(void) {
	// A client that ignores the stream credit.
	sim *s = sim_new(16);
	s->sv.consume = 0;
	sim_handshake(s);
	int64_t id = hw_quic_stream_open(s->c.q, 1);
	hw_qc_stream *cs = hw_qc_smap_get(&s->c.q->streams, (uint64_t)id);
	cs->tx_max = 1u << 30;
	s->c.q->tx_max_data = 1u << 30;
	app_send(&s->c, (uint64_t)id, 2u << 20);
	CHECK(sim_run(s, cond_closed_both, NULL, 10000), "closed");
	CHECK_EQ(s->sv.close_err, HW_QUIC_FLOW_CONTROL_ERROR);
	CHECK(!s->c.close_app && s->c.close_err == HW_QUIC_FLOW_CONTROL_ERROR, "client told");
	CHECK(s->sv.st[id].received <= s->scfg.initial_max_stream_data, "never past the credit");
	sim_free(s);

	// One that ignores the connection's: four streams of 1 MiB each fit their own credit, the
	// fifth byte past 4 MiB does not fit the connection's.
	s = sim_new(17);
	s->sv.consume = 0;
	sim_handshake(s);
	s->c.q->tx_max_data = 1u << 30;
	for (int i = 0; i < 5; i++) {
		id = hw_quic_stream_open(s->c.q, 1);
		app_send(&s->c, (uint64_t)id, 1u << 20);
	}
	CHECK(sim_run(s, cond_closed_both, NULL, 10000), "closed");
	CHECK_EQ(s->sv.close_err, HW_QUIC_FLOW_CONTROL_ERROR);
	CHECK(s->sv.bytes_rx <= s->scfg.initial_max_data, "never past the connection credit");
	sim_free(s);
}

static void test_amplification(void) {
	sim *s = sim_new(18);
	s->scfg.tls.chain_len = 8; // a first flight bigger than 3x the client's Initial
	s->check_amp = 1;
	sim_start(s);
	sim_flush(s);
	uint64_t client_sent = s->c2s;
	CHECK_EQ(client_sent, HW_QUIC_MIN_DGRAM);
	s->block_c2s = 1; // the client's address answers nothing more
	sim_advance(s, 5000);
	CHECK(s->sv.q, "server exists");
	CHECK(s->s2c > 0 && s->s2c <= 3 * client_sent, "server sent %llu for %llu", (unsigned long long)s->s2c,
	      (unsigned long long)client_sent);
	CHECK(!s->sv.q->path_validated, "not validated");
	s->block_c2s = 0;
	CHECK(sim_run(s, cond_established, NULL, 20000), "handshake once the client answers");
	CHECK(s->sv.q->path_validated, "validated by the Handshake packet");
	sim_free(s);
}

// The server's first flight is lost and the client sends its Initial again at its PTO, which in
// Chrome is about 300 ms in (a 100 ms initial RTT): the server sends its flight again at once, not
// at its own PTO, which without a round trip measured is a second away (RFC 9002 6.2.3).
static void test_handshake_resend(void) {
	sim *s = sim_new(19);
	s->delay_ms = 20;
	uint64_t t0 = s->now;
	sim_start(s);
	s->c.q->rtt.smoothed = 100000; // Chrome's kInitialRtt
	s->c.q->rtt.var = 50000;
	s->block_s2c = 1;
	sim_advance(s, 30); // the Initial reaches the server, its answer is lost
	CHECK(s->sv.q && s->s2c > 0, "the server answered");
	s->block_s2c = 0;
	CHECK(sim_run(s, cond_established, NULL, 20000), "handshake");
	CHECK(s->now - t0 < 500, "established after %llu ms", (unsigned long long)(s->now - t0));
	CHECK_EQ(s->sv.q->hs_resends, 1);
	sim_free(s);
}

static void test_retry(void) {
	sim *s = sim_new(19);
	s->retry = 1;
	s->check_amp = 1;
	sim_handshake(s);
	CHECK(s->c.q->retried, "client went through Retry");
	CHECK(s->sv.q->retry_scid_len == HW_QUIC_CID_LEN, "server knows the Retry SCID");
	bulk(s, 256 * 1024, 256 * 1024, 20000);
	sim_free(s);

	// A Retry whose integrity tag is wrong is ignored.
	s = sim_new(20);
	s->retry = 1;
	sim_start(s);
	sim_flush(s);
	CHECK(s->hn == 1, "initial queued");
	sim_pkt p = heap_pop(s);
	hw_quic_header h;
	CHECK_EQ(hw_quic_parse_header(p.data, p.len, &h), 0);
	uint8_t scid[HW_QUIC_CID_LEN] = {9, 9, 9, 9, 9, 9, 9, 9}, out[512];
	size_t n = hw_quic_retry(&h, (const struct sockaddr *)&p.from, s->token_key, s->now, scid, out, sizeof(out));
	CHECK(n > 0, "retry");
	out[n - 1] ^= 1;
	hw_quic_input(s->c.q, out, n, (const struct sockaddr *)&s->saddr, sizeof(s->saddr), s->now);
	CHECK(!s->c.q->retried, "forged Retry ignored");
	free(p.data);
	sim_free(s);
}

static void test_key_update(void) {
	sim *s = sim_new(21);
	s->loss_ppm = 5000;
	s->reorder_ppm = 50000;
	s->jitter_ms = 4;
	sim_handshake(s);
	bulk(s, 1u << 20, 1u << 20, 30000);
	CHECK_EQ(hw_qc_key_update(s->c.q), 0);
	CHECK_EQ(hw_qc_key_update(s->c.q), -1); // not before the new phase is acknowledged
	bulk(s, 1u << 20, 1u << 20, 30000);
	CHECK(s->sv.q->rx_phase == 1 && s->sv.q->tx_phase == 1, "server followed");
	CHECK(s->c.q->rx_phase == 1, "client heard the answer");
	// And the other way, twice more.
	for (int i = 0; i < 2; i++) {
		CHECK_EQ(hw_qc_key_update(s->sv.q), 0);
		bulk(s, 512 * 1024, 512 * 1024, 30000);
	}
	CHECK(s->c.q->rx_phase == 1 && s->c.q->tx_phase == 1 && s->sv.q->rx_phase == 1, "phases");
	CHECK_EQ(s->c.q->key_updates, 3);
	CHECK_EQ(s->sv.q->key_updates, 3);
	CHECK(!s->c.closed && !s->sv.closed, "still up");
	sim_free(s);
}

static void test_stream_reset_stop(void) {
	sim *s = sim_new(22);
	sim_handshake(s);
	s->sv.consume = 1;
	// The client resets its sending side mid-stream: the server hears RESET_STREAM and the
	// bytes it never saw are credited back to the connection.
	int64_t id = hw_quic_stream_open(s->c.q, 1);
	app_send(&s->c, (uint64_t)id, 3u << 20);
	half h = {(uint64_t)id, 256 * 1024};
	CHECK(sim_run(s, cond_server_got, &h, 10000), "some arrived");
	hw_quic_stream_reset(s->c.q, (uint64_t)id, 77);
	CHECK_EQ(hw_quic_queued(s->c.q), 0);
	sim_advance(s, 500);
	CHECK(s->sv.st[id].reset, "server heard the reset");
	CHECK_EQ(s->sv.q->rx_consumed, s->sv.q->rx_highest);
	// The server asks the client to stop a stream: the client answers with RESET_STREAM.
	int64_t id2 = hw_quic_stream_open(s->c.q, 1);
	app_send(&s->c, (uint64_t)id2, 3u << 20);
	half h2 = {(uint64_t)id2, 128 * 1024};
	CHECK(sim_run(s, cond_server_got, &h2, 10000), "some arrived");
	hw_quic_stream_stop(s->sv.q, (uint64_t)id2, 88);
	sim_advance(s, 500);
	CHECK(s->c.st[id2].stopped, "client heard STOP_SENDING");
	CHECK(s->sv.st[id2].reset, "and reset");
	// Both of the client's streams are still half open (the server's side), until the server
	// finishes them.
	hw_quic_stream_write(s->sv.q, (uint64_t)id, NULL, 0, 1);
	hw_quic_stream_write(s->sv.q, (uint64_t)id2, NULL, 0, 1);
	sim_advance(s, 500);
	CHECK(s->c.q->streams.count == 0 && s->sv.q->streams.count == 0, "freed");
	CHECK(!s->c.closed && !s->sv.closed, "still up");
	sim_free(s);
}

static void bench(uint64_t mib) {
	sim *s = sim_new(99);
	s->delay_ms = 1;
	sim_handshake(s);
	double t0 = cpu_seconds();
	bulk(s, mib << 20, 0, 3600000);
	double t = cpu_seconds() - t0;
	printf("bench: %llu MiB on one stream, zero loss: %.1f MB/s of payload per CPU second (%.3f s CPU, both "
	       "endpoints)\n",
	       (unsigned long long)mib, (double)(mib << 20) / 1e6 / t, t);
	sim_free(s);
}

int main(int argc, char **argv) {
	for (size_t i = 0; i < sizeof(g_pattern); i++) g_pattern[i] = (uint8_t)(i * 2654435761u >> 13);
	make_cert();
	if (argc > 1 && !strcmp(argv[1], "--bench")) {
		g_bench = 1;
		bench(argc > 2 ? strtoull(argv[2], NULL, 10) : 256);
		return 0;
	}
	if (argc > 1 && !strcmp(argv[1], "--cc-table")) {
		cc_table(argc > 2 ? (int)strtol(argv[2], NULL, 10) : -1, argc > 3 ? (int)strtol(argv[3], NULL, 10) : -1);
		return 0;
	}
	if (argc > 1 && !strcmp(argv[1], "--loss-table")) {
		g_bench = 1;
		loss_table();
		return 0;
	}
	RUN(test_varint);
	RUN(test_ranges);
	RUN(test_frames_roundtrip);
	RUN(test_frames_malformed);
	RUN(test_sendbuf);
	RUN(test_recvbuf);
	RUN(test_rtt_cc);
	RUN(test_bbr_random_loss);
	RUN(test_bbr_model);
	RUN(test_bbr_buffer_limited);
	RUN(test_clock_us);
	RUN(test_bbr_probe_rtt_stale);
	RUN(test_bbr_clock_tick);
	RUN(test_bbr_sub_tick_rtt);
	RUN(test_bbr_app_limited);
	RUN(test_bbr2_shallow_buffer);
	RUN(test_bbr2_random_loss);
	RUN(test_bbr2_startup_loss);
	RUN(test_bbr2_capacity_drop);
	RUN(test_bbr2_app_limited);
	RUN(test_smap);
	RUN(test_handshake);
	RUN(test_handshake_hrr);
	RUN(test_close_app);
	RUN(test_close_transport);
	RUN(test_frames_by_space);
	RUN(test_idle_timeout);
	RUN(test_stateless_reset);
	RUN(test_aead_limit);
	RUN(test_handshake_resend);
	RUN(test_amplification);
	RUN(test_retry);
	RUN(test_flow_control_holds);
	RUN(test_flow_control_violation);
	RUN(test_stream_reset_stop);
	RUN(test_datagrams);
	RUN(test_many_streams);
	RUN(test_key_update);
	RUN(test_migration);
	RUN(test_loss);
	RUN(test_bbr2_stack);
	RUN(test_pmtu);
	RUN(test_bulk_64m);
	hw_der_free(&g_cert);
	return 0;
}

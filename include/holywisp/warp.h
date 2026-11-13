/*
 * holywisp/warp.h - which WARP tunnel a UDP stream leaves through.
 *
 * On an edge with kernel WARP tunnels, the edge router (abulxt's edge-router.py) sends each TCP
 * stream out through one tunnel, chosen by rendezvous hashing of the stream's site, so that every
 * name of a site leaves from one exit address. holyWisp dials UDP itself and marks the socket
 * (SO_MARK) for the tunnel the router would have chosen, so a site's QUIC and WebRTC leave from
 * the same exit as its TCP. Everything here must agree with the router to the bit: the site key
 * (site_key), the score (rendezvous_score: BLAKE2b, 8 bytes, of key "\0" name, big-endian) and
 * the choice (the highest score, ties to the greater name, among the tunnels healthy for the
 * address family). tests/test_warp.c holds vectors generated from the router itself.
 */
#ifndef HOLYWISP_WARP_H
#define HOLYWISP_WARP_H

#include <stddef.h>
#include <stdint.h>

#define HW_WARP_MAX_TUNNELS 16
#define HW_WARP_NAME_MAX    16 // an interface name: 1 to 15 of A-Z a-z 0-9 _ . - and the NUL

typedef struct hw_warp_tunnel {
	char name[HW_WARP_NAME_MAX];
	uint32_t mark;
} hw_warp_tunnel;

// The tunnels healthy for each address family, as the router published them.
typedef struct hw_warp_state {
	hw_warp_tunnel v4[HW_WARP_MAX_TUNNELS];
	int n4;
	hw_warp_tunnel v6[HW_WARP_MAX_TUNNELS];
	int n6;
} hw_warp_state;

// The site of a host name, which picks its tunnel: the approximate registrable domain (the last
// two labels, or three under a two-letter TLD whose second level is a public suffix of its own,
// as in example.co.uk), lower-cased, trailing dots dropped. Written to out with its NUL. 0, or -1
// when it does not fit in cap (out is then empty). An IP literal is not a host name: its key is
// the address as inet_ntop writes it.
int hw_warp_site_key(const char *host, char *out, size_t cap);

// The rendezvous score of a tunnel for a key: the first 8 bytes of BLAKE2b(key "\0" name), read
// big-endian.
uint64_t hw_warp_score(const char *key, const char *name);

// The tunnel for key among those healthy for the family (v6 nonzero: IPv6), or NULL when there
// is none.
const hw_warp_tunnel *hw_warp_pick(const hw_warp_state *st, int v6, const char *key);

// Read the router's state file: {"v4": [{"name": "warp0", "mark": 30465}, ...], "v6": [...]}.
// Other keys, at either level, are ignored; a family that is absent has no healthy tunnel. A name
// that is not an interface name, a mark outside 1..0xFFFFFFFF, a name or mark listed twice in one
// family, more than HW_WARP_MAX_TUNNELS in one, or anything that is not JSON is an error: 0, or
// -1 with the reason in err, and then *out holds nothing to use.
int hw_warp_state_parse(const char *json, size_t len, hw_warp_state *out, char *err, size_t err_cap);

// Drop every tunnel whose mark is not one of marks[0..n): the state file can only choose among
// the marks the configuration allows. Returns how many were dropped.
int hw_warp_state_restrict(hw_warp_state *st, const uint32_t *marks, int n);

// "0x7701,0x7702, 30467" -> marks (hex with 0x, or decimal; 1..0xFFFFFFFF, each once). The count,
// or -1 when the list is empty, malformed, repeats a mark or holds more than cap.
int hw_warp_marks_parse(const char *text, uint32_t *marks, int cap);

#endif

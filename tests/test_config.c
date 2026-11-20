/*
 * Config parsing: inline comments, quoted values, flags, and that the shipped default configs
 * actually load (a broken default config would brick a fresh install).
 */
#include "holywisp/quic.h"
#include "holywisp/server.h"

#include "server/config.h"
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_file(const char *path, const char *content) {
	FILE *f = fopen(path, "w");
	CHECK(f != NULL, "open %s", path);
	fputs(content, f);
	fclose(f);
}

// prefix, then a line of exactly len bytes (body and spaces, which the reader trims), then end.
static void padded_line(char *out, size_t cap, const char *prefix, const char *body, size_t len, const char *end) {
	size_t p = strlen(prefix), b = strlen(body), e = strlen(end);
	CHECK(p + len + e < cap && b <= len, "padded_line: %zu bytes do not fit", p + len + e);
	size_t at = 0;
	for (const char *c = prefix; *c; c++) out[at++] = *c;
	for (const char *c = body; *c; c++) out[at++] = *c;
	while (at < p + len) out[at++] = ' ';
	for (const char *c = end; *c; c++) out[at++] = *c;
	out[at] = '\0';
}

static void test_inline_comments_and_quotes(void) {
	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-cfg");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	close(fd);
	write_file(path, "# a full-line comment\n"
	                 "host = 127.0.0.1            # bind address\n"
	                 "port = 6001\n"
	                 "workers = 0                 # 0 = one per CPU\n"
	                 "syn-signature-min-samples = 128\n"
	                 "\n"
	                 "   # indented comment\n"
	                 "non-ws-response = \"hello # world\"   # the body may contain a hash\n"
	                 "motd =\n"
	                 "webclient-wisp-url = wss://relay.example/pipe/k/\n");
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK(hw_config_load_file(&cfg, path, err, sizeof(err)) == 0, "load: %s", err);
	CHECK_STR(cfg.host, "127.0.0.1");
	CHECK_EQ(cfg.port, 6001);
	CHECK_EQ(cfg.workers, 0);
	CHECK_EQ(cfg.flood.syn_signature_min_samples, 128);
	// A quoted value keeps its inner '#' and spaces; the trailing comment is dropped.
	CHECK_STR(cfg.non_ws_response, "hello # world");
	CHECK_STR(cfg.webclient_wisp_url, "wss://relay.example/pipe/k/");
	unlink(path);
}

static void test_bad_value_reports_line(void) {
	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-cfg");
	int fd = mkstemp(path);
	close(fd);
	write_file(path, "port = 6001\nworkers = notanumber\n");
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK(hw_config_load_file(&cfg, path, err, sizeof(err)) != 0, "bad value rejected");
	CHECK(strstr(err, ":2:") != NULL, "error names the line: %s", err);
	unlink(path);
}

// The web client URL goes into a <script> string: only ws(s):// and nothing that could escape it.
static void test_webclient_url_validation(void) {
	hw_server_config cfg;
	char err[256];
	const char *bad[] = {"https://relay.example/", "wss://relay.example/\"</script>", "wss://a b", "wss://x'y"};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		hw_server_config_defaults(&cfg);
		snprintf(cfg.webclient_wisp_url, sizeof(cfg.webclient_wisp_url), "%s", bad[i]);
		CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) != 0, "rejected: %s", bad[i]);
	}
	hw_server_config_defaults(&cfg);
	snprintf(cfg.webclient_wisp_url, sizeof(cfg.webclient_wisp_url), "%s", "wss://relay.example/pipe/k/");
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) == 0, "accepted: %s", err);
}

// The configs we ship must load, or a fresh install will not start.
static void load_shipped(const char *path) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK(hw_config_load_file(&cfg, path, err, sizeof(err)) == 0, "%s: %s", path, err);
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) == 0, "%s validate: %s", path, err);
}

static void test_busy_poll_key(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	CHECK_EQ(cfg.busy_poll_us, 0);
	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-cfg");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "mkstemp");
	const char *text = "busy-poll-us = 50\n";
	CHECK_EQ(write(fd, text, strlen(text)), (ssize_t)strlen(text));
	close(fd);
	char err[256] = "";
	CHECK(hw_config_load_file(&cfg, path, err, sizeof(err)) == 0, "load: %s", err);
	CHECK_EQ(cfg.busy_poll_us, 50);
	unlink(path);
}

static void test_stop_on_stdin_eof_key(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK_EQ(cfg.stop_on_stdin_eof, 0);
	CHECK_EQ(hw_config_set(&cfg, "stop-on-stdin-eof", "on", err, sizeof(err)), 0);
	CHECK_EQ(cfg.stop_on_stdin_eof, 1);
	CHECK(hw_config_set(&cfg, "stop-on-stdin-eof", "maybe", err, sizeof(err)) != 0, "rejects a non-boolean");
}

static void test_stream_credit_key(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK_EQ(cfg.stream_credit, 1);
	CHECK_EQ(hw_config_set(&cfg, "stream-credit", "off", err, sizeof(err)), 0);
	CHECK_EQ(cfg.stream_credit, 0);
	CHECK_EQ(hw_config_set(&cfg, "stream-credit", "true", err, sizeof(err)), 0);
	CHECK_EQ(cfg.stream_credit, 1);
	CHECK(hw_config_set(&cfg, "stream-credit", "sometimes", err, sizeof(err)) != 0, "rejects a non-boolean");
	CHECK_EQ(cfg.stream_credit, 1);
}

// The queue budget: on by default, sizes past 4 GiB (a 64-bit field), 0 turns either half off.
// And the cap on connections of one address still in their HTTP head.
static void test_queue_and_head_keys(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK_EQ(cfg.server_queue_max, 4ull << 30);
	CHECK_EQ(cfg.server_queue_max_per_ip, 1ull << 30);
	CHECK_EQ(hw_config_set(&cfg, "server-queue-max", "17179869184", err, sizeof(err)), 0);
	CHECK_EQ(cfg.server_queue_max, 16ull << 30);
	CHECK_EQ(hw_config_set(&cfg, "server-queue-max-per-ip", "0", err, sizeof(err)), 0);
	CHECK_EQ(cfg.server_queue_max_per_ip, 0);
	CHECK(hw_config_set(&cfg, "server-queue-max", "-1", err, sizeof(err)) != 0, "rejects a negative size");
	CHECK_EQ(cfg.flood.max_handshakes_per_ip, 128);
	CHECK_EQ(hw_config_set(&cfg, "max-handshakes-per-ip", "8", err, sizeof(err)), 0);
	CHECK_EQ(cfg.flood.max_handshakes_per_ip, 8);
}

static void test_upload_credit_key(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK_EQ(cfg.upload_credit, 1);
	CHECK_EQ(hw_config_set(&cfg, "upload-credit", "off", err, sizeof(err)), 0);
	CHECK_EQ(cfg.upload_credit, 0);
	CHECK_EQ(hw_config_set(&cfg, "upload-credit", "on", err, sizeof(err)), 0);
	CHECK_EQ(cfg.upload_credit, 1);
	CHECK(hw_config_set(&cfg, "upload-credit", "sometimes", err, sizeof(err)) != 0, "rejects a non-boolean");
	CHECK_EQ(cfg.upload_credit, 1);
}

static void test_proxy_client_key_keys(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK_EQ(cfg.proxy_client_key, 0);
	CHECK_STR(cfg.proxy_client_key_secret, "");
	CHECK_EQ(hw_config_set(&cfg, "proxy-client-key", "on", err, sizeof(err)), 0);
	CHECK_EQ(cfg.proxy_client_key, 1);
	CHECK_EQ(hw_config_set(&cfg, "proxy-client-key-secret", "sixteen-or-more!", err, sizeof(err)), 0);
	CHECK_STR(cfg.proxy_client_key_secret, "sixteen-or-more!");
	// A secret that does not fit is refused, and the error, which is logged, does not hold it.
	char longer[200];
	memset(longer, 'q', sizeof(longer) - 1);
	longer[sizeof(longer) - 1] = '\0';
	CHECK(hw_config_set(&cfg, "proxy-client-key-secret", longer, err, sizeof(err)) != 0, "a 199-byte secret");
	CHECK(strstr(err, "qqqq") == NULL, "the secret in the error: %s", err);
}

static void test_warp_bypass_host_key(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	// The edge router reads the same list: these are the spellings both take, and only these.
	const char *good[] = {"youtube.com", "*.youtube.com", " .reddit.com", "Reddit.COM."};
	for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
		CHECK_EQ(hw_config_set(&cfg, "warp-bypass-host", good[i], err, sizeof(err)), 0);
	}
	CHECK_EQ(cfg.warp_bypass_hosts.count, 4);
	CHECK(hw_hostlist_allows(&cfg.warp_bypass_hosts, "m.youtube.com", 13), "subdomain");
	CHECK(hw_hostlist_allows(&cfg.warp_bypass_hosts, "reddit.com", 10), "exact");
	CHECK(!hw_hostlist_allows(&cfg.warp_bypass_hosts, "notyoutube.com", 14), "suffix is not a subdomain");
	const char *bad[] = {"", ".", "*.", "*", "you*tube.com", "*.*.youtube.com", "*youtube.com", "*. "};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		CHECK(hw_config_set(&cfg, "warp-bypass-host", bad[i], err, sizeof(err)) != 0, "accepted '%s'", bad[i]);
	}
	CHECK_EQ(cfg.warp_bypass_hosts.count, 4);
}

// A policy file holds the lists an operator edits, in the config file's syntax, and nothing else.
// Its entries go on top of the config's own. A key that is not a list, a value the key refuses,
// a line too long to be read whole and a file that is not there are each an error naming the line.
static void test_policy_file_keys(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK_EQ(hw_config_set(&cfg, "policy-file", "/etc/holywisp/policy.conf", err, sizeof(err)), 0);
	CHECK_STR(cfg.policy_file, "/etc/holywisp/policy.conf");
	CHECK_EQ(hw_config_set(&cfg, "block-host", "config.example", err, sizeof(err)), 0);

	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-policy");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	close(fd);
	write_file(path, "# lists only\n"
	                 "block-host = *.blocked.example   # and its subdomains\n"
	                 "allow-port = 443\n"
	                 "block-port = 6881-6889\n"
	                 "warp-bypass-host = *.youtube.com\n"
	                 "allow-origin = https://app.example\n"
	                 "allow-host = \"only.example\"\n");
	CHECK(hw_config_load_policy(&cfg, path, err, sizeof(err)) == 0, "load: %s", err);
	CHECK_EQ(cfg.block_hosts.count, 2);
	CHECK(hw_hostlist_blocks(&cfg.block_hosts, "config.example", 14), "the config's entry stays");
	CHECK(hw_hostlist_blocks(&cfg.block_hosts, "a.blocked.example", 17), "the file's entry");
	CHECK(hw_portset_has(&cfg.allow_ports, 443) && hw_portset_has(&cfg.block_ports, 6885), "ports");
	CHECK_EQ(cfg.warp_bypass_hosts.count, 1);
	CHECK_EQ(cfg.allow_origin_count, 1);
	CHECK_STR(cfg.allow_origins[0], "https://app.example");
	CHECK_EQ(cfg.allow_hosts.count, 1);

	const struct {
		const char *content;
		const char *says;
	} bad[] = {
	    {"block-host = a.example\nport = 7000\n", ":2: 'port' is not for a policy file"},
	    {"policy-file = /tmp/other\n", ":1: 'policy-file' is not for a policy file"},
	    {"password-user = alice:secret\n", ":1: 'password-user' is not for a policy file"},
	    {"allow-port = https\n", ":1: bad value"},
	    {"allow-origin = example.com\n", ":1: allow-origin"},
	    {"warp-bypass-host = you*tube.com\n", ":1: warp-bypass-host"},
	    {"block-host\n", ":1: expected key = value"},
	};
	hw_server_config *scratch = malloc(sizeof(*scratch)); // a config is 260 KiB: not two on Windows' stack
	CHECK(scratch != NULL, "malloc");
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		write_file(path, bad[i].content);
		*scratch = cfg;
		CHECK(hw_config_load_policy(scratch, path, err, sizeof(err)) != 0, "accepted: %s", bad[i].content);
		CHECK(strstr(err, bad[i].says) != NULL, "'%s' for %s", err, bad[i].content);
	}
	free(scratch);
	// A line the reader cannot hold whole is refused, never read as two.
	static char longline[1200];
	int at = snprintf(longline, sizeof(longline), "block-host = ");
	memset(longline + at, 'a', sizeof(longline) - 2 - (size_t)at);
	longline[sizeof(longline) - 2] = '\n';
	write_file(path, longline);
	CHECK(hw_config_load_policy(&cfg, path, err, sizeof(err)) != 0, "a long line was accepted");
	CHECK(strstr(err, ":1: line longer than 1023 bytes") != NULL, "%s", err);
	// The limit is what the message says: 1023 bytes is a line, 1024 is not.
	static char text[2 * HW_CONFIG_LINE_MAX];
	padded_line(text, sizeof(text), "", "allow-port = 8443", HW_CONFIG_LINE_MAX, "\n");
	write_file(path, text);
	CHECK(hw_config_load_policy(&cfg, path, err, sizeof(err)) == 0, "1023 bytes: %s", err);
	CHECK(hw_portset_has(&cfg.allow_ports, 8443), "the line of 1023 bytes was applied");
	padded_line(text, sizeof(text), "", "allow-port = 8444", HW_CONFIG_LINE_MAX + 1, "\n");
	write_file(path, text);
	CHECK(hw_config_load_policy(&cfg, path, err, sizeof(err)) != 0, "1024 bytes were accepted");
	CHECK(strstr(err, ":1: line longer than 1023 bytes") != NULL, "%s", err);
	unlink(path);
	CHECK(hw_config_load_policy(&cfg, path, err, sizeof(err)) != 0, "a missing file was accepted");
}

// A config file's line of more than HW_CONFIG_LINE_MAX bytes is an error naming it, comments
// included: the reader once took the rest of it as a line of its own, so a setting at the end of
// a long comment was applied.
static void test_config_long_lines(void) {
	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-cfg");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	close(fd);
	hw_server_config *cfg = malloc(sizeof(*cfg)); // a config is 260 KiB: not on Windows' stack
	CHECK(cfg != NULL, "malloc");
	char err[512];
	static char text[4 * HW_CONFIG_LINE_MAX];
	// Exactly the limit, ended by "\n", by "\r\n" or by the end of the file: a line.
	const char *ends[] = {"\n", "\r\n", ""};
	for (size_t i = 0; i < sizeof(ends) / sizeof(ends[0]); i++) {
		hw_server_config_defaults(cfg);
		padded_line(text, sizeof(text), "", "port = 7000", HW_CONFIG_LINE_MAX, ends[i]);
		write_file(path, text);
		CHECK(hw_config_load_file(cfg, path, err, sizeof(err)) == 0, "1023 bytes, end %zu: %s", i, err);
		CHECK_EQ(cfg->port, 7000);
	}
	// One byte more, however it ends.
	for (size_t i = 0; i < sizeof(ends) / sizeof(ends[0]); i++) {
		hw_server_config_defaults(cfg);
		padded_line(text, sizeof(text), "port = 1\n", "port = 7000", HW_CONFIG_LINE_MAX + 1, ends[i]);
		write_file(path, text);
		CHECK(hw_config_load_file(cfg, path, err, sizeof(err)) != 0, "1024 bytes, end %zu, accepted", i);
		CHECK(strstr(err, ":2: line longer than 1023 bytes") != NULL, "%s", err);
	}
	// A comment whose tail, past the buffer, is a setting.
	int at = snprintf(text, sizeof(text), "# ");
	memset(text + at, 'x', (size_t)HW_CONFIG_LINE_MAX - 2);
	snprintf(text + HW_CONFIG_LINE_MAX, sizeof(text) - HW_CONFIG_LINE_MAX, "port = 7001\n");
	write_file(path, text);
	hw_server_config_defaults(cfg);
	CHECK(hw_config_load_file(cfg, path, err, sizeof(err)) != 0, "a long comment was accepted");
	CHECK(strstr(err, ":1: line longer than 1023 bytes") != NULL, "%s", err);
	CHECK(cfg->port != 7001, "the comment's tail was applied");
	unlink(path);
	free(cfg);
}

// The WebTransport keys, their defaults, and what validation refuses.
static void test_webtransport_keys(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK_EQ(cfg.webtransport, 0);
	CHECK_EQ(cfg.webtransport_port, 0);
	CHECK_EQ(cfg.webtransport_idle_timeout_s, 30);
	CHECK_EQ(cfg.webtransport_max_handshakes, 1024);
	CHECK_EQ(cfg.webtransport_retry_threshold, 64);
	CHECK_EQ(hw_config_set(&cfg, "webtransport", "on", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-host", "::1", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-port", "4433", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-url", "https://relay.example:4433/wt", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-idle-timeout-s", "45", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-max-handshakes", "256", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-retry-threshold", "0", err, sizeof(err)), 0);
	CHECK_EQ(cfg.webtransport, 1);
	CHECK_STR(cfg.webtransport_host, "::1");
	CHECK_EQ(cfg.webtransport_port, 4433);
	CHECK_STR(cfg.webtransport_url, "https://relay.example:4433/wt");
	CHECK_EQ(cfg.webtransport_idle_timeout_s, 45);
	CHECK_EQ(cfg.webtransport_max_handshakes, 256);
	CHECK_EQ(cfg.webtransport_retry_threshold, 0);
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) == 0, "valid: %s", err);
	// Congestion control: BBR unless NewReno is asked for, and nothing else.
	CHECK_EQ(cfg.webtransport_congestion, HW_QUIC_CC_BBR);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-congestion-control", "newreno", err, sizeof(err)), 0);
	CHECK_EQ(cfg.webtransport_congestion, HW_QUIC_CC_NEWRENO);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-congestion-control", "bbr", err, sizeof(err)), 0);
	CHECK_EQ(cfg.webtransport_congestion, HW_QUIC_CC_BBR);
	CHECK(hw_config_set(&cfg, "webtransport-congestion-control", "cubic", err, sizeof(err)) != 0, "no cubic");
	// Lanes: 8 unless set, 0 to 16, and the validator holds a struct filled in by hand to that.
	CHECK_EQ(cfg.webtransport_lanes, 8);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-lanes", "16", err, sizeof(err)), 0);
	CHECK_EQ(cfg.webtransport_lanes, 16);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-lanes", "0", err, sizeof(err)), 0);
	CHECK_EQ(cfg.webtransport_lanes, 0);
	CHECK(hw_config_set(&cfg, "webtransport-lanes", "17", err, sizeof(err)) != 0, "17 lanes");
	CHECK(hw_config_set(&cfg, "webtransport-lanes", "-1", err, sizeof(err)) != 0, "-1 lanes");
	CHECK_EQ(cfg.webtransport_lanes, 0);
	cfg.webtransport_lanes = 17;
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) != 0, "17 lanes set by hand");
	CHECK(strstr(err, "webtransport-lanes") != NULL, "the error names it: %s", err);
	cfg.webtransport_lanes = 4;
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) == 0, "4 lanes: %s", err);
	// An idle timeout is not optional, and neither is a handshake cap.
	CHECK(hw_config_set(&cfg, "webtransport-idle-timeout-s", "0", err, sizeof(err)) != 0, "idle timeout 0");
	CHECK(hw_config_set(&cfg, "webtransport-max-handshakes", "0", err, sizeof(err)) != 0, "no handshakes");
	CHECK(hw_config_set(&cfg, "webtransport-port", "65536", err, sizeof(err)) != 0, "port range");
	// A certificate needs its key, and the other way round.
	CHECK_EQ(hw_config_set(&cfg, "webtransport-cert", "/etc/wt/chain.pem", err, sizeof(err)), 0);
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) != 0, "cert without key");
	CHECK(strstr(err, "webtransport-key") != NULL, "the error names it: %s", err);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-key", "/etc/wt/key.pem", err, sizeof(err)), 0);
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) == 0, "cert and key: %s", err);
	cfg.webtransport_cert[0] = '\0';
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) != 0, "key without cert");
	cfg.webtransport_key[0] = '\0';
	// The URL goes into JSON as it is: https:// and nothing that would need escaping.
	const char *bad[] = {"http://relay.example/", "wss://relay.example/", "https://", "https://a\"b", "https://a\\b",
	                     "https://a b",           "https://r\xc3\xa9lay/"};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		snprintf(cfg.webtransport_url, sizeof(cfg.webtransport_url), "%s", bad[i]);
		CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) != 0, "accepted %s", bad[i]);
	}
	cfg.webtransport_url[0] = '\0';
	// The certificate directory, and the paths: [host] /path, repeatable.
	CHECK_EQ(hw_config_set(&cfg, "webtransport-cert-dir", "/etc/wt/hosts", err, sizeof(err)), 0);
	CHECK_STR(cfg.webtransport_cert_dir, "/etc/wt/hosts");
	CHECK_STR(cfg.webtransport_reset_key_file, "");
	CHECK_EQ(hw_config_set(&cfg, "webtransport-reset-key-file", "/var/lib/holywisp/wt.key", err, sizeof(err)), 0);
	CHECK_STR(cfg.webtransport_reset_key_file, "/var/lib/holywisp/wt.key");
	CHECK_EQ(hw_config_set(&cfg, "webtransport-path", "/pipe/0123456789abcdef", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(&cfg, "webtransport-path", "relay.example   /", err, sizeof(err)), 0);
	CHECK_EQ(cfg.webtransport_path_count, 2);
	CHECK_STR(cfg.webtransport_paths[0].host, "");
	CHECK_STR(cfg.webtransport_paths[0].path, "/pipe/0123456789abcdef");
	CHECK_STR(cfg.webtransport_paths[1].host, "relay.example");
	CHECK_STR(cfg.webtransport_paths[1].path, "/");
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) == 0, "paths: %s", err);
	// Not a path, or not one rule; and the value is never repeated (it may hold a gate key).
	const char *bad_paths[] = {
	    "pipe/secretkey", "", "relay.example", "/a b", "/secretkey?x", "a/b /secretkey", "relay.example /secretkey x"};
	for (size_t i = 0; i < sizeof(bad_paths) / sizeof(bad_paths[0]); i++) {
		CHECK(hw_config_set(&cfg, "webtransport-path", bad_paths[i], err, sizeof(err)) != 0, "accepted '%s'",
		      bad_paths[i]);
		CHECK(strstr(err, "secretkey") == NULL, "the value is in the message: %s", err);
	}
	CHECK_EQ(cfg.webtransport_path_count, 2);
	for (int i = 2; i < HW_MAX_WT_PATHS; i++) {
		CHECK_EQ(hw_config_set(&cfg, "webtransport-path", "/x", err, sizeof(err)), 0);
	}
	CHECK(hw_config_set(&cfg, "webtransport-path", "/x", err, sizeof(err)) != 0, "past HW_MAX_WT_PATHS");
}

// hw_server_config_check (holywisp --check-config): what a start would refuse, found without a
// start, and nothing secret in what it says.
static void test_config_check(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[512];
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) == 0, "defaults: %s", err);
	// A rule across keys that every key alone passes: the parse accepts it, the check does not.
	CHECK_EQ(hw_config_set(&cfg, "tcp-warp", "on", err, sizeof(err)), 0);
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) != 0, "tcp-warp without its tunnels");
	CHECK(strstr(err, "tcp-warp") != NULL, "the error names it: %s", err);
	cfg.tcp_warp = 0;
	// A proxy at a literal address needs no lookup; its user and password are never repeated.
	CHECK_EQ(hw_config_set(&cfg, "proxy", "socks5://user:hunter2secret@127.0.0.1:1080", err, sizeof(err)), 0);
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) == 0, "literal proxy: %s", err);
	CHECK_EQ(hw_config_set(&cfg, "proxy-client-key-secret", "hunter2", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(&cfg, "proxy-client-key", "on", err, sizeof(err)), 0);
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) != 0, "a short secret");
	CHECK(strstr(err, "hunter2") == NULL, "the secret is in the message: %s", err);
	hw_server_config_defaults(&cfg);
	// WebTransport files: only what a start would read. Off, nothing is read.
	char missing[512];
	hw_test_tmp(missing, sizeof(missing), "hw-cfg-missing");
	snprintf(cfg.webtransport_cert, sizeof(cfg.webtransport_cert), "%s", missing);
	snprintf(cfg.webtransport_key, sizeof(cfg.webtransport_key), "%s", missing);
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) == 0, "webtransport off: %s", err);
	cfg.webtransport = 1;
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) != 0, "a certificate that is not there");
	CHECK(strstr(err, "webtransport-cert") != NULL, "the error names it: %s", err);
	// Not a PEM certificate at all.
	char junk[512];
	hw_test_tmp(junk, sizeof(junk), "hw-cfg-pem");
	int fd = mkstemp(junk);
	CHECK(fd >= 0, "tmp");
	close(fd);
	write_file(junk, "not a certificate\n");
	snprintf(cfg.webtransport_cert, sizeof(cfg.webtransport_cert), "%s", junk);
	snprintf(cfg.webtransport_key, sizeof(cfg.webtransport_key), "%s", junk);
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) != 0, "junk for a certificate");
	unlink(junk);
	cfg.webtransport_cert[0] = cfg.webtransport_key[0] = '\0';
	// The self-signed certificate is made at start, from nothing: no file to check.
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) == 0, "self-signed: %s", err);
	snprintf(cfg.webtransport_cert_dir, sizeof(cfg.webtransport_cert_dir), "%s", missing);
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) != 0, "a certificate directory that is not there");
	CHECK(strstr(err, "webtransport-cert-dir") != NULL, "the error names it: %s", err);
}

// A dns-server that is not an address is an error where it is written, and a config filled in by
// hand with one is refused by validation, so by a start and --check-config alike: skipped, it
// would put the lookups on the system resolver (the name gate's 127.0.0.1:1083 on the edges).
static void test_dns_server_key(void) {
	hw_server_config *cfg = malloc(sizeof(*cfg)); // a config is 260 KiB: not on Windows' stack
	CHECK(cfg != NULL, "malloc");
	hw_server_config_defaults(cfg);
	char err[512];
	CHECK_EQ(hw_config_set(cfg, "dns-server", "127.0.0.1:1083", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(cfg, "dns-server", "[2606:4700:4700::1111]:53", err, sizeof(err)), 0);
	CHECK_EQ(hw_config_set(cfg, "dns-server", "1.1.1.1", err, sizeof(err)), 0);
	CHECK_EQ(cfg->dns_server_count, 3);
	CHECK(hw_server_config_check(cfg, err, sizeof(err)) == 0, "good servers: %s", err);
	const char *bad[] = {"127.0.0.1:abc", "2606:4700:4700::1111", "dns.example", "1.1.1.1:0", ""};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		CHECK(hw_config_set(cfg, "dns-server", bad[i], err, sizeof(err)) != 0, "accepted '%s'", bad[i]);
		CHECK(strstr(err, "dns-server") != NULL, "the error names the key: %s", err);
	}
	CHECK_EQ(cfg->dns_server_count, 3);
	// A file names the line.
	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-cfg");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	close(fd);
	write_file(path, "dns-server = 1.1.1.1\ndns-server = 1.1.1.1:5x\n");
	CHECK(hw_config_load_file(cfg, path, err, sizeof(err)) != 0, "a file with a bad dns-server");
	CHECK(strstr(err, ":2: dns-server") != NULL, "%s", err);
	unlink(path);
	// Filled in by hand: validation, so hw_server_new and the check, refuse it.
	snprintf(cfg->dns_servers[1], sizeof(cfg->dns_servers[1]), "%s", "127.0.0.1:abc");
	CHECK(hw_server_config_validate(cfg, err, sizeof(err)) != 0, "a bad server set by hand");
	CHECK(strstr(err, "dns-server 2") != NULL, "%s", err);
	CHECK(hw_server_config_check(cfg, err, sizeof(err)) != 0, "the check took it");
	CHECK(hw_server_new(cfg) == NULL, "a server started with it");
	snprintf(cfg->dns_servers[1], sizeof(cfg->dns_servers[1]), "%s", "1.0.0.1");
	cfg->dns_server_count = HW_MAX_DNS_SERVERS + 1;
	CHECK(hw_server_config_validate(cfg, err, sizeof(err)) != 0, "more servers than there is room for");
	free(cfg);
}

// trusted-headers-reset is a boolean like the others: on (as written in the shipped examples and
// on the edges) or true (the npm wrapper's flag) empties the list, off leaves it, anything else is
// refused. It once emptied the list whatever it was given.
static void test_trusted_headers_reset_key(void) {
	hw_server_config *cfg = malloc(sizeof(*cfg)); // a config is 260 KiB: not on Windows' stack
	CHECK(cfg != NULL, "malloc");
	char err[256];
	hw_server_config_defaults(cfg);
	CHECK_EQ(cfg->trusted_header_count, 1);
	CHECK_STR(cfg->trusted_headers[0], "X-Forwarded-For");
	const char *off[] = {"off", "false", "no", "0"};
	for (size_t i = 0; i < sizeof(off) / sizeof(off[0]); i++) {
		CHECK_EQ(hw_config_set(cfg, "trusted-headers-reset", off[i], err, sizeof(err)), 0);
		CHECK_EQ(cfg->trusted_header_count, 1);
	}
	const char *on[] = {"on", "true", "yes", "1"};
	for (size_t i = 0; i < sizeof(on) / sizeof(on[0]); i++) {
		CHECK_EQ(hw_config_set(cfg, "trusted-header", "CF-Connecting-IP", err, sizeof(err)), 0);
		CHECK_EQ(hw_config_set(cfg, "trusted-headers-reset", on[i], err, sizeof(err)), 0);
		CHECK_EQ(cfg->trusted_header_count, 0);
	}
	CHECK(hw_config_set(cfg, "trusted-headers-reset", "", err, sizeof(err)) != 0, "an empty value");
	CHECK(hw_config_set(cfg, "trusted-headers-reset", "maybe", err, sizeof(err)) != 0, "a non-boolean");
	// As the edges write it, and as a bare flag after the file, which then empties the file's list.
	char path[512];
	hw_test_tmp(path, sizeof(path), "hw-cfg");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	close(fd);
	write_file(path, "trusted-headers-reset = on\ntrusted-header = X-Real-IP\n");
	hw_server_config_defaults(cfg);
	CHECK(hw_config_load_file(cfg, path, err, sizeof(err)) == 0, "load: %s", err);
	CHECK_EQ(cfg->trusted_header_count, 1);
	CHECK_STR(cfg->trusted_headers[0], "X-Real-IP");
	char config_arg[600];
	snprintf(config_arg, sizeof(config_arg), "--config=%s", path);
	char argv0[] = "holywisp", flag[] = "--trusted-headers-reset";
	char *argv[] = {argv0, config_arg, flag, NULL};
	hw_server_config_defaults(cfg);
	CHECK_EQ(hw_config_parse_args(cfg, 3, argv, err, sizeof(err)), 0);
	CHECK_EQ(cfg->trusted_header_count, 0);
	unlink(path);
	free(cfg);
}

// --check-config reads policy-file as a start does: a file a start would refuse is refused, with
// the line it fails at, and one it would take passes.
static void test_config_check_policy_file(void) {
	hw_server_config *cfg = malloc(sizeof(*cfg)); // a config is 260 KiB: not on Windows' stack
	CHECK(cfg != NULL, "malloc");
	hw_server_config_defaults(cfg);
	char err[512];
	char path[200]; // it goes into policy_file, 256 bytes
	hw_test_tmp(path, sizeof(path), "hw-cfg-policy");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "tmp");
	close(fd);
	snprintf(cfg->policy_file, sizeof(cfg->policy_file), "%s", path);
	write_file(path, "block-host = blocked.example\nallow-port = 443\n");
	CHECK(hw_server_config_check(cfg, err, sizeof(err)) == 0, "a good policy file: %s", err);
	const struct {
		const char *content;
		const char *says;
	} bad[] = {
	    {"block-host = a.example\nport = 7000\n", ":2: 'port' is not for a policy file"},
	    {"allow-port = https\n", ":1: bad value"},
	    // Every line loads, but the config it makes is refused: warp-bypass-host needs WARP.
	    {"warp-bypass-host = example.com\n", "warp-bypass-host"},
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		write_file(path, bad[i].content);
		CHECK(hw_server_config_check(cfg, err, sizeof(err)) != 0, "accepted: %s", bad[i].content);
		CHECK(strncmp(err, "policy-file: ", 13) == 0, "the error names the key: %s", err);
		CHECK(strstr(err, bad[i].says) != NULL, "'%s' for %s", err, bad[i].content);
	}
	unlink(path);
	CHECK(hw_server_config_check(cfg, err, sizeof(err)) != 0, "a policy file that is not there");
	CHECK(strncmp(err, "policy-file: ", 13) == 0, "the error names the key: %s", err);
	free(cfg);
}

static void test_shipped_configs(void) {
	// Run from the repo root (ctest WORKING_DIRECTORY); try both locations.
	if (access("holywisp.conf.example", F_OK) == 0) load_shipped("holywisp.conf.example");
	if (access("deploy/holywisp.conf", F_OK) == 0) load_shipped("deploy/holywisp.conf");
}

int main(void) {
	RUN(test_inline_comments_and_quotes);
	RUN(test_bad_value_reports_line);
	RUN(test_webclient_url_validation);
	RUN(test_busy_poll_key);
	RUN(test_stop_on_stdin_eof_key);
	RUN(test_stream_credit_key);
	RUN(test_queue_and_head_keys);
	RUN(test_upload_credit_key);
	RUN(test_proxy_client_key_keys);
	RUN(test_warp_bypass_host_key);
	RUN(test_webtransport_keys);
	RUN(test_config_check);
	RUN(test_config_check_policy_file);
	RUN(test_dns_server_key);
	RUN(test_trusted_headers_reset_key);
	RUN(test_policy_file_keys);
	RUN(test_config_long_lines);
	RUN(test_shipped_configs);
	return 0;
}

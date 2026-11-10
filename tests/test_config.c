/*
 * Config parsing: inline comments, quoted values, flags, and that the shipped default configs
 * actually load (a broken default config would brick a fresh install).
 */
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
	RUN(test_shipped_configs);
	return 0;
}

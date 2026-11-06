/*
 * Config parsing: inline comments, quoted values, flags, and that the shipped default configs
 * actually load (a broken default config would brick a fresh install).
 */
#include "holywisp/server.h"

#include "server/config.h"
#include "test.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void write_file(const char *path, const char *content) {
	FILE *f = fopen(path, "w");
	CHECK(f != NULL, "open %s", path);
	fputs(content, f);
	fclose(f);
}

static void test_inline_comments_and_quotes(void) {
	char path[] = "/tmp/hw-cfg-XXXXXX";
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
	                 "motd =\n");
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
	unlink(path);
}

static void test_bad_value_reports_line(void) {
	char path[] = "/tmp/hw-cfg-XXXXXX";
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

// The configs we ship must load, or a fresh install will not start.
static void load_shipped(const char *path) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[256];
	CHECK(hw_config_load_file(&cfg, path, err, sizeof(err)) == 0, "%s: %s", path, err);
	CHECK(hw_server_config_validate(&cfg, err, sizeof(err)) == 0, "%s validate: %s", path, err);
}

static void test_shipped_configs(void) {
	// Run from the repo root (ctest WORKING_DIRECTORY); try both locations.
	if (access("holywisp.conf.example", F_OK) == 0) load_shipped("holywisp.conf.example");
	if (access("deploy/holywisp.conf", F_OK) == 0) load_shipped("deploy/holywisp.conf");
}

int main(void) {
	RUN(test_inline_comments_and_quotes);
	RUN(test_bad_value_reports_line);
	RUN(test_shipped_configs);
	return 0;
}

/*
 * server/config.h - config file and command line parsing for the holywisp binary.
 *
 * The file format is `key = value`, one per line, `#` comments. Keys match the long command-line
 * flags without the leading dashes. Flags override the file.
 */
#ifndef HOLYWISP_SERVER_CONFIG_H
#define HOLYWISP_SERVER_CONFIG_H

#include "holywisp/server.h"

// Apply one key/value. 0 on success, -1 with a message in err.
int hw_config_set(hw_server_config *cfg, const char *key, const char *value, char *err, size_t err_cap);
// Load a file; -1 with err describing the line that failed or the open error.
int hw_config_load_file(hw_server_config *cfg, const char *path, char *err, size_t err_cap);
// Load a policy-file into cfg's lists, on top of what they hold. It may hold only the keys that
// are lists an operator edits while the server runs (allow-host, block-host, allow-port,
// block-port, warp-bypass-host, allow-origin) in the config file's syntax, and every line must
// end within 1023 bytes. -1 with err naming the line at the first that does not: any other key, a
// bad value, a full list or a read error. cfg then holds part of the file, so the caller loads
// into a copy and throws it away. Nothing is checked across keys (hw_server_config_validate is).
int hw_config_load_policy(hw_server_config *cfg, const char *path, char *err, size_t err_cap);
// Parse argv. Returns 0 to continue, 1 when the process should exit successfully (help/version),
// -1 on a bad argument (err filled).
int hw_config_parse_args(hw_server_config *cfg, int argc, char **argv, char *err, size_t err_cap);
void hw_config_usage(const char *argv0);

#endif

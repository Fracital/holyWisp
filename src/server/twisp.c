/*
 * Twisp: terminal streams (PTY over Wisp), the same feature wispurr ships. A CONNECT with stream
 * type TERM carries a command line in the hostname field; it is split the way a shell splits a
 * line (quotes and backslashes, no variable or glob expansion) and run on a fresh pseudo-terminal.
 * The PTY master becomes the stream's fd, so stream.c relays it exactly like a TCP socket: EIO on
 * the master is the child exiting. The terminal and the process are the platform's (holywisp/sys.h).
 *
 * This is a remote-shell capability for an operator who runs the server. It is off by default
 * (enable-twisp) and conn.c reaches twisp_open() only for a Wisp v2 client that has authenticated
 * with a configured password. Those three gates are the whole access-control story and must stay
 * in place; see AGENTS.md.
 */
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/sys.h"
#include "holywisp/wisp.h"

#include "internal.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#define TWISP_MAX_ARGS 64

// Split a command line into argv. Single quotes are literal; double quotes allow backslash
// escapes; a bare backslash escapes the next character. Returns the count, or -1 on an unmatched
// quote. The storage for the strings is `store` (command is copied in), argv points into it.
static int shell_split(const char *command, size_t len, char *store, char **argv) {
	int argc = 0;
	size_t o = 0;
	int in_single = 0, in_double = 0, in_word = 0;
	for (size_t i = 0; i < len; i++) {
		char ch = command[i];
		if (ch == '\\' && !in_single) {
			if (i + 1 < len) ch = command[++i];
		} else if (ch == '\'' && !in_double) {
			in_single = !in_single;
			if (!in_word) {
				in_word = 1;
				if (argc >= TWISP_MAX_ARGS) return -1;
				argv[argc++] = store + o;
			}
			continue;
		} else if (ch == '"' && !in_single) {
			in_double = !in_double;
			if (!in_word) {
				in_word = 1;
				if (argc >= TWISP_MAX_ARGS) return -1;
				argv[argc++] = store + o;
			}
			continue;
		} else if ((ch == ' ' || ch == '\t') && !in_single && !in_double) {
			if (in_word) {
				store[o++] = '\0';
				in_word = 0;
			}
			continue;
		}
		if (!in_word) {
			in_word = 1;
			if (argc >= TWISP_MAX_ARGS) return -1;
			argv[argc++] = store + o;
		}
		store[o++] = ch;
	}
	if (in_single || in_double) return -1;
	if (in_word) store[o++] = '\0';
	argv[argc] = NULL;
	return argc;
}

void twisp_open(hw_conn *c, uint32_t id, const char *command, size_t len) {
	if (len == 0 || len > 4096) {
		conn_send_close(c, id, HW_CLOSE_INVALID_INFO);
		return;
	}
	char store[4097];
	char *argv[TWISP_MAX_ARGS + 1];
	int argc = shell_split(command, len, store, argv);
	if (argc <= 0) {
		conn_send_close(c, id, HW_CLOSE_INVALID_INFO);
		return;
	}

	int master;
	pid_t pid = hw_sys_pty_spawn(argv, &master);
	if (pid < 0) {
		HW_WARN("twisp", "%s: cannot start a terminal: %s", c->peer, strerror(errno));
		conn_send_close(c, id, HW_CLOSE_NETWORK_ERROR);
		return;
	}
	// The master side is the stream fd.
	hw_stream *s = stream_new(c, id, HW_STREAM_TERM, command, len, 0);
	if (!s) {
		close(master);
		hw_sys_pty_end(pid);
		return; // stream_new already sent CLOSE
	}
	s->pid = pid;
	HW_INFO("twisp", "%s: stream %u exec %s (pid %d)", c->peer, id, argv[0], (int)pid);
	stream_adopt(s, master);
}

void twisp_resize(hw_stream *s, uint16_t rows, uint16_t cols) {
	if (s->type != HW_STREAM_TERM || s->fd < 0) return;
	hw_sys_pty_resize(s->fd, rows, cols);
}

void twisp_kill(hw_stream *s) {
	if (s->pid <= 0) return;
	hw_sys_pty_end(s->pid);
	s->pid = 0;
}

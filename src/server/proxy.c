/*
 * Upstream proxy: SOCKS5 (RFC 1928, username/password RFC 1929) and HTTP CONNECT (RFC 7231
 * section 4.3.6), driven as a state machine on the stream's socket. The destination handed to the
 * proxy is the hostname the client asked for (SOCKS5 ATYP 3, CONNECT host:port), the way a
 * socks5h:// proxy expects it, so a classifying or geo-routing proxy can resolve the name itself.
 * The name was still resolved and policy-checked locally before the dial, so the egress rules
 * apply unchanged; only a literal IP in CONNECT is sent as an address.
 */
#include "holywisp/base64.h"
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/wisp.h"

#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

// ---------------------------------------------------------------------------------- config

int proxy_config_parse(const char *url, hw_proxy_config *out, char *err, size_t err_cap) {
	memset(out, 0, sizeof(*out));
	if (!url || !*url) return 0;
	const char *p;
	if (!strncmp(url, "socks5://", 9)) {
		out->kind = PROXY_SOCKS5;
		out->port = 1080;
		p = url + 9;
	} else if (!strncmp(url, "socks5h://", 10)) {
		out->kind = PROXY_SOCKS5;
		out->port = 1080;
		p = url + 10;
	} else if (!strncmp(url, "http://", 7)) {
		out->kind = PROXY_HTTP;
		out->port = 80;
		p = url + 7;
	} else if (!strncmp(url, "https://", 8)) {
		snprintf(err, err_cap, "proxy: https:// proxies need TLS, which this server does not speak");
		return -1;
	} else {
		snprintf(err, err_cap, "proxy: scheme must be socks5://, socks5h:// or http://");
		return -1;
	}
	if (strchr(p, '/') || strchr(p, '?') || strchr(p, '#')) {
		snprintf(err, err_cap, "proxy: URL may not have a path, query or fragment");
		return -1;
	}
	const char *at = strrchr(p, '@');
	if (at) {
		const char *colon = memchr(p, ':', (size_t)(at - p));
		size_t ul = colon ? (size_t)(colon - p) : (size_t)(at - p);
		size_t pl = colon ? (size_t)(at - colon - 1) : 0;
		if (ul == 0 || ul >= sizeof(out->user) || pl >= sizeof(out->pass)) {
			snprintf(err, err_cap, "proxy: bad credentials");
			return -1;
		}
		memcpy(out->user, p, ul);
		if (pl) memcpy(out->pass, colon + 1, pl);
		p = at + 1;
	}
	char hostport[320];
	if (strlen(p) >= sizeof(hostport)) {
		snprintf(err, err_cap, "proxy: host too long");
		return -1;
	}
	memcpy(hostport, p, strlen(p) + 1);
	char *host = hostport;
	char *port_str = NULL;
	if (host[0] == '[') {
		char *close = strchr(host, ']');
		if (!close) {
			snprintf(err, err_cap, "proxy: unbalanced [ ]");
			return -1;
		}
		*close = '\0';
		host++;
		if (close[1] == ':') port_str = close + 2;
	} else {
		char *colon = strrchr(host, ':');
		if (colon) {
			*colon = '\0';
			port_str = colon + 1;
		}
	}
	if (!*host || strlen(host) >= sizeof(out->host)) {
		snprintf(err, err_cap, "proxy: missing host");
		return -1;
	}
	memcpy(out->host, host, strlen(host) + 1);
	if (port_str) {
		char *end;
		long n = strtol(port_str, &end, 10);
		if (end == port_str || *end || n < 1 || n > 65535) {
			snprintf(err, err_cap, "proxy: bad port");
			return -1;
		}
		out->port = (uint16_t)n;
	}
	return 0;
}

int proxy_config_resolve(hw_proxy_config *p) {
	if (p->kind == PROXY_NONE) return 0;
	socklen_t sl;
	if (hw_addr_parse(p->host, p->port, &p->addr, &sl) == 1) {
		p->addr_len = sl;
		return 0;
	}
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	char service[8];
	snprintf(service, sizeof(service), "%u", p->port);
	struct addrinfo *res = NULL;
	if (getaddrinfo(p->host, service, &hints, &res) != 0 || !res) {
		errno = EHOSTUNREACH;
		return -1;
	}
	memcpy(&p->addr, res->ai_addr, res->ai_addrlen);
	p->addr_len = res->ai_addrlen;
	freeaddrinfo(res);
	return 0;
}

// ---------------------------------------------------------------------------------- handshake

static int proxy_send(hw_stream *s, const uint8_t *data, size_t len) {
	// The handshake is a handful of bytes on a fresh socket: a short write here is an error, not
	// something worth a queue.
	ssize_t n = send(s->fd, data, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (n != (ssize_t)len) {
		stream_close(s, HW_CLOSE_NETWORK_ERROR, 1);
		return -1;
	}
	return 0;
}

static void proxy_fail(hw_stream *s, const char *why, uint8_t reason) {
	HW_DEBUG("proxy", "%s: stream %u: %s", s->conn->peer, s->id, why);
	stream_close(s, reason, 1);
}

// The destination address the stream is currently trying, as a sockaddr.
static const struct sockaddr *target_addr(const hw_stream *s) {
	return (const struct sockaddr *)&s->addrs[s->addr_idx - 1];
}

// "host:port" for an HTTP CONNECT line: the name as the client gave it, or the literal address.
static void target_str(const hw_stream *s, char *buf, size_t cap) {
	if (s->literal_host) {
		hw_addr_str(target_addr(s), buf, cap);
	} else {
		snprintf(buf, cap, "%s:%u", s->host, s->port);
	}
}

static int socks5_send_connect(hw_stream *s) {
	uint8_t req[4 + 1 + 255 + 2];
	size_t n = 0;
	req[n++] = 5;
	req[n++] = 1; // CONNECT
	req[n++] = 0;
	const struct sockaddr *sa = target_addr(s);
	if (!s->literal_host) {
		size_t hl = strlen(s->host); // handle_connect capped it at 255
		req[n++] = 3;
		req[n++] = (uint8_t)hl;
		memcpy(req + n, s->host, hl);
		n += hl;
	} else if (sa->sa_family == AF_INET) {
		req[n++] = 1;
		memcpy(req + n, &((const struct sockaddr_in *)sa)->sin_addr, 4);
		n += 4;
	} else {
		req[n++] = 4;
		memcpy(req + n, &((const struct sockaddr_in6 *)sa)->sin6_addr, 16);
		n += 16;
	}
	req[n++] = (uint8_t)(s->port >> 8);
	req[n++] = (uint8_t)s->port;
	s->proxy_phase = PROXY_PHASE_CONNECT;
	return proxy_send(s, req, n);
}

int proxy_start(hw_stream *s) {
	const hw_proxy_config *p = &s->conn->w->server->proxy;
	hw_buf_clear(&s->pin);
	if (p->kind == PROXY_SOCKS5) {
		uint8_t greet[4] = {5, 1, 0, 0};
		size_t n = 3;
		if (p->user[0]) {
			greet[1] = 2;
			greet[3] = 2; // also offer username/password
			n = 4;
		}
		s->proxy_phase = PROXY_PHASE_GREETING;
		return proxy_send(s, greet, n);
	}
	// HTTP CONNECT host:port
	char dest[sizeof(s->host) + 8];
	target_str(s, dest, sizeof(dest));
	char auth[512] = "";
	if (p->user[0]) {
		char cred[260];
		int cl = snprintf(cred, sizeof(cred), "%s:%s", p->user, p->pass);
		char b64[HW_BASE64_LEN(sizeof(cred))];
		hw_base64_encode((const uint8_t *)cred, (size_t)cl, b64, sizeof(b64));
		snprintf(auth, sizeof(auth), "Proxy-Authorization: Basic %s\r\n", b64);
	}
	char req[1024];
	int n = snprintf(req, sizeof(req),
	                 "CONNECT %s HTTP/1.1\r\n"
	                 "Host: %s\r\n"
	                 "Proxy-Connection: Keep-Alive\r\n"
	                 "%s"
	                 "\r\n",
	                 dest, dest, auth);
	s->proxy_phase = PROXY_PHASE_CONNECT;
	return proxy_send(s, (const uint8_t *)req, (size_t)n);
}

static int socks5_reply_len(const uint8_t *d, size_t len) {
	if (len < 5) return 0;
	switch (d[3]) {
	case 1:
		return 10;
	case 4:
		return 22;
	case 3:
		return 7 + d[4];
	default:
		return -1;
	}
}

static uint8_t socks5_reason(uint8_t rep) {
	switch (rep) {
	case 3:
	case 4:
		return HW_CLOSE_UNREACHABLE;
	case 5:
		return HW_CLOSE_REFUSED;
	case 6:
		return HW_CLOSE_NO_RESPONSE;
	case 2:
		return HW_CLOSE_BLOCKED;
	default:
		return HW_CLOSE_NETWORK_ERROR;
	}
}

// Returns 1 when the handshake finished and `consumed` bytes of pin belong to it, 0 for more.
static int socks5_step(hw_stream *s, size_t *consumed) {
	const hw_proxy_config *p = &s->conn->w->server->proxy;
	const uint8_t *d = hw_buf_head(&s->pin);
	size_t len = hw_buf_avail(&s->pin);
	*consumed = 0;
	switch (s->proxy_phase) {
	case PROXY_PHASE_GREETING: {
		if (len < 2) return 0;
		if (d[0] != 5) {
			proxy_fail(s, "socks5: bad version", HW_CLOSE_NETWORK_ERROR);
			return -1;
		}
		*consumed = 2;
		if (d[1] == 0) return socks5_send_connect(s) == 0 ? 0 : -1;
		if (d[1] == 2 && p->user[0]) {
			uint8_t req[1 + 1 + 127 + 1 + 127];
			size_t ul = strlen(p->user), pl = strlen(p->pass);
			size_t n = 0;
			req[n++] = 1;
			req[n++] = (uint8_t)ul;
			memcpy(req + n, p->user, ul);
			n += ul;
			req[n++] = (uint8_t)pl;
			memcpy(req + n, p->pass, pl);
			n += pl;
			s->proxy_phase = PROXY_PHASE_AUTH;
			return proxy_send(s, req, n) == 0 ? 0 : -1;
		}
		proxy_fail(s, "socks5: no acceptable auth method", HW_CLOSE_BLOCKED);
		return -1;
	}
	case PROXY_PHASE_AUTH:
		if (len < 2) return 0;
		*consumed = 2;
		if (d[1] != 0) {
			proxy_fail(s, "socks5: authentication rejected", HW_CLOSE_BLOCKED);
			return -1;
		}
		return socks5_send_connect(s) == 0 ? 0 : -1;
	case PROXY_PHASE_CONNECT: {
		int need = socks5_reply_len(d, len);
		if (need < 0) {
			proxy_fail(s, "socks5: bad reply address type", HW_CLOSE_NETWORK_ERROR);
			return -1;
		}
		if (need == 0 || len < (size_t)need) return 0;
		*consumed = (size_t)need;
		if (d[1] != 0) {
			char why[48];
			snprintf(why, sizeof(why), "socks5: connect failed (rep %u)", d[1]);
			proxy_fail(s, why, socks5_reason(d[1]));
			return -1;
		}
		return 1;
	}
	}
	return -1;
}

static int http_step(hw_stream *s, size_t *consumed) {
	const uint8_t *d = hw_buf_head(&s->pin);
	size_t len = hw_buf_avail(&s->pin);
	*consumed = 0;
	size_t head = 0;
	for (size_t i = 3; i < len; i++) {
		if (d[i - 3] == '\r' && d[i - 2] == '\n' && d[i - 1] == '\r' && d[i] == '\n') {
			head = i + 1;
			break;
		}
	}
	if (!head) {
		if (len > 8192) {
			proxy_fail(s, "http proxy: response head too large", HW_CLOSE_NETWORK_ERROR);
			return -1;
		}
		return 0;
	}
	*consumed = head;
	if (len < 12 || memcmp(d, "HTTP/1.", 7) != 0) {
		proxy_fail(s, "http proxy: not an HTTP response", HW_CLOSE_NETWORK_ERROR);
		return -1;
	}
	int status = (int)strtol((const char *)d + 9, NULL, 10);
	if (status < 200 || status > 299) {
		char why[48];
		snprintf(why, sizeof(why), "http proxy: CONNECT returned %d", status);
		proxy_fail(s, why, status == 407 || status == 403 ? HW_CLOSE_BLOCKED : HW_CLOSE_UNREACHABLE);
		return -1;
	}
	return 1;
}

int proxy_on_data(hw_stream *s, const uint8_t *data, size_t len) {
	hw_conn *c = s->conn;
	if (hw_buf_append(&s->pin, data, len) != 0) {
		stream_close(s, HW_CLOSE_UNKNOWN, 1);
		return -1;
	}
	for (;;) {
		size_t consumed = 0;
		int r = c->w->server->proxy.kind == PROXY_SOCKS5 ? socks5_step(s, &consumed) : http_step(s, &consumed);
		if (r < 0) return -1;
		hw_buf_consume(&s->pin, consumed);
		if (r == 1) {
			// Whatever follows the handshake is already payload from the destination.
			size_t rest = hw_buf_avail(&s->pin);
			stream_connected(s);
			if (c->closing || s->state != STREAM_OPEN) return -1;
			if (rest > 0) {
				conn_send_data(c, s->id, hw_buf_head(&s->pin), rest);
				if (c->closing) return -1;
			}
			hw_buf_clear(&s->pin);
			return 1;
		}
		if (consumed == 0) return 0;
	}
}

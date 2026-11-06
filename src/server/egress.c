/*
 * Egress policy: which remote addresses a stream may be opened to. Default deny for anything that
 * is not a public unicast address, so a Wisp server on a LAN does not become a door into it.
 */
#include "internal.h"

int egress_allowed(const hw_server_config *cfg, const struct sockaddr *sa, enum hw_addr_class *why) {
	enum hw_addr_class c = hw_addr_classify(sa);
	if (why) *why = c;
	switch (c) {
	case HW_ADDR_PUBLIC:
		return 0;
	case HW_ADDR_LOOPBACK:
		return cfg->allow_loopback ? 0 : -1;
	case HW_ADDR_PRIVATE:
		return cfg->allow_private ? 0 : -1;
	case HW_ADDR_LINK_LOCAL:
		return cfg->allow_link_local ? 0 : -1;
	case HW_ADDR_UNSPECIFIED:
	case HW_ADDR_MULTICAST:
	case HW_ADDR_RESERVED:
		return -1;
	}
	return -1;
}

#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>

#include "hardware.h"

int nl_init_80211(int if_index, nl80211_t *ret){
	int nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	// Form request for family ID
	// Send and parse response
	// Fill out ret on success
	// On fail close socket ret 0;
}
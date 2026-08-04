#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>

#include "hardware.h"

int nl_genetlink_socket(){
	return socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
}

int nl_ismonitor(int nlfd){

}

int nl_setmonitor(int nlfd){

}

int nl_setchannel(int nlfd){

}

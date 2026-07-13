#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcnlt.h>
#include <pthread.h>

#include "network.h"
#include "data.h"

#define RADIOTAPTSFT       0x80
#define RADIOTAPFLAGS      0x40
#define RADIOTAPRATE       0x20
#define RADIOTAPCHANNEL    0x10
#define RADIOTAPFHSS       0x08
#define RADIOTAPSIGNAL     0x04

#define RADIOTAPPRESENT    0x02

int openbindraw(char *if_name){
	int if_index = if_nametoindex(if_name);
	if(!if_index){
		return -1;
	}

	int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(fd == -1){
		return -1;
	}

	struct sockaddr_ll sa = {0};
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = if_index;
	if(bind(fd, (sockaddr *)&sa, sizeof(sa)) == -1){
		close(fd);
		return -1;
	}

	int flags = fcntl(fd, F_GETFL);
	if(flags == -1){
		close(fd);
		return -1;
	}
	if(fcntl(fd, F_SETFL, (flags | O_NONBLOCK)) == -1){
		close(fd);
		return -1;
	}

	return fd;
}

int ismonitor(int fd, char *if_name){
	struct iwreq iwr = {0};
	strncpy(iwr.ifr_ifrn.ifrn_name, if_name, IFNAMSIZ);

	if(ioctl(fd, SIOCGIWMODE, &iwr) == -1){
		return -1;
	}

	if(iwr.u.mode == IW_MODE_MONITOR){
		return 1;
	}

	return 0;
}

int setmonitor(int fd, char *if_name){
	struct iwreq iwr = {0};
	struct ifreq ifr = {0};

	strncpy(iwr.ifr_ifrn.ifrn_name, if_name, IFNAMSIZ);
	strncpy(ifr.ifr_ifrn.ifrn_name, if_name, IFNAMSIZ);

	if(ioctl(fd, SIOCGIFFLAGS, &ifr) == -1){
		return -1;
	}

	ifr.ifr_flags &= ~IFF_UP;
	if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1){
		return -1;
	}

	ifr.ifr_flags |= IFF_UP;

	iwr.u.mode = IW_MODE_MONITOR;
	if(ioctl(fd, SIOCSIWMODE, &iwr) == -1){
		ioctl(fd, SIOCSIFFLAGS, &ifr)
		return -1;
	}

	if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1){
		return -1;
	}

	return 0;
}

int setchannel(int fd, char *if_name, Channels *channels){
	pthread_mutex_lock(channels->lock);

	if(channels->number_nodes == 1){
		return 0;
	}

	struct iwreq iwr = {0};
	strncpy(iwr.ifr_ifrn.ifrn_name, if_name, IFNAMSIZ);
	memcpy(iwr.u.freq, channels->current->freq, sizeof(struct iw_freq));

	if(ioctl(fd, SIOCSIWFREQ, &iwr) == -1){
		return -1;
	}
	channels->current = channels->current->next;
	pthread_mutex_unlock(channels->lock);

	return 0;
}

int rtpalign(int offset, int align){
	return offset + (offset % align);
}

int radiotap(uint8_t *buffer, Radiotap *rtp){
	memcpy(rtp->header_len, buffer[2], sizeof(uint16_t));
	int num_words = 0;
	int offset;
	while(buffer[7 + (num_words * 4)] & RADIOTAPPRESENT){
		num_words++;
	}
	num_words++;

	offset = 4 + (4 * num_words);
	if(buffer[4] & (RADIOTAPCHANNEL | RADIOTAPSIGNAL) != (RADIOTAPCHANNEL | RADIOTAPSIGNAL)){
		return 0;
	}

	if(buffer[4] & RADIOTAPTSFT){
		offset += 8;
	}
	if(buffer[4] & RADIOTAPFLAGS){
		offset += 1;
	}
	if(buffer[4] & RADIOTAPRATE){
		offset += 1;
	}
	if(buffer[4] & RADIOTAPCHANNEL){
		offset = rtpalign(offset, 2);
		memcpy(rtp->freq, buffer[offset], sizeof(uint16_t));
		offset += 4;
	}
	if(buffer[4] & RADIOTAPFHSS){
		offset += 2;
	}
	if(buffer[4] & RADIOTAPSIGNAL){
		rtp->dbm = buffer[offset];
		offset += 1;
	}

	return 1;
}

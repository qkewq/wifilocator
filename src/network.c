#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <net/if.h>
#include <linux/wireless.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>

#include "network.h"
#include "data.h"

typedef enum Radiotapword{
	RTPTSFT = 0x80,
	RTPFLAGS = 0x40,
	RTPRATE = 0x20,
	RTPCHANNEL = 0x10,
	RTPFHSS = 0x08,
	RTPSIGNAL = 0x04,
	RTPPRESENT = 0x02,
} Radiotapword;

typedef enum Frametypes{
	MANAGEMENT = 0x00,
	CONTROL = 0x01,
	DATA = 0x02,
} Frametypes;

typedef enum Controlframes{
	CON_CTS = 0x0C,
	CON_ACK = 0x0D,
	CON_WRAP = 0x07,
} Controlframes;

uint8_t channel_nums[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,32,36,40,44,48,52,56,60,64,68,
	72,76,80,84,88,92,96,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165,169,173,177,
};

uint16_t channel_freq[] = {2412,2417,2422,2427,2432,2437,2442,2447,2452,2457,2462,2467,2472,
	2484,5160,5180,5200,5220,5240,5260,5280,5300,5320,5340,5360,5380,5400,5420,5440,5460,5480,5500,
	5520,5540,5560,5580,5600,5620,5640,5660,5680,5700,5720,5745,5765,5785,5805,5825,5845,5865,5885,
};

uint8_t freqtochannel(uint16_t freq){
	for(int i = 0; i < sizeof(channel_freq) / sizeof(uint16_t); i++){
		if(channel_freq[i] == freq){
			return channel_nums[i];
		}
	}

	return 0;
}

uint16_t channeltofreq(uint8_t channel){
	for(int i = 0; i < sizeof(channel_nums) / sizeof(uint8_t); i++){
		if(channel_nums[i] == channel){
			return channel_freq[i];
		}
	}

	return 0;
}

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
	if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1){
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
		ioctl(fd, SIOCSIFFLAGS, &ifr);
		return -1;
	}

	if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1){
		return -1;
	}

	return 0;
}

int setchannel(int fd, char *if_name, Channels *channels){
	pthread_mutex_lock(&channels->lock);

	if(channels->number_nodes == 1){
		pthread_mutex_unlock(&channels->lock);
		return 0;
	}

	struct iwreq iwr = {0};
	strncpy(iwr.ifr_ifrn.ifrn_name, if_name, IFNAMSIZ);
	channels->current_index = (channels->current_index + 1 ) % channels->number_nodes;
	memcpy(&iwr.u.freq, &channels->channels[channels->current_index], sizeof(struct iw_freq));

	if(ioctl(fd, SIOCSIWFREQ, &iwr) == -1){
		pthread_mutex_unlock(&channels->lock);
		return -1;
	}

	pthread_mutex_unlock(&channels->lock);

	return 0;
}

int rtpalign(int offset, int align){
	return offset + (offset % align);
}

int radiotap(uint8_t *buffer, Radiotap *rtp){
	memcpy(&rtp->header_len, &buffer[2], sizeof(uint16_t));
	int num_words = 0;
	int offset;
	while(buffer[7 + (num_words * 4)] & RTPPRESENT){
		num_words++;
	}
	num_words++;

	offset = 4 + (4 * num_words);
	if(buffer[4] & (RTPCHANNEL | RTPSIGNAL) != (RTPCHANNEL)){
		return 0;
	}

	if(buffer[4] & RTPTSFT){
		offset += 8;
	}
	if(buffer[4] & RTPFLAGS){
		offset += 1;
	}
	if(buffer[4] & RTPRATE){
		offset += 1;
	}
	if(buffer[4] & RTPCHANNEL){
		offset = rtpalign(offset, 2);
		memcpy(&rtp->freq, &buffer[offset], sizeof(uint16_t));
		offset += 4;
	}
	if(buffer[4] & RTPFHSS){
		offset += 2;
	}
	if(buffer[4] & RTPSIGNAL){
		rtp->dbm = buffer[offset];
		offset += 1;
	}

	return 1;
}

int txpresent(uint8_t type){
	switch(type & 0x30){
		case MANAGEMENT:
		case DATA:
			return 1;
		case CONTROL:
			switch(type & 0x0F){
				case CON_CTS:
				case CON_ACK:
				case CON_WRAP:
					return 0;
				default:
					return 1;
			}
	}

	return 0;
}

int isdevbssid(uint8_t *buffer){
	switch(buffer[0] | 0x30){
		case DATA:
			return buffer[1] & 0x40; // From DS bit
		case MANAGEMENT:
			if(memcmp(&buffer[10], &buffer[16], 6) == 0){
				return 1;
			}
			else{
				return 0;
			}
		case CONTROL:
			return -1; // Can't determine direction from control frames
	}

	return -1;
}

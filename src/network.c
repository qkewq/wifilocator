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
#include "vector.h"

#define RSN_IE            48
#define WPA_IE            221
#define CHANNEL_REPORT_IE 51

typedef enum Radiotapword{
	RTPTSFT = 0x01,
	RTPFLAGS = 0x02,
	RTPRATE = 0x04,
	RTPCHANNEL = 0x08,
	RTPFHSS = 0x10,
	RTPSIGNAL = 0x20,
	RTPPRESENT = 0x080,
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
	if(channels->number_nodes == 1){
		return 0;
	}

	// pthread_mutex_lock(&channels->lock);

	struct iwreq iwr = {0};
	strncpy(iwr.ifr_ifrn.ifrn_name, if_name, IFNAMSIZ);
	channels->current_index = (channels->current_index + 1 ) % channels->number_nodes;
	memcpy(&iwr.u.freq, &channels->channels[channels->current_index], sizeof(struct iw_freq));

	if(ioctl(fd, SIOCSIWFREQ, &iwr) == -1){
		// pthread_mutex_unlock(&channels->lock);
		return -1;
	}

	// pthread_mutex_unlock(&channels->lock);

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
	if(buffer[4] & (RTPCHANNEL | RTPSIGNAL) != (RTPCHANNEL | RTPSIGNAL)){
		return 0;
	}

	if(buffer[4] & RTPTSFT){
		offset = rtpalign(offset, 8);
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
	switch(type & 0x0C >> 2){
		case MANAGEMENT:
		case DATA:
			return 1;
		case CONTROL:
			switch(type & 0xF0 >> 4){
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
	switch(buffer[0] & 0x0C >> 2){
		case DATA:
			return buffer[1] & 0x02 >> 1; // From DS bit
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

int isprobe(uint8_t type){
	if(((type & 0x0C) >> 2) == MANAGEMENT && ((type & 0xF0) >> 4 == 0x04)){
		return 1;
	}

	return 0;
}

int isbeacon(uint8_t type){
	if(((type & 0x0C) >> 2) == MANAGEMENT && ((type & 0xF0) >> 4 == 0x08)){
		return 1;
	}

	return 0;
}

int getssid(uint8_t *buffer, int *ssid_offset, uint8_t *ssid_len){
	int offset = 24;
	if(buffer[1] & 0x80){
		offset += 4;
	}
	if((buffer[0] & 0x0F) >> 4 == 0x08){
		offset += 12;
	}

	if(buffer[offset] != 0x00){
		*ssid_offset = 0;
		return 0;
	}

	*ssid_offset = offset + 2;
	*ssid_len = buffer[offset + 1];
	return 1;
}

Protocols parse_rsn_ie(uint8_t *buffer){
	Protocols ret = UNKNOWN;
	int offset = 8;
	offset += ((buffer[offset] << 8) + buffer[offset + 1]) * 4;
	offset += 2;
	uint16_t akm_count = (buffer[offset] << 8) + buffer[offset + 1];
	offset += 2;
	uint8_t oui[3] = {0x00, 0x0F, 0xAC};
	for(int i = 0; i < akm_count; i++){
		if(memcmp(&buffer[offset + (i * 4)], &oui, 3) == 0){
			switch(buffer[offset + (i * 4) - 1]){
				case 0x01:
					if(ret == WPA3E){
						return WPA3E_T;
					}
					ret = WPA2E;
					break;
				case 0x02:
					if(ret == WPA3P){
						return WPA3P_T;
					}
					ret = WPA2P;
					break;
				case 0x05:
					if(ret == WPA2E){
						return WPA3E_T;
					}
					ret = WPA3E;
					break;
				case 0x08:
					if(ret == WPA2P){
						return WPA3P_T;
					}
					ret = WPA3P;
					break;
			}
		}
	}

	return ret;
}

Protocols parse_wpa_ie(uint8_t *buffer){
	int offset = 12;
	offset += buffer[offset] * 4;
	offset += 1;
	uint8_t akm_count = buffer[offset];
	offset += 1;
	uint8_t oui[3] = {0x00, 0x50, 0xF2};
	for(int i = 0; i < akm_count; i++){
		if(memcmp(&buffer[offset + (i * 4)], &oui, 3) == 0){
			switch(buffer[offset + (i * 4) - 1]){
				case 0x01:
					return WPAE;
				case 0x02:
					return WPAP;
			}
		}
	}

	return UNKNOWN;
}

Protocols getprotocol(uint8_t *buffer, size_t len){
	int offset = 34;
	int privacy_bit = 0;
	int rsn_offset = 0;
	int wpa_offset = 0;
	uint8_t wpa_type[4] = {0x00, 0x50, 0xF2, 0x01};
	if(buffer[1] & 0x80){
		offset += 4;
	}

	privacy_bit = buffer[offset + 1] & 0x10;
	offset += 2;
	if(!privacy_bit){
		return OPEN;
	}

	while(offset < len){
		if(buffer[offset] != RSN_IE || buffer[offset] != WPA_IE){
			offset += buffer[offset + 1] + 2;
			continue;
		}

		if(buffer[offset] == RSN_IE){
			rsn_offset = offset;
		}

		if(buffer[offset] == WPA_IE){
			if(memcmp(&buffer[offset + 2], &wpa_type, 4) == 0){
				wpa_offset = offset;
			}
		}

		offset += buffer[offset + 1] + 2;
	}

	if(privacy_bit && !rsn_offset && !wpa_offset){
		return WEP;
	}

	Protocols ret = UNKNOWN;
	if(rsn_offset){
		ret = parse_rsn_ie(&buffer[rsn_offset]);
	}
	if(wpa_offset){
		ret = parse_wpa_ie(&buffer[wpa_offset]);
	}

	return ret;
}

int getchannels(uint8_t *buffer, Vector *channels, size_t len){
	int offset = 34;
	if(buffer[1] & 0x80){
		offset += 4;
	}

	uint8_t present[255] = {0};
	while(offset < len){
		if(buffer[offset] != CHANNEL_REPORT_IE){
			offset += buffer[offset + 1] + 2;
			continue;
		}
		for(int i = 0; i < buffer[offset + 1] - 1; i++){
			uint8_t channel = buffer[offset + 3 + i];
			if(present[channel]){
				continue;
			}
			present[channel] = 1;
			if(!vecappend(channels, &channel)){
				return 0;
			}
		}
		offset += buffer[offset + 1] + 2;
	}

	if(!vecoptimize(channels)){
		return 0;
	}

	return 1;
}

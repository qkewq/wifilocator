#ifndef NETWORK_H
#define NETWORK_H

typedef struct Radiotap{
	uint16_t header_len;
	uint16_t freq;
	int8_t dbm;
} Radiotap;

typedef struct Channels Channels;

uint8_t freqtochannel(uint16_t freq);
uint16_t channeltofreq(uint8_t channel);
int openbindraw(char *if_name);
int ismonitor(int fd, char *if_name);
int setmonitor(int fd, char *if_name);
int setchannel(int fd, char *if_name, Channels *channels);
int radiotap(uint8_t *buffer, Radiotap *rtp);
int txpresent(uint8_t type);
int isdevbssid(uint8_t *buffer);

#endif

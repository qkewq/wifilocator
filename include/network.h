#ifndef NETWORK_H
#define NETWORK_H

typedef struct Radiotap{
	uint16_t header_len;
	uint16_t freq;
	int8_t dbm;
} Radiotap;

int openbindraw(char *if_name);
int ismonitor(int fd, char *if_name);
int setmonitor(int fd, char *if_name);
int setchannel(int fd, char *if_name, Channels *channels);
int radiotap(uint8_t *buffer, Radiotap *rtp);

#endif

#ifndef NETWORK_H
#define NETWORK_H

#define SSIDMAX 32

typedef struct Radiotap{
	uint16_t header_len;
	uint16_t freq;
	int8_t dbm;
} Radiotap;

typedef struct Channels Channels;
typedef enum Protocols Protocols;
typedef struct Vector Vector;

uint8_t freqtochannel(uint16_t freq);
uint16_t channeltofreq(uint8_t channel);
int openbindraw(char *if_name);
int ismonitor(int fd, char *if_name);
int setmonitor(int fd, char *if_name);
int setchannel(int fd, char *if_name, Channels *channels);
int radiotap(uint8_t *buffer, Radiotap *rtp);
int txpresent(uint8_t type);
int isdevbssid(uint8_t *buffer);
int isprobe(uint8_t type);
int isbeacon(uint8_t type);
int getssid(uint8_t *buffer, int *ssid_offset, uint8_t *ssid_len);
Protocols getprotocol(uint8_t *buffer, size_t len);
int getchannels(uint8_t *buffer, Vector *channels, size_t len);

#endif

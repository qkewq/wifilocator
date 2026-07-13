#ifndef DATA_H
#define DATA_H

#include <linux/wireless.h> // For struct iw_freq

/* ---- CHANNELS ---- */

typedef struct Channels{
	pthread_mutex_t lock;
	size_t number_nodes;
	size_t current_index;
	struct iw_freq channels[IW_MAX_FREQUENCIES];
} Channels;

/* ---- DEVICES ---- */

typedef struct Device{
	uint8_t mac[6];
	char *org;
	uint8_t isbssid;
	size_t num_frames;
	time_t last_frame;
	uint8_t channel;
	int8_t last_dbm;
} Device;

typedef struct Devices{
	pthread_mutex_t lock;
	struct Vector *device;
} Devices;

/* ---- NETWORKS ---- */

typedef struct Ssidmapnode{
	struct Ssidmapnode *next;
	char *ssid;
	struct Network *network;
} Ssidmapnode;

typedef struct Ssidmap{
	size_t mapsize;
	Ssidmapnode **map;
} Ssidmap;

typedef struct Network{
	struct Network *next;
	char *ssid;
	// cipher & security
	// bssids
	// channels
} Network;

typedef struct Networks{
	pthread_mutex_t lock;
	size_t number_nodes;
	struct Network *head;
	struct Ssidmap map;
} Networks;

/* ---- PROBES ---- */

typedef struct Probe{
	// networks being probed for not including wildcards
	struct Probe next;
	uint8_t mac[6];
	char *org;

} Probe;

typedef struct Probes{
	pthread_mutex_t lock;
	size_t number_nodes;
	struct Probe *head;
} Probes;

/* ---- HEAD ---- */

typedef struct Scannerdata{
	int fd;
	char if_name[IFNAMSIZ];
	struct Channels *channels;
	struct Devices devices;
	struct Networks networks;
	struct Probes probes;
	struct Ouimap *ouimap;
} Scannerdata;

int buildChannels(Arguments *args, int fd, Channels **ret);
int builddata(int fd, char *if_name, Channels *channels, Ouimap *ouimap, Scannerdata **ret);

#endif

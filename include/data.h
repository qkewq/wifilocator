#ifndef DATA_H
#define DATA_H

#include <linux/wireless.h> // For struct iw_freq
#include <stdint.h> // For int types
#include <stdatomic.h> // For atomic_size_t

#define SSIDMAXTERM 33

typedef struct Arguments Arguments;
typedef struct Ouimap Ouimap;

typedef struct Addrworg{
	uint8_t mac[6];
	char *org; // Points to char in ouimap, nullable
} Addrworg;

/* ---- CHANNELS ---- */

typedef struct Channels{
	pthread_mutex_t lock;
	size_t number_nodes;
	// size_t current_index;
	atomic_size_t current_index;
	struct iw_freq channels[IW_MAX_FREQUENCIES];
} Channels;

/* ---- DEVICES ---- */

typedef struct Device{
	struct Addrworg addr;
	size_t num_frames;
	time_t last_frame;
	int8_t isbssid;
	uint8_t channel;
	int8_t last_dbm;
} Device;

typedef struct Devices{
	pthread_mutex_t lock;
	struct Vector *device; // Vector with type struct Device
} Devices;

/* ---- NETWORKS ---- */

typedef enum Protocols{
	UNKNOWN = 0x00,
	OPEN,
	WEP,
	WPAP,
	WPAE,
	WPA2P,
	WPA2E,
	WPA3P,
	WPA3E,
	WPA3P_T,
	WPA3E_T,
} Protocols;

typedef struct Network{
	char ssid[SSIDMAXTERM];
	enum Protocols protocol;
	time_t last_seen;
	struct Vector *bssids; // Vector with type Addrworg
	struct Vector *channels; // Vector with type uint8_t
} Network;

typedef struct Networks{
	pthread_mutex_t lock;
	struct Vector *network; // Vector with type struct Network
} Networks;

/* ---- PROBES ---- */

typedef struct Request{
	char ssid[SSIDMAXTERM];
	size_t num_requests;
} Request;

typedef struct Probe{
	struct Addrworg addr;
	struct Vector *requests; // Vector with type Request
} Probe;

typedef struct Probes{
	pthread_mutex_t lock;
	struct Vector *probe; // Vector with type struct Probe
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
void makeaddrworg(Addrworg *addrworg, uint8_t *addr, Ouimap *ouimap);
void datafree(Scannerdata *data);

#endif

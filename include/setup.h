#ifndef SETUP_H
#define SETUP_H

#define ARGSTRING "hmi:b:c:"

typedef enum Bands{
	bandno,
	band2g,
	band5g,
	bandall,
} Bands;

typedef struct Arguments{
	char if_name[IFNAMSIZ];
	uint8_t setmon;
	uint8_t help;
	Bands band;
	struct iw_freq freq;
} Arguments;

int getargs(Arguments *args, int argc, char *argv);
// terminal stuff
// signal handler

#endif

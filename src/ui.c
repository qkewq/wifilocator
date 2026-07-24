#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>

#include "ui.h"
#include "uidata.h"
#include "vector.h"
#include "data.h"


int rssi_index = -1;

typedef enum Userinput{
	UNKNOWN,
	UP_ARROW,
	DOWN_ARROW,
	LEFT_Q,
	RIGHT_E,
	ENTER,
} Userinput;

Userinput getinput(){
	char buffer[16] = {0};
	int ret = read(STDIN_FILENO, buffer, sizeof(buffer) / sizeof(char));
	if(!ret){
		return UNKNOWN;
	}

	switch(buffer[0]){
		case 'q':
		case 'Q':
			return LEFT_Q;
		case 'e':
		case 'E':
			return RIGHT_E;
		case '\n':
			return ENTER;
		case '\e':
			if(ret >= 3 && memcmp(buffer, "\e[A", 3) == 0){
				return UP_ARROW;
			}
			else if(ret >= 3 && memcmp(buffer, "\e[B", 3) == 0){
				return DOWN_ARROW;
			}
		default:
			return UNKNOWN;
	}
}

int drawheader(int current){
	char *titles[NUMPAGES] = {"NETWORKS",
							"DEVICES",
							"RSSI",
							"PROBES",
	};
	printf(HOME NORMAL CLEAR"<Q");
	for(int i = 0; i < NUMPAGES; i++){
		if(i == current){
			printf(HIGHLIGHT" %s "NORMAL, titles[i]);
			continue;
		}
		printf(" %s ", titles[i]);
	}
	printf("E>\n");

	return 0;
}

int drawchannels(Channels *channels){
	printf("Channels:" RED);
	int current = channels->current_index;
	for(int i = 0; i < channels->number_nodes; i++){
		if(i == current){
			printf(GREEN" %d "RED, channels->channels[i].i);
			continue;
		}
		printf(" %d ", channels->channels[i].i);
	}

	printf(NORMAL"\n");
	return 0;
}

int devicepage(struct pollfd *pfd, Scannerdata *data, int current){
	int selected = 0;
	int start = 0;
	int readyfd = 0;
	drawheader(current);
	printf("\n");
	while(1){
		printf("\e[3;0H\r");
		readyfd = poll(pfd, 1, 1000 / APROXFRAMERATE);
		if(readyfd == -1){
			return -1;
		}
		if(readyfd > 0){
			// Userinput uin = getinput();
			switch(getinput()){
				case ENTER:
					rssi_index = selected;
					return 2;
				case LEFT_Q:
					return (current - 1) % NUMPAGES;
				case RIGHT_E:
					return (current + 1) % NUMPAGES;
				case UP_ARROW:
					selected--;
					break;
				case DOWN_ARROW:
					selected++;
					break;
				default:
					continue;
			}
		}

		drawchannels(data->channels);
		if(drawdevices(&data->devices, &selected, &start) == -1){
			return -1;
		}
		fflush(stdout);
	}
}

int networkpage(struct pollfd *pfd, Scannerdata *data, int current){
	drawheader(current);
	printf("\n");
	drawchannels(data->channels);
}

int probepage(struct pollfd *pfd, Scannerdata *data, int current){
	drawheader(current);
	printf("\n");
	drawchannels(data->channels);
}

int rssipage(struct pollfd *pfd, Scannerdata *data, int current){
	int8_t history[RSSIMAXHISTORY];
	memset(history, -100, RSSIMAXHISTORY);
	uint8_t history_index = 0;
	int8_t peak_dbm = -100;
	size_t last_frame_count = 0;

	Rssiinput rssi = {.history = history,
					.history_index = &history_index,
					.last_frame_count = &last_frame_count,
					.peak_dbm = &peak_dbm,
					.rssi_index = rssi_index,
	};

	drawheader(current);
	printf("\n");

	int readyfd = 0;
	while(1){
		printf("\e[3;0H\r");
		readyfd = poll(pfd, 1, 1000 / APROXFRAMERATE);
		if(readyfd == -1){
			return -1;
		}
		if(readyfd > 0){
			switch(getinput()){
				// Add case ENTER: to lock channel or keep scanning
				case LEFT_Q:
					return (current - 1) % NUMPAGES;
				case RIGHT_E:
					return (current + 1) % NUMPAGES;
				default:
					continue;
			}
		}

		drawchannels(data->channels);
		if(rssi_index == -1){
			printf("No target selected, use the devices page to pick a device\n");
			continue;
		}

		if(drawrssi(&data->devices, &rssi) == -1){
			return -1;
		}

		fflush(stdout);
	}
}

typedef int(*Pagefunc_t)(struct pollfd *pfd, Scannerdata *data, int current);

Pagefunc_t pages[NUMPAGES] = {&networkpage,
							&devicepage,
							&rssipage,
							&probepage,
};

int startui(Scannerdata *data){
	printf(ALTBUFF HOME CLEAR HIDE);

	struct pollfd pfd = {0};
	pfd.fd = STDIN_FILENO;
	pfd.events |= POLLIN;

	int current = 1;
	while(current >= 0){
		current = (*pages[current])(&pfd, data, current);
	}
}

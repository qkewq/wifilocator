#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <pthread.h>

#include "vector.h"
#include "data.h"
#include "uidata.h"

#define DEV_USEDROWS 7

int drawdevices(Devices *devices, int selected, int start){
	struct winsize ws;
	if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1){
		return -1;
	}

	int numtoprint = ws.ws_row - DEV_USEDROWS;
	size_t used = devices->device->used;
	if(!used){
		printf("Nothing found yet\n");
		return 0;
	}

	if(numtoprint > used){
		numtoprint = used;
		start = 0;
	}

	if(selected < 0){
		start = used - numtoprint;
		selected = used;
	}
	else if(selected >= used){
		start = 0;
		selected = 0;
	}

	time_t now = time(NULL);

	pthread_mutex_lock(&devices->lock);
	for(int i = 0; i < numtoprint; i++){
		Device *device = (Device *)vecindex(devices->device, i);
		if(!device){
			return -1;
		}
		printf(CLEARLINE);
		if(i == selected){
			printf(HIGHLIGHT);
		}
		printf("%d. ", i + 1);
		if(device->addr.org){
			printf("%s", device->addr.org);
		}
		else{
			printf("%02x:%02x:%02x:", device->addr.mac[0], device->addr.mac[1], device->addr.mac[2]);
		}
		printf("%02x:%02x:%02x\t", device->addr.mac[3], device->addr.mac[4], device->addr.mac[5]);
		switch(device->isbssid){
			case -1:
				printf("Unknown");
				break;
			case 0:
				printf("Client");
				break;
			case 1:
				printf("AP");
				break;
		}
		printf("\t %d Frame(s)", device->num_frames);
		printf("\tChannel %d", device->channel);
		printf("\tSeen %ds ago", now - device->last_frame);
		printf("\t%ddbm", device->last_dbm);
		if(i == selected){
			printf("Enter to send to RSSI");
		}
		printf(NORMAL "\n");
	}
	pthread_mutex_unlock(&devices->lock);

	printf(YELLOW CLEARLINE "%d of %d Displayed\n", numtoprint, devices->device->used);
	printf("Use arrows keys, Q, and E to navigate, Enter to select\n" NORMAL);
	return start;
}

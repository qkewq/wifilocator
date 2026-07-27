#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <pthread.h>

#include "vector.h"
#include "data.h"
#include "uidata.h"

#define DEV_USEDROWS 7
#define RSS_USEDROWS 5
#define PRO_USERROWS 6

void printaddr(Addrworg *addr){
	int printed;
	if(addr->org){
		printed = printf("%s_", addr->org);
	}
	else{
		printed = printf("%02x:%02x:%02x:", addr->mac[0], addr->mac[1], addr->mac[2]);
	}
	printed += printf("%02x:%02x:%02x", addr->mac[3], addr->mac[4], addr->mac[5]);

	printf(NORMAL);
	for(printed; printed < 22; printed++){
		printf(" ");
	}
}

void printrole(uint8_t isbssid){
	printf("   ");
	switch(isbssid){
		case 0:
			printf(BLUE "Client ");
			break;
		case 1:
			printf(PURPLE "AP     ");
			break;
		default:
			printf(RED "Unknown");
	}
	printf("   " NORMAL);
}

int drawdevices(Devices *devices, int *selected, int *start){
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
		*start = 0;
	}

	if(*selected < 0){
		*selected = used - 1;
	}
	else if(*selected >= used){
		*selected = 0;
	}

	if(*selected < *start){
		*start = *selected;
	}
	else if(*selected >= *start + numtoprint){
		*start = *selected - numtoprint + 1;
	}

	time_t now = time(NULL);

	pthread_mutex_lock(&devices->lock);
	for(int i = 0; i < numtoprint; i++){
		Device *device = (Device *)vecindex(devices->device, i + *start);
		if(!device){
			return -1;
		}
		printf(CLEARLINE);
		if(i + *start == *selected){
			printf(HIGHLIGHT);
		}
		printf("%2d. ", i + *start + 1);
		printaddr(&device->addr);
		printrole(device->isbssid);
		printf(YELLOW " %3d " NORMAL "Frame(s)", device->num_frames);
		printf("  Channel " YELLOW "%3d" NORMAL, device->channel);
		printf("  Seen " YELLOW "%2ds " NORMAL "ago", now - device->last_frame);
		printf(YELLOW "  %2d " NORMAL "dbm", device->last_dbm);
		if(i + *start == *selected){
			printf(YELLOW " --Enter to send to RSSI->" NORMAL);
		}
		printf(NORMAL "\n");
	}
	pthread_mutex_unlock(&devices->lock);

	printf(YELLOW CLEARLINE "%d-%d of %d Displayed\n", *start + 1, *start + numtoprint, devices->device->used);
	printf("Use arrows keys, Q, and E to navigate, Enter to select\n" NORMAL);

	return 0;
}

int printgraph(struct winsize *ws, int8_t peak, int8_t last){ // optimize this later :)
	int graph_height = (ws->ws_row - RSS_USEDROWS - 3) / 2;
	int segment_size = ws->ws_col / 3;
	int last_pos = ws->ws_col * (100 + last) / 100;
	int peak_pos = ws->ws_col * (100 + peak) / 100;

	for(int i = 0; i < graph_height; i++){
		int j = 0;
		printf(CLEARLINE RED);
		for(j; j < segment_size; j++){
			if(j == last_pos){
				break;
			}
			printf("|");
		}
		printf(YELLOW);
		if(j + 1 >= segment_size){
			for(j; j < segment_size * 2; j++){
				if(j == last_pos){
					break;
				}
				printf("|");
			}
		}
		printf(GREEN);
		if(j + 1 >= segment_size * 2){
			for(j; j < segment_size * 3; j++){
				if(j == last_pos){
					break;
				}
				printf("|");
			}
		}
		for(j; j < peak_pos; j++){
			printf(" ");
		}
		printf(CYAN BLUEBG "|" NORMAL "\n");
	}
	printf("\n");
	return 0;
}

int printhistory(struct winsize *ws, int8_t *history, uint8_t index){
	int graph_height = (ws->ws_row - RSS_USEDROWS - 3) / 2;
	int graph_col = RSSIMAXHISTORY;
	if(ws->ws_col - 1 < graph_col){
		graph_col = ws->ws_col - 1;
	}
	index -= graph_col % RSSIMAXHISTORY;
	for(int i = 0; i < graph_height; i++){
		int row_min = -1 * (100 / graph_height) * i;
		printf("|");
		for(int j = 0; j < graph_col; j++){
			if(history[(index + j) % RSSIMAXHISTORY] >= row_min){
				printf("#");
			}
			else{
				printf(" ");
			}
		}
		printf("\n");
	}
	return 0;
}

int drawrssi(Devices *devices, Rssiinput *input){
	struct winsize ws;
	if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1){
		return -1;
	}

	pthread_mutex_lock(&devices->lock);

	Device *device = (Device *)vecindex(devices->device, input->rssi_index);
	if(!device){
		pthread_mutex_unlock(&devices->lock);

		return -1;
	}
	Device local = {0};
	memcpy(&local, device, sizeof(Device));

	pthread_mutex_unlock(&devices->lock);

	printf(CLEARLINE HIGHLIGHT);
	printaddr(&local.addr);
	printrole(local.isbssid);
	printf("\tChannel: " YELLOW "%d\t" NORMAL, local.channel);
	printf(YELLOW "%d" NORMAL "Frame(s)", local.num_frames);
	printf("\tSeen " YELLOW "%ds" NORMAL "ago\n\n", time(NULL) - local.last_frame);

	if(local.num_frames <= *input->last_frame_count){
		*input->last_frame_count = local.num_frames;
		return 0;
	}
	*input->last_frame_count = local.num_frames;

	input->history[*input->history_index] = local.last_dbm;
	*input->history_index = (*input->history_index + 1) % RSSIMAXHISTORY;
	if(local.last_dbm > *input->peak_dbm){
		*input->peak_dbm = local.last_dbm;
	}

	printf("Last: " YELLOW "%d" NORMAL "dbm\tPeak: " BLUE "%d" NORMAL "dbm\n\n",
		 local.last_dbm, *input->peak_dbm
	);

	printgraph(&ws, *input->peak_dbm, local.last_dbm);
	printhistory(&ws, input->history, *input->history_index);

	return 0;
}

int printprobes(Probe *probe, int maxrows, int showwild){
	int i = 0;
	for(i; i < probe->requests->used && i < maxrows; i++){
		Request *req = vecindex(probe->requests, i);
		if(!req){
			return i;
		}

		if(!req->ssid[0] && !showwild){
			continue;
		}
		printf("    -->" YELLOW "%2d" NORMAL "requests made for ssid: ", req->num_requests);

		if(!req->ssid[0]){
			printf(RED "Wildcard Request" NORMAL);
		}
		else{
			printf(GREEN "%s" NORMAL, req->ssid);
		}
		printf("\n");
	}

	return i;
}

int drawprobes(Probes *probes, Probesinput *input){
	struct winsize ws;
	if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1){
		return -1;
	}

	if(input->showwild){
		printf(HIGHLIGHT "[X] Show wildcard requests\n" NORMAL);
	}
	else{
		printf(HIGHLIGHT "[ ] Show wildcard requests\n" NORMAL);
	}

	int printed = 0;
	int numtoprint = ws.ws_row - PRO_USERROWS;
	size_t used = probes->probe->used;
	if(!used){
		printf("Nothing found yet\n");
		return 0;
	}

	pthread_mutex_lock(&probes->lock);
	printf(CLEARTOEND);
	for(int i = 0; i < used; i ++){
		if(printed == numtoprint - 1){
			break;
		}
		Probe *probe = vecindex(probes->probe, i);
		if(!probe){
			return -1;
		}
		printf("%2d. ", i + 1);
		printaddr(&probe->addr);
		printf("\n");
		printed++;
		printed = printprobes(probe, numtoprint - printed, input->showwild);
	}

	pthread_mutex_unlock(&probes->lock);

	printf(YELLOW "TEST\n" NORMAL);

	return 0;
}

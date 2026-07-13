#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
// <linux/wireless.h> included in header

#include "data.h"
#include "setup.h"
#include "ouimap.h"
#include "vector.h"

#define SSIDMAPSIZE 40

void channel_free(Channels *channel_head){
	if(!channel_head->head){
		free(channel_head);
		return;
	}
	if(channel_head->head == channel_head->head){
		free(head->head);
		free(channel_head);
		return;
	}

	Channel *current = channel_head->head;
	Channel *next = NULL;
	while(current != channel_head->head){
		next = current->next;
		free(current);
		current = next;
	}
	free(channel_head);
}

int inchannel(int freq, Channels *channel_head){
	for(int i = 0; i < channel_head->number_nodes; i++){
		if(channel_head->channels[i].m == freq){
			return 1;
		}
	}

	return 0;
}

// int addChannel(Channels *channel_head, Channel *new_node){
int addChannel(Channels *channel_head, struct iw_freq *freq){
	memcpy(channel_head->channels[number_nodes], freq, sizeof(struct iw_freq));
	channel_head->number_nodes++;

	return 0;
}

int addnodesinrange(int lb, int ub, Channels *channel_head, iw_range *range){
	for(int i = 0; i < range->num_channels; i++){
		if(range->freq[i].m >= lb && range->freq[i].m <= ub){
			addChannel(channel_head, &range->freq);
		}
	}

	return 0;
}

int buildChannels(Arguments *args, int fd, Channels **ret){
	struct iw_req iwr = {0};
	struct iw_range range = {0};

	strncpy(iwr.ifr_ifrn.ifrn_name, args.if_name, IFNAMSIZ);

	Channels *channel_head = calloc(1, sizeof(Channels));
	if(!channel_head){
		return -1;
	}

	if(!args->band && !args->freq.m){ // No channel specified use current channel
		if(ioctl(fd, SIOCGIWFREQ, &iwr) == -1){
			free(channel_head);
			return -1;
		}
		addChannel(channel_head, &iwr.u.freq);
		ret = channel_head;

		return 0;
	}

	iwr.u.data.pointer = &range;
	iwr.u.data.length = sizeof(iw_range);

	if(ioctl(fd, SIOCGIWRANGE, &iwr) == -1){ // Get channel capabilities
		free(channel_head);
		return -1;
	}

	if(args->band){
		if(args->band == band2g || args->band == bandall){
			addnodesinrange(2412, 2484, channel_head, &range);
		}
		if(args->band == band5g || args->band == bandall){
			addnodesinrange(5160, 5885, channel_head, &range);
		}
	}

	if(args->freq.m){
		for(int i = 0; i < range.num_channels; i++){
			if(args->freq.m == range.freq[i]){
				if(inchannel(range.freq[i], channel_head)){
					break;
				}
				else{
					addChannel(channel_head, &range.freq[i]);
					break;
				}
			}
		}
	}

	if(!channel_head->number_nodes){
		channel_free(channel_head);
		return -1;
	}

	channel_head->current_index = 0;

	ret = channel_head;
	return 0;
}

int builddata(int fd, char *if_name, Channels *channels, Ouimap *ouimap, Scannerdata **ret){
	Scannerdata *scannerdata = calloc(1, sizeof(Scannerdata));
	if(!scannerdata){
		return -1;
	}

	scannerdata->fd = fd;
	strncpy(scannerdata->if_name, if_name, IFNAMSIZ);
	scannerdata->channels = channels;
	scannerdata->ouimap = ouimap;

	scannerdata->networks.map.map = calloc(SSIDMAPSIZE, sizeof(Ssidmapnode));
	if(!scannerdata->networks.map.map){
		free(scannerdata);
		return -1;
	}
	scannerdata->networks.map.mapsize = SSIDMAPSIZE;

	scannerdata->devices.device = vecinit(16, sizeof(Device));
	if(!scannerdata->devices.device){
		free(scannerdata);
		free(scannerdata->networks.map.map);
		return -1;
	}

	pthread_mutex_init(scannerdata->channels->lock);
	pthread_mutex_init(scannerdata->devices.lock);
	pthread_mutex_init(scannerdata->networks.lock);
	pthread_mutex_init(scannerdata->probes.lock);

	ret = scannerdata;
	return 0;
}

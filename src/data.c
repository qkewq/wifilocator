#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h.>
#include <pthread.h>

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
	if(!channel_head->head){
		return 0;
	}
	if(channel_head->head.freq.m == freq){
		return 1;
	}

	Channel *current = channel_head->head;
	while(current != channel_head->head){
		if(current->freq.m == freq){
			return 1;
		}
		current = current->next;
	}

	return 0;
}

int addChannel(Channels *channel_head, Channel *new_node){
	if(!channel_head->head){
		channel_head->head = new_node;
		channel_head->current = new_node;
		new_node->next = new_node;
	}
	else{
		channel_head->current->next = new_node;
		channel_head->current = new_node;
		new_node->next = head;
	}
	channel_head->number_nodes++;

	return 0;
}

int addnodesinrange(int lb, int ub, Channels *channel_head, iw_range *range){
	for(int i = 0; i < range->num_channels; i++){
		if(range->freq[i].m >= lb && range->freq[i].m <= ub){
			Channel *new_node = calloc(1, sizeof(Channel));
			if(!new_node){
				return -1;
			}
			memcpy(new_node->freq, range->freq[i], sizeof(struct iw_freq));
			addChannel(channel_head, new_node);
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
		Channel *new_node = calloc(1, sizeof(Channel));
		if(!new_node){
			free(channel_head);
			return -1;
		}
		memcpy(channel->freq, iwr.u.freq, sizeof(struct iw_freq));
		addChannel(channel_head, new_node);
		channel_head->current = channel_head->head;
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
			if(addnodesinrange(2412, 2484, channel_head, &range) == -1){
				channel_free(channel_head);
				return -1;
			}
		}
		if(args->band == band5g || args->band == bandall){
			if(addnodesinrange(5160, 5885, channel_head, &range) == -1){
				channel_free(channel_head);
				return -1;
			}
		}
	}

	if(args->freq.m){
		for(int i = 0; i < range.num_channels; i++){
			if(args->freq.m == range.freq[i]){
				if(inchannel(range.freq[i], channel_head)){
					break;
				}
				else{
					Channel *new_node = calloc(1, sizeof(Channel));
					if(!new_node){
						channel_free(channel_head);
						return -1;
					}
					memcpy(new_node->freq, range.freq[i], sizeof(struct iw_freq));
					addChannel(channel_head, newnode);
					break;
				}
			}
		}
	}

	if(!channel_head->number_nodes){
		channel_free(channel_head);
		return -1;
	}

	channel_head->current = channel_head->head;
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

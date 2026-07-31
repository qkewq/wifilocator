#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>

// included in header
// #include <stdint.h>
// #include <stdatomic.h>
// <linux/wireless.h>

#include "data.h"
#include "setup.h"
#include "ouimap.h"
#include "vector.h"
#include "network.h"

void channel_free(Channels *channel_head){
	pthread_mutex_destroy(&channel_head->lock);
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

int addChannel(Channels *channel_head, struct iw_freq *freq){
	memcpy(&channel_head->channels[channel_head->number_nodes], freq, sizeof(struct iw_freq));
	channel_head->number_nodes++;

	return 0;
}

int addnodesinrange(int lb, int ub, Channels *channel_head, struct iw_range *range){
	for(int i = 0; i < range->num_channels; i++){
		if(range->freq[i].m >= lb && range->freq[i].m <= ub){
			addChannel(channel_head, &range->freq[i]);
		}
	}

	return 0;
}

int buildChannels(Arguments *args, int fd, Channels **ret){
	struct iwreq iwr = {0};
	struct iw_range range = {0};

	strncpy(iwr.ifr_ifrn.ifrn_name, args->if_name, IFNAMSIZ);

	Channels *channel_head = calloc(1, sizeof(Channels));
	if(!channel_head){
		return -1;
	}

	if(!args->band && !args->freq.m){ // No channel specified use current channel
		if(ioctl(fd, SIOCGIWFREQ, &iwr) == -1){
			free(channel_head);
			return -1;
		}
		iwr.u.freq.i = freqtochannel(iwr.u.freq.m);
		addChannel(channel_head, &iwr.u.freq);
		*ret = channel_head;

		return 0;
	}

	iwr.u.data.pointer = &range;
	iwr.u.data.length = sizeof(struct iw_range);

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
			if(args->freq.m == range.freq[i].m){
				if(inchannel(range.freq[i].m, channel_head)){
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

	memcpy(&iwr.u.freq, &channel_head->channels[0], sizeof(struct iw_freq));
	if(ioctl(fd, SIOCSIWFREQ, &iwr) == -1){
		free(channel_head);
		return -1;
	}
	channel_head->current_index = 0;

	*ret = channel_head;
	return 0;
}

void makeaddrworg(Addrworg *addrworg, uint8_t *addr, Ouimap *ouimap){
	addrworg->org = ouilookup(ouimap, addr);
	memcpy(addrworg->mac, addr, 6);
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

	scannerdata->devices.device = vecinit(64, sizeof(Device));
	scannerdata->networks.network = vecinit(8, sizeof(Network));
	scannerdata->probes.probe = vecinit(16, sizeof(Probe));

	if(!scannerdata->devices.device ||
	!scannerdata->networks.network ||
	!scannerdata->probes.probe){
		datafree(scannerdata);
		return -1;
	}

	pthread_mutex_init(&scannerdata->channels->lock, NULL);
	pthread_mutex_init(&scannerdata->devices.lock, NULL);
	pthread_mutex_init(&scannerdata->networks.lock, NULL);
	pthread_mutex_init(&scannerdata->probes.lock, NULL);

	*ret = scannerdata;
	return 0;
}

void networkfree(void *arg){
	Network *network = (Network *)arg;
	free(network->ssid);
	vecfree(network->bssids);
	vecfree(network->channels);
}

void probefree(void *arg){
	Probe *probe = (Probe *)arg;
	vecfree(probe->requests);
}

void datafree(Scannerdata *data){
	if(!data){
		return;
	}

	channel_free(data->channels);

	if(data->devices.device){
		pthread_mutex_destroy(&data->devices.lock);
		vecfree(data->devices.device);
	}
	if(data->networks.network){
		pthread_mutex_destroy(&data->networks.lock);
		vecfree_custom(data->networks.network, networkfree);
	}
	if(data->probes.probe){
		pthread_mutex_destroy(&data->probes.lock);
		vecfree_custom(data->probes.probe, probefree);
	}
	if(data->ouimap){
		ouifree(data->ouimap);
	}

	free(data);
}

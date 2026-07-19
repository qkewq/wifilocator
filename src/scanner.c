#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pthread.h>
#include <poll.h>

#include "scanner.h"
#include "data.h"
#include "network.h"
#include "vector.h"

#define TXOFFSET 0x0A
#define ADDRLEN  0x06

void *scanner_th(void *t_arg){
	Scannerdata *data = t_arg;

	time_t channel_time = time(NULL);
	ssize_t frame_size;
	uint8_t buffer[BUFFERSIZE];
	Radiotap rtp;
	Device *existing = NULL;
	int addroffset;

	int readyfd = 0;
	struct pollfd pfd = {0};
	pfd.fd = data->fd;
	pfd.events |= POLLIN;

	while(1){
		readyfd = poll(&pfd, 1, POLLTIMEOUT_S * 1000);
		if(readyfd == -1){
			// handle fatal error
		}

		if(!readyfd || channel_time < time(NULL) - POLLTIMEOUT_S){
			if(setchannel(data->fd, data->if_name, data->channels) == -1){
				// handle fatal error
			}
			channel_time = time(NULL);
			continue;
		}

		frame_size = recv(data->fd, buffer, BUFFERSIZE, 0);
		if(frame_size == -1){
			// handle fatal error
		}

		if(!radiotap(buffer, &rtp)){
			continue;
		}
		if(!txpresent(buffer[rtp.header_len])){
			continue;
		}

		addroffset = rtp.header_len + TXOFFSET;
		// Reading struct without lock because this should be the only
		// writer thread.  Somehow remember to change this if that changes:)
		existing = (Device *)veccmp(data->devices.device,
									&buffer[addroffset],
									ADDRLEN,
									offsetof(Addrworg, mac) + offsetof(Device, addr)
								);

		if(!existing){
			Device new_device = {0};
			makeaddrworg(&new_device, &buffer[addroffset], data->ouimap);
			new_device.num_frames++;
			new_device.last_frame = time(NULL);
			new_device.isbssid = isdevbssid(&buffer[rtp.header_len]);
			new_device.channel = freqtochannel(rtp.freq);
			new_device.last_dbm = rtp.dbm;
			pthread_mutex_lock(&data->devices.lock);
			if(!vecappend(data->devices.device, &new_device)){
				// out of memory
			}
			pthread_mutex_unlock(&data->devices.lock);
		}
		else{
			pthread_mutex_lock(&data->devices.lock);
			existing->num_frames++;
			existing->last_frame = time(NULL);
			existing->last_dbm = rtp.dbm;
			if(existing->isbssid == -1){
				existing->isbssid = isdevbssid(&buffer[rtp.header_len]);
			}
			pthread_mutex_unlock(&data->devices.lock);
		}


	}
}

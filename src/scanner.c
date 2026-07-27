#include <stdlib.h>
#include <stdio.h>
#include <string.h>
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
		// writer thread.  Somehow remember to change this if that changes :)
		existing = (Device *)veccmp(data->devices.device,
									&buffer[addroffset],
									ADDRLEN,
									offsetof(Addrworg, mac) + offsetof(Device, addr)
		);

		if(!existing){
			Device new_device = {0};
			makeaddrworg(&new_device.addr, &buffer[addroffset], data->ouimap);
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

		if(isprobe(buffer[rtp.header_len])){ // Will abstract this later I promise :)
			int ssid_offset = 0;
			uint8_t ssid_len = 0;
			getssid(&buffer[rtp.header_len], &ssid_offset, &ssid_len);
			// Another no lock read :)
			Probe *existing_probe = (Probe *)veccmp(data->probes.probe,
													&buffer[addroffset],
													ADDRLEN,
													offsetof(Addrworg, mac) + offsetof(Probe, addr)
			);

			if(!existing_probe){
				Probe new_probe = {0};
				new_probe.requests = vecinit(2, sizeof(Request));
				if(!new_probe.requests){
					// out of memory
				}
				makeaddrworg(&new_probe.addr, &buffer[addroffset], data->ouimap);
				pthread_mutex_lock(&data->probes.lock);
				if(!vecappend(data->probes.probe,&new_probe)){
					// out of memory
				}
				existing_probe = (Probe *)data->probes.probe->data + data->probes.probe->used - 1;
				pthread_mutex_unlock(&data->probes.lock);
			}

			// Probe new_probe = {0};
			// :)
			Request *req = (Request *)veccmp(existing_probe->requests,
											&buffer[ssid_offset + rtp.header_len],
											ssid_len,
											offsetof(Request, ssid)
			);
			pthread_mutex_lock(&data->probes.lock);
			if(!req){
				Request new_request = {0};
				memcpy(&new_request.ssid, &buffer[ssid_offset + rtp.header_len], ssid_len);
				new_request.num_requests++;
				if(!vecappend(existing_probe->requests, &new_request)){
					// out of memory
				}
			}
			else{
				req->num_requests++;
			}
			pthread_mutex_unlock(&data->probes.lock);
		}
	}
}

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

void scanner_th(void *t_arg){
	Scannerdata *data = t_arg;

	time_t channel_time = time(NULL);
	ssize_t frame_size;
	uint8_t buffer[BUFFERSIZE];
	Radiotap rtp;
	uint16_t frame_control;

	int readyfd = 0;
	struct pollfd pfd = {0};
	pfd.fd = data->fd;
	pfd.events |= POLLIN;

	while(1){
		readyfd = poll(&pfd, 1, POLLTIMEOUT_S * 1000);
		if(readyfd == -1){
			// handle fatal error
		}

		if(!readyfd || channel_time > time(NULL) - POLLTIMEOUT_S){
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

		frame_control = (buffer[rtp.header_len] << 8) + buffer[rtp.header_len + 1];
		if(frame_control & )// and with non tx addr frame types all at once
		// parse
		// lock
		// write
		// unlock
	}
}

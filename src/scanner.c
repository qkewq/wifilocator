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

		// parse
		// lock
		// write
		// unlock
	}
}

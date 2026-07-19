#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#include "ouimap.h"
#include "setup.h"
#include "network.h"
#include "data.h"
#include "setup.h"
#include "scanner.h"

void usage(){
	printf("");
}

int main(int argc, char **argv){

	Arguments args = {0};
	if(getargs(&args, argc, argv) == -1){ // Prints some error messages
		usage();
		return 1;
	}

	if(args.help){
		usage();
		return 0;
	}

	if(!args.if_name[0]){
		printf("Missing required argument -i, --interface=<interface>\n");
		return 1;
	}

	int fd = openbindraw(args.if_name);
	if(fd < 0){
		printf("Socket create failed with interface %s\n", args.if_name);
		return 1;
	}

	int ismon = ismonitor(fd, args.if_name);
	if(ismon == -1){
		printf("Failed to check mode for interface %s\n", args.if_name);
		close(fd);
		return 1;
	}
	if(!ismon && !args.setmon){
		printf("Interface %s is not in monitor mode\nUse -m, --monitor to enable\n", args.if_name);
		close(fd);
		return 1;
	}
	else if(!ismon && args.setmon){
		if(setmonitor(fd, args.if_name) == -1){
			printf("Failed to put interface %s into monitor mode\n", args.if_name);
			close(fd);
			return 1;
		}
	}

	Channels *channels = NULL;
	if(buildChannels(&args, fd, &channels) == -1){
		printf("Failed to build channels list\n");
		close(fd);
		return 1;
	}

	Ouimap *ouimap = ouimapgen(OUIMAPSIZE, OUIFILEPATH);
	if(!ouimap){
		printf("Failed to get OUI list\n");
		close(fd);
		return 1;
	}

	Scannerdata *scannerdata = NULL;
	if(builddata(fd, args.if_name, channels, ouimap, &scannerdata) == -1){
		printf("Failed to prepare data structures\n"); // Out of memory
		return 1;
	}


	pthread_t scanner;
	if(pthread_create(&scanner, NULL, scanner_th, scannerdata) != 0){
		printf("Failed to start scanner thread\n");
		return 1;
	}

	// ui time

	return 0;
}

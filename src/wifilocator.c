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
#include "ui.h"

void usage(char *v){
	printf(
		"%s: Launches tui for passively scanning nearby networks and devices\n"
		"\n"
		"Usage: %s [-mh] [ -i interface] [-c channel] [-b band]\n"
		"\n"
		"Options:\n"
		"-i, --interface=[ interface ]    The name of the interface to be used for scanning\n"
		"-m, --monitor                    Enables monitor mode on the interface if it is not already\n"
		"-c, --channel=[ channel | freq]  Values > 1000 are frequencies, values < 1000 are channel numbers\n"
		"-b, --band=[ 2.4g | 5g | all ]   Choose to scan an entire band or all channels\n"
		"-h, --help                       Print this help message\n"
		"\n"
		"Examples:\n"
		"%s -i wlan0 -m -c 11\n"
		"%s --interface wlan0 --band 2.4g --channel 48\n"
		"%s -i wlan0 -c 2437\n",v,v,v,v,v
	);
}

int main(int argc, char **argv){

	if(argc == 1){
		usage(argv[0]);
		return 0;
	}

	Arguments args = {0};
	if(getargs(&args, argc, argv) == -1){ // Prints some error messages
		usage(argv[0]);
		return 1;
	}

	if(args.help){
		usage(argv[0]);
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
		close(fd);
		return 1;
	}

	if(prepterminal() == -1){
		printf("Failed to set terminal mode\n");
		close(fd);
		return 1;
	}

	pthread_t scanner;
	if(pthread_create(&scanner, NULL, scanner_th, scannerdata) != 0){
		printf("Failed to start scanner thread\n");
		return 1;
	}

	startui(scannerdata);

	return 0;
}

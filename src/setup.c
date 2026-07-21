#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <stdint.h>
#include <net/if.h>
#include <string.h>

#include "setup.h"
#include "network.h"

#define BAND2G "2.4g"
#define BAND5G "5g"
#define BANDAL "all"

int argtoband(Arguments *args, char *optarg){
	if(strncmp(optarg, BAND2G, sizeof(BAND2G)) == 0){
		args->band = band2g;
	}
	else if(strncmp(optarg, BAND5G, sizeof(BAND5G)) == 0){
		args->band = band5g;
	}
	else if(strncmp(optarg, BANDAL, sizeof(BANDAL)) == 0){
		args->band = bandall;
	}
	else{
		printf("Unknown argument for -b, --band=%s\nExpected < 2.4g | 5g | all >\n", optarg);
		return -1;
	}

	return 0;
}

int argtofreq(Arguments *args, char *optarg){
	int value = atoi(optarg);

	args->freq.e = 6;
	args->freq.flags = 0;
	if(value < 1000 && value > 0){
		args->freq.m = channeltofreq(value);
		args->freq.i = value;
		if(!args->freq.m){
			printf("Invalid argument for -c, --channel=%s\n"
				"Unknown channel number", optarg);
			return -1;
		}
		return 0;
	}
	else if(value >= 1000){
		args->freq.i = freqtochannel(value);
		args->freq.m = value;
		if(!args->freq.i){
			printf("Invalid argument for -c, --channel=%s\n"
				"Unkown frequency", optarg);
			return -1;
		}
		return 0;
	}
	printf("Invalid argument for -c, --channel=%s\n"
		"Values under 1000 are channel numbers, values greater than 1000 are frequencies in Mhz\n", optarg);

	return -1;
}

int getargs(Arguments *args, int argc, char **argv){
	struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"interface", required_argument, 0, 'i'},
		{"monitor", no_argument, 0, 'm'},
		{"band", required_argument, 0, 'b'},
		{"channel", required_argument, 0, 'c'},
		{0,0,0,0}
	};

	int option;
	int ret = 0;
	while(1){
		int opt_index = 0;
		option = getopt_long(argc, argv, ARGSTRING, long_options, &opt_index);
		if(option == -1){
			break;
		}

		switch(option){
			case 'h':
				args->help = 1;
				break;
			case 'i':
				strncpy(args->if_name, optarg, IFNAMSIZ);
				break;
			case 'm':
				args->setmon = 1;
				break;
			case 'b':
				ret = argtoband(args, optarg);
				break;
			case 'c':
				ret = argtofreq(args, optarg);
				break;
			default:
				ret = -1;
				break;
		}
	}

	return ret;
}

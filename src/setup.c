#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <net/if.h>
#include <string.h>

#include "setup.h"

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
	uint8_t channel_nums[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,32,36,40,44,48,52,56,60,64,68,
		72,76,80,84,88,92,96,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165,169,173,177};

	uint16_t channel_freq[] = {2412,2417,2422,2427,2432,2437,2442,2447,2452,2457,2462,2467,2472,
		2484,5160,5180,5200,5220,5240,5260,5280,5300,5320,5340,5360,5380,5400,5420,5440,5460,5480,5500,
		5520,5540,5560,5580,5600,5620,5640,5660,5680,5700,5720,5745,5765,5785,5805,5825,5845,5865,5885};

	int value = atoi(optarg);

	if(value < 1000){
		for(int i = 0; i < sizeof(channel_nums) / sizeof(channel_nums[0]); i++){
			if(channel_nums[i] == value){
				args->freq.m = channel_freq[i];
				args->freq.e = 6;
				args->freq.i = value;
				args->freq.flags = 0;
				return 0;
			}
		}
	}
	else if(value >= 1000){
		for(int i = 0; i < sizeof(channel_freq) / sizeof(channel_freq[0]); i++){
			if(channel_freq[i] = value){
				args->freq.m = value;
				args->freq.e = 6;
				args->freq.i = channel_num[i];
				args->freq.flags = 0;
				return 0;
			}
		}
	}
	printf("Invalid argument for -c, --channel=%s\n"
		"Values under 1000 are channel numbers, values greater than 1000 are frequencies in Mhz\n", optarg);

	return -1;
}

int getargs(Arguments *args, int argc, char *argv){
	struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"interface", required_argument, 0, 'i'},
		{"monitor", no_argument, 0, 'm'},
		{"band", required_argument, 0, 'b'},
		{"channel", required_argument, 0, 'c'},
		{0,0,0,0}
	}

	int option;
	int ret = 0;
	while(1){
		int opt_index = 0;
		option = get_optlong(argc, argv, ARGSTRING, long_options, &option_index);
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
				ret = argtoband(arg, optarg);
				break;
			case 'c':
				ret = argtofreq(arg, optarg);
				break;
			default:
				ret = -1;
				break;
		}
	}

	return ret;
}

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "ouimap.h"

uint8_t htoi(char c){ // Single hex character
	switch(c){
		case '0':
			return 0x0;
		case '1':
			return 0x1;
		case '2':
			return 0x2;
		case '3':
			return 0x3;
		case '4':
			return 0x4;
		case '5':
			return 0x5;
		case '6':
			return 0x6;
		case '7':
			return 0x7;
		case '8':
			return 0x8;
		case '9':
			return 0x9;
		case 'a':
		case 'A':
			return 0xa;
		case 'B':
		case 'b':
			return 0xb;
		case 'C':
		case 'c':
			return 0xc;
		case 'D':
		case 'd':
			return 0xd;
		case 'E':
		case 'e':
			return 0xe;
		case 'F':
		case 'f':
			return 0xf;
		default:
			return 0;
	}
}

uint32_t getindex(size_t mapsize, uint8_t *oui){
	return ((oui[0] << 16) + (oui[1] << 8) + oui[2]) % mapsize;
}

Ouimap *ouimapgen(size_t mapsize, char *filepath){
	if(mapsize <= 0){
		return NULL;
	}

	// <oui><org_name>\n
	// xxxxxxExampleCorp\n
	FILE *file = fopen(filepath, "r");
	if(!file){
		return NULL;
	}

	Ouimap *map = calloc(1, sizeof(Ouimap));
	if(!map){
		return NULL;
	}
	map->map = calloc(mapsize, sizeof(Ouinode));
	if(!map->map){
		ouifree(map);
		return NULL;
	}
	map->mapsize = mapsize;

	while(1){
		char line[64] = {0};
		if(!fgets(line, sizeof(line) / sizeof(char), file)){
			if(feof(file)){
				break;
			}
			else{
				ouifree(map);
				return NULL;
			}
		}

		if(line[0] == '\n'){
			continue;
		}

		uint8_t oui[3];
		char org[58];
		int x = 0;
		for(int i = 0; i < 3; i++){
			oui[i] = htoi(line[x]) << 4;
			x++;
			oui[i] += htoi(line[x]);
			x++;
		}

		int orglen = 0;
		for(orglen; orglen < sizeof(org) / sizeof(char); orglen++){
			org[orglen] = line[orglen + 6];
			if(org[orglen] == '\n' || org[orglen] == '\r'){
				org[orglen] = '\0';
				break;
			}
		}

		Ouinode *newnode = calloc(1, sizeof(Ouinode));
		if(!newnode){
			ouifree(map);
			return NULL;
		}
		newnode->org = calloc(orglen, sizeof(char));
		if(!newnode->org){
			free(newnode);
			ouifree(map);
			return NULL;
		}
		memcpy(newnode->oui, oui, sizeof(newnode->oui));
		memcpy(newnode->org, org, orglen);

		uint32_t index = getindex(mapsize, oui);
		newnode->next = map->map[index];
		map->map[index] = newnode;
	}

	return map;
}

char *ouilookup(Ouimap *map, uint8_t *oui){ // ouifree() frees char * returned by lookup
	uint32_t index = getindex(map->mapsize, oui);

	Ouinode *current = map->map[index];
	while(current){
		if(memcmp(current->oui, oui, 3) == 0){
			return current->org;
		}
		current = current->next;
	}

	return NULL;
}

void ouifree(Ouimap *map){
	if(!map){
		return;
	}

	for(int i = 0; i < map->mapsize; i++){
		Ouinode *current = map->map[i];
		Ouinode *next;
		while(current){
			next = current->next;
			free(current->org);
			free(current);
			current = next;
		}
	}

	free(map);
}

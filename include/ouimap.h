#ifndef OUIMAP_H
#define OUIMAP_H

#define OUIFILEPATH      "/usr/share/wifilocator/oui24.txt"
#define OUIMAPSIZE       10007

typedef struct Ouinode{
	struct Ouinode *next;
	uint8_t oui[3];
	char *org;
} Ouinode;

typedef struct Ouimap{
	size_t mapsize;
	Ouinode **map;
} Ouimap;



Ouimap *ouimapgen(size_t mapsize, char *filepath);
char *ouilookup(Ouimap *map, uint8_t *oui);
void ouifree(Ouimap *map);

#endif

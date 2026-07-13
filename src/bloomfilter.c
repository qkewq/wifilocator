#include <stdlib.h>
#include <stdint.h>

#include "bloomfilter.h"

Bloomfilter *bf_init(size_t num_bits){
	if(!num_bits){
		return NULL;
	}

	Bloomfilter *bf = calloc(1, sizeof(Bloomfilter));
	if(!bf){
		return NULL;
	}

	bf->bitarray = calloc((num_bits + 7) / 8, sizeof(uint8_t));
	if(!bf->bitarray){
		free(bf);
		return NULL;
	}
	bf->arraysize = ((num_bits + 7) / 8) * 8;

	return bf;
}

int bf_insert(Bloomfilter *bf, void *data, size_t size){

}

int bf_lookup(Bloomfilter *bf, void *data, size_t size){

}

void bf_free(Bloomfilter *bf){
	if(!bf){
		return;
	}

	free(bf->bitarray);
	free(bf);
}

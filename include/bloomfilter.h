#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

typedef struct Bloomfilter{
	size_t arraysize;    // Size of bitarray in bytes
	uint8_t *bitarray;   // Bit array for bloom filter
} Bloomfilter;

Bloomfilter *bf_init(size_t num_bits); // rounds to next multiple of 8
int bf_insert(Bloomfilter *bf, void *data, size_t size);
int bf_lookup(Bloomfilter *bf, void *data, size_t size);
void bf_free(Bloomfilter *bf);

#endif

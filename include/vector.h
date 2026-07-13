#ifndef VECTOR_H
#define VECTOR_H

typedef struct Vector{
	size_t unitsize;    // Size of each index
	size_t capacity;    // Number of indexes
	size_t used;        // Current used
	void *data;         // The vector array
} Vector;

Vector *vecinit(size_t count, size_t size);
int vecappend(Vector *vector, void *data);
int vecinsert(Vector *vector, void *data, size_t index);
int vecremove(Vector *vector, size_t index);
int vecoptimize(Vector *vector);
void vecfree(Vector *vector);

#endif

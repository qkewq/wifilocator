#ifndef VECTOR_H
#define VECTOR_H

typedef struct Vector{
	size_t unitsize;
	size_t capacity;
	size_t used;
	void *data;
} Vector;

Vector *vecinit(size_t count, size_t size);
int vecappend(Vector *vector, void *data);
int vecinsert(Vector *vector, void *data, size_t index);
int vecremove(Vector *vector, size_t index);
int vecoptimize(Vector *vector);
void vecfree(Vector *vector);

#endif

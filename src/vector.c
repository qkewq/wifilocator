#include <stdlib.h>
#include <string.h>

#include "vector.h"

int vecresize(Vector *vector){
	void *new_data = calloc(vector->capacity * 2, vector->unitsize);
	if(!new_data){
		return 0;
	}

	memcpy(new_data, vector->data, vector->unitsize * vector->used);
	free(vector->data);
	vector->data = new_data;
	vector->capacity = vector->capacity * 2;

	return 1;
}

Vector *vecinit(size_t count, size_t size){
	if(!count || !size){
		return NULL;
	}

	Vector *vector = calloc(1, sizeof(Vector));
	if(!vector){
		return NULL;
	}

	vector->data = calloc(count, size);
	if(!vector->data){
		free(vector);
		return NULL;
	}

	vector->capacity = count;
	vector->unitsize = size;

	return vector;
}

int vecappend(Vector *vector, void *data){
	if(!vector || !data){
		return 0;
	}

	if(vector->used == vector->capacity){
		if(!vecresize(vector)){
			return 0;
		}
	}

	memcpy((char *)vector->data + vector->unitsize * vector->used, data, vector->unitsize);
	vector->used++;

	return 1;
}

int vecinsert(Vector *vector, void *data, size_t index){
	if(!vector || !data || index > vector->capacity){
		return 0;
	}

	if(vector->used == vector->capacity){
		if(!vecresize(vector)){
			return 0;
		}
	}

	if(index = vector->used){
		return vecappend(vector, data);
	}

	memmove((char *)vector->data + vector->unitsize * index,
			(char *)vector->data + vector->unitsize * index + vector->unitsize,
			vector->unitsize);
	memcpy((char *)vector->data + vector->unitsize * index, data, vector->unitsize);
	vector->used++;

	return 1;
}

int vecremove(Vector *vector, size_t index){
	if(!vector || index > vector->capacity){
		return 0;
	}

	if(index >= vector->used - 1){
		vector->used--;
		return 1;
	}

	memmove((char *)vector->data + vector->unitsize * index + vector->unitsize,
			(char *)vector->data + vector->unitsize * index,
			vector->unitsize);

	vector->used--;
	return 1;
}

int vecoptimize(Vector *vector){
	if(!vector){
		return 0;
	}

	if(vector->used == vector->capacity || !vector->used){ // capacity cannot be zero
		return 1;
	}

	void *new_data = calloc(vector->used, vector->unitsize);
	if(!new_data){
		return 0;
	}

	memcpy(new_data, vector->data, vector->unitsize * vector->used);
	free(vector->data);
	vector->data = new_data;
	vector->capacity = vector->used;

	return 1;
}

void vecfree(Vector *vector){
	if(!vector){
		return;
	}

	free(vector->data);
	free(vector);
}

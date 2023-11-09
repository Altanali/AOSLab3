#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>
#include <stdlib.h>

static void *(*malloc_fnc_ptr)(size_t) = NULL;
#define SIZE 64
#define MAGIC 0XCC

static void get_malloc(void) {
	malloc_fnc_ptr = dlsym(RTLD_NEXT, "malloc");
	if(malloc_fnc_ptr == NULL) {
		printf("Bad dlsym.\n");
		exit(1);
	}
}

void *malloc(size_t size) {
	if(!malloc_fnc_ptr) get_malloc();
	char *result = (char *)malloc_fnc_ptr(size);
	for(int i = 0; i < size; ++i) {
		result[i] = MAGIC;
	}
	return result;
}


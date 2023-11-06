#ifndef COMMON_H
#define COMMON_H
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define handle_error(msg) \
           do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

    
#endif
#ifndef COMMON_H
#define COMMON_H
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define handle_error(msg) \
           do { perror(msg); exit(EXIT_FAILURE); } while (0)

#endif
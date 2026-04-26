#ifndef ANGBAND_COMMON_H
#define ANGBAND_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <fcntl.h>

#define die(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)

#endif // ANGBAND_COMMON_H

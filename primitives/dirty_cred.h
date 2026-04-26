#ifndef ANGBAND_DIRTY_CRED_H
#define ANGBAND_DIRTY_CRED_H

#define _GNU_SOURCE
#include "common.h"
#include <sched.h>

int dirty_cred_spray_users(int num);
int dirty_cred_trigger_swap();

#endif // ANGBAND_DIRTY_CRED_H

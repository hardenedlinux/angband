#ifndef ANGBAND_USERNS_H
#define ANGBAND_USERNS_H

#include "common.h"
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

/**
 * userns_clone_and_run - Create child in new user+network namespace.
 *
 * The child runs with uid=0, euid=0, all capabilities including
 * CAP_NET_ADMIN. The parent waits for the child to complete.
 *
 * @fn:  Function to run in the child (new namespace)
 * @arg: Argument passed to fn
 * Returns: exit status of child, or -1 on error.
 */
typedef int (*userns_child_fn_t)(void *arg);
int userns_clone_and_run(userns_child_fn_t fn, void *arg);

#endif

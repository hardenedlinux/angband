#ifndef ANGBAND_PIPE_BUFFER_H
#define ANGBAND_PIPE_BUFFER_H

#include "common.h"

/* Simplified pipe_buffer for exploitation purposes */
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
};

int pipe_buffer_spray(int num_pipes, int pipe_fds[][2]);
int pipe_buffer_alloc(int pipe_fds[2]);

#endif // ANGBAND_PIPE_BUFFER_H

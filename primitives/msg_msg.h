#ifndef ANGBAND_MSG_MSG_H
#define ANGBAND_MSG_MSG_H

#include "common.h"

struct msg_msg {
    struct list_head {
        struct list_head *next, *prev;
    } m_list;
    long m_type;
    size_t m_ts;
    struct msg_msgseg *next;
    void *security;
};

int msg_msg_alloc(int msqid, void *buf, size_t size, long type);
int msg_msg_spray(int num_queues, int num_msgs, size_t size, long type);

#endif // ANGBAND_MSG_MSG_H

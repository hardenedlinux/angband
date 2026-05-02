#ifndef ANGBAND_NETLINK_H
#define ANGBAND_NETLINK_H

#include "common.h"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/veth.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define NL_ATTRBUF_SIZE 4096

int nl_create_socket(void);
int nl_send_msg(int fd, struct nlmsghdr *nlh);
int nl_recv_ack(int fd);
int nl_create_veth(int fd, const char *name1, const char *name2);
int nl_delete_link(int fd, const char *name);
int nl_create_macvlan(int fd, const char *name, const char *lower,
                      int mode, const unsigned char *macaddr, int macaddr_mode);
int nl_create_dummy(int fd, const char *name);

int nl_add_attr_max(struct nlmsghdr *nlh, unsigned short type,
                    const void *data, unsigned short len, size_t max_size);
int nl_add_str_attr_max(struct nlmsghdr *nlh, unsigned short type,
                        const char *str, size_t max_size);
void nl_init_msg(struct nlmsghdr *nlh, int type, int flags, int seq,
                 size_t max_size);

#endif

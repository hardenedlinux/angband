#include "netlink.h"
#include <sys/time.h>
#include <errno.h>

static unsigned int nl_seq;

void nl_init_msg(struct nlmsghdr *nlh, int type, int flags, int seq,
                 size_t max_size)
{
    memset(nlh, 0, max_size);
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlh->nlmsg_type  = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = 0;

    struct ifinfomsg *ifi = NLMSG_DATA(nlh);
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
}

int nl_add_attr_max(struct nlmsghdr *nlh, unsigned short type,
                    const void *data, unsigned short len, size_t max_size)
{
    unsigned short rta_len = RTA_LENGTH(len);
    if (NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta_len) > max_size)
        return -1;
    struct rtattr *rta = NLMSG_TAIL(nlh);
    rta->rta_type = type;
    rta->rta_len  = rta_len;
    if (data)
        memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta_len);
    return 0;
}

int nl_add_str_attr_max(struct nlmsghdr *nlh, unsigned short type,
                        const char *str, size_t max_size)
{
    return nl_add_attr_max(nlh, type, str, strlen(str) + 1, max_size);
}

int nl_create_socket(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int nl_send_msg(int fd, struct nlmsghdr *nlh)
{
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
    struct msghdr msg = {
        .msg_name    = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };
    return sendmsg(fd, &msg, 0);
}

int nl_recv_ack(int fd)
{
    char buf[32768];
    struct sockaddr_nl sa;
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg = {
        .msg_name    = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int ret = recvmsg(fd, &msg, 0);
    if (ret < 0) {
        fprintf(stderr, "  nl_recv_ack: recvmsg=%d errno=%d (%s)\n",
                ret, errno, strerror(errno));
        return -1;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = NLMSG_DATA(nlh);
        return err->error;
    }
    return 0;
}

static int nl_do_request(int fd, struct nlmsghdr *nlh)
{
    if (nl_send_msg(fd, nlh) < 0) return -1;
    return nl_recv_ack(fd);
}

int nl_create_veth(int fd, const char *name1, const char *name2)
{
    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifi;
        char             attrbuf[NL_ATTRBUF_SIZE];
    } req;
    size_t max = sizeof(req);

    nl_init_msg(&req.nlh, RTM_NEWLINK,
                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                ++nl_seq, max);

    /* IFLA_IFNAME for the first peer (MUST come before IFLA_LINKINFO) */
    nl_add_str_attr_max(&req.nlh, IFLA_IFNAME, name1, max);

    /* IFLA_LINKINFO with IFLA_INFO_KIND = "veth" */
    struct rtattr *linkinfo = NLMSG_TAIL(&req.nlh);
    nl_add_attr_max(&req.nlh, IFLA_LINKINFO, NULL, 0, max);
    nl_add_str_attr_max(&req.nlh, IFLA_INFO_KIND, "veth", max);

    /* IFLA_INFO_DATA with VETH_INFO_PEER containing peer IFLA attrs */
    struct rtattr *infodata = NLMSG_TAIL(&req.nlh);
    nl_add_attr_max(&req.nlh, IFLA_INFO_DATA, NULL, 0, max);

    /* VETH_INFO_PEER: contains IFLA_* attributes directly.
     * The peer device inherits IFLA_IFNAME, IFLA_ADDRESS, etc. from here.
     * There is NO ifinfomsg header inside -- just the nested attributes. */
    struct rtattr *peerinfo = NLMSG_TAIL(&req.nlh);
    nl_add_attr_max(&req.nlh, VETH_INFO_PEER, NULL, 0, max);

    /* Peer device's IFLA_IFNAME */
    nl_add_str_attr_max(&req.nlh, IFLA_IFNAME, name2, max);

    /* End VETH_INFO_PEER */
    peerinfo->rta_len = (void *)NLMSG_TAIL(&req.nlh) - (void *)peerinfo;

    /* End IFLA_INFO_DATA */
    infodata->rta_len = (void *)NLMSG_TAIL(&req.nlh) - (void *)infodata;

    /* End IFLA_LINKINFO */
    linkinfo->rta_len = (void *)NLMSG_TAIL(&req.nlh) - (void *)linkinfo;

    return nl_do_request(fd, &req.nlh);
}

int nl_create_macvlan(int fd, const char *name, const char *lower,
                      int mode, const unsigned char *macaddr,
                      int macaddr_mode)
{
    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifi;
        char             attrbuf[NL_ATTRBUF_SIZE];
    } req;
    size_t max = sizeof(req);

    int flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nl_init_msg(&req.nlh, RTM_NEWLINK, flags, ++nl_seq, max);

    int lower_idx = if_nametoindex(lower);
    if (lower_idx == 0) return -1;

    nl_add_attr_max(&req.nlh, IFLA_LINK, &lower_idx, sizeof(lower_idx), max);
    nl_add_str_attr_max(&req.nlh, IFLA_IFNAME, name, max);

    struct rtattr *linkinfo = NLMSG_TAIL(&req.nlh);
    nl_add_attr_max(&req.nlh, IFLA_LINKINFO, NULL, 0, max);
    nl_add_str_attr_max(&req.nlh, IFLA_INFO_KIND, "macvlan", max);

    struct rtattr *infodata = NLMSG_TAIL(&req.nlh);
    nl_add_attr_max(&req.nlh, IFLA_INFO_DATA, NULL, 0, max);

    nl_add_attr_max(&req.nlh, IFLA_MACVLAN_MODE, &mode, sizeof(mode), max);

    if (macaddr_mode && macaddr) {
        nl_add_attr_max(&req.nlh, IFLA_MACVLAN_MACADDR_MODE,
                        &macaddr_mode, sizeof(macaddr_mode), max);
        nl_add_attr_max(&req.nlh, IFLA_MACVLAN_MACADDR, macaddr, 6, max);
    }

    infodata->rta_len = (void *)NLMSG_TAIL(&req.nlh) - (void *)infodata;
    linkinfo->rta_len = (void *)NLMSG_TAIL(&req.nlh) - (void *)linkinfo;

    return nl_do_request(fd, &req.nlh);
}

int nl_delete_link(int fd, const char *name)
{
    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifi;
        char             attrbuf[256];
    } req;
    size_t max = sizeof(req);

    nl_init_msg(&req.nlh, RTM_DELLINK,
                NLM_F_REQUEST | NLM_F_ACK, ++nl_seq, max);

    int idx = if_nametoindex(name);
    if (idx == 0) return -1;

    struct ifinfomsg *ifi = NLMSG_DATA(&req.nlh);
    ifi->ifi_index = idx;

    return nl_do_request(fd, &req.nlh);
}

int nl_create_dummy(int fd, const char *name)
{
    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifi;
        char             attrbuf[NL_ATTRBUF_SIZE];
    } req;
    size_t max = sizeof(req);

    nl_init_msg(&req.nlh, RTM_NEWLINK,
                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                ++nl_seq, max);

    nl_add_str_attr_max(&req.nlh, IFLA_IFNAME, name, max);

    struct rtattr *linkinfo = NLMSG_TAIL(&req.nlh);
    nl_add_attr_max(&req.nlh, IFLA_LINKINFO, NULL, 0, max);
    nl_add_str_attr_max(&req.nlh, IFLA_INFO_KIND, "dummy", max);
    linkinfo->rta_len = (void *)NLMSG_TAIL(&req.nlh) - (void *)linkinfo;

    return nl_do_request(fd, &req.nlh);
}

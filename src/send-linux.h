/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef ZMAP_SEND_LINUX_H
#define ZMAP_SEND_LINUX_H

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <liburing.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "../lib/includes.h"
#include "./send.h"


#ifdef ZMAP_SEND_BSD_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

// Dummy sockaddr for sendto
static struct sockaddr_ll sockaddr;

// Used internally to decide to send packets with liburing or send_mmsg
static bool use_liburing;
__thread struct io_uring ring;
#define QUEUE_DEPTH 128 // ring buffer size for liburing's submission queue
#define SQ_POLLING_IDLE_TIMEOUT 1000 // how long kernel thread will wait before timing out
// io_uring is an async I/O package. In send_packet, the caller passes in a pointer to a buffer. We'll create a submission queue entry (sqe) using this buffer and put it on the sqe ring buffer.
// However, then we then immediately return to the caller which re-uses this buffer.
// We need to create a data-structure to persist this data so it can be sent async and the caller can reuse the buffer
struct data_and_metadata
{
    char buf[MAX_PACKET_SIZE];
    struct msghdr msg;
    struct iovec iov;
};
__thread struct data_and_metadata* data_arr;
// points to an open buffer in buf_array
__thread uint16_t free_buffer_ptr = 0;
__thread struct io_uring_cqe* cqe;

int send_run_init(sock_t s, uint32_t kernel_cpu, bool is_liburing_enabled);
int send_batch(sock_t sock, batch_t* batch, int retries);
int send_run_cleanup(void);



#endif /* ZMAP_SEND_LINUX_H */

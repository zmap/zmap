/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef SEND_H
#define SEND_H

#include "iterator.h"
#include "socket.h"

#include <assert.h>

iterator_t *send_init(void);
int send_run(sock_t, shard_t *);

// Fit two packets with metadata into one 4k page.
// 2k seems like more than enough with typical MTU of
// 1500, and we don't want to cause IP fragmentation.
#define MAX_PACKET_SIZE (2048 - sizeof(uint32_t) - 2 * sizeof(uint8_t))

// Metadata and initial packet bytes are adjacent,
// for cache locality esp. with short packets.
// buf is aligned such that the end of the Ethernet
// header and beginning of the IP header will align
// to a 32 bit boundary, such that reading/writing
// IP addresses and other 32 bit header fields is
// properly aligned.
struct batch_packet {
	uint32_t len;
	uint8_t unused[2];
	uint8_t buf[MAX_PACKET_SIZE];
};

static_assert((offsetof(struct batch_packet, buf) + sizeof(struct ether_header)) % sizeof(uint32_t) == 0,
	      "buf is aligned such that IP header is 32-bit aligned");

typedef struct {
	struct batch_packet *packets;
	uint16_t len;
	uint16_t capacity;
} batch_t;

batch_t *create_packet_batch(uint16_t capacity);
void free_packet_batch(batch_t *batch);

#endif // SEND_H

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
#include "./probe_modules/packet.h"

iterator_t *send_init(void);
int send_run(sock_t, shard_t *, uint32_t kernel_cpu);

typedef struct {
	char* packets;
	uint32_t* ips;
	int* lens;
	uint8_t len;
	uint8_t capacity;
}batch_t;

batch_t* create_packet_batch(uint8_t capacity);
void free_packet_batch(batch_t* batch);

#endif // SEND_H

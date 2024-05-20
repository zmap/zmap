/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef SEND_INTERNAL_H
#define SEND_INTERNAL_H

#include "socket.h"

int send_run_init(sock_t s);
int send_batch(sock_t sock, batch_t *batch, int retries);

#if defined(PFRING)
#include "send-pfring.h"
#elif defined(NETMAP)
void submit_batch_internal(batch_t *batch);
int send_batch_internal(sock_t sock, batch_t *batch);
#elif defined(__linux__)
#include "send-linux.h"
#endif

#endif // SEND_INTERNAL_H

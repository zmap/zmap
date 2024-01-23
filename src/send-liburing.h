/*
 * ZMap Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef ZMAP_DEV_SEND_LIBURING_H
#define ZMAP_DEV_SEND_LIBURING_H

#include <sys/socket.h>

#include <./send.h>

int send_run_init_liburing(uint32_t kernel_cpu);
int send_batch_liburing_helper(sock_t sock, batch_t* batch);
int send_run_cleanup_liburing(void);

#endif //ZMAP_DEV_SEND_LIBURING_H
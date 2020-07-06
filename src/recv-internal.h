/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_RECV_INTERNAL_H
#define ZMAP_RECV_INTERNAL_H

#include <stdint.h>

void handle_packet(uint32_t buflen, const uint8_t *bytes, const struct timespec ts);
void recv_init();
void recv_packets();
void recv_cleanup();

#endif /* ZMAP_RECV_INTERNAL_H */

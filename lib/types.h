/*
 * Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ZMAP_TYPES_H
#define ZMAP_TYPES_H

#include <stdint.h>

#include <stdint.h>

typedef uint32_t ipaddr_n_t; // IPv4 address network order
typedef uint32_t ipaddr_h_t; // IPv4 address host order
typedef uint16_t port_n_t;   // port network order
typedef uint16_t port_h_t;   // port host order
typedef unsigned char macaddr_t;

#endif /* ZMAP_TYPES_H */

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

#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wflexible-array-extensions"
#include <dnet.h>
#pragma GCC diagnostic warning "-Wflexible-array-extensions"
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD 2
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#if defined(__NetBSD__)
#define ICMP_UNREACH_PRECEDENCE_CUTOFF ICMP_UNREACH_PREC_CUTOFF
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h> // NOTE: net/if.h MUST be included BEFORE ifaddrs.h
#include <arpa/inet.h>

#define MAC_ADDR_LEN ETHER_ADDR_LEN
#define UNUSED __attribute__((unused))

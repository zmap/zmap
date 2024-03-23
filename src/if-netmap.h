/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_IF_NETMAP_H
#define ZMAP_IF_NETMAP_H

// Platform-specific functionality required for NETMAP.

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

// Wait until a NICs PHY has reset and the interface is ready for sending
// packets again.  Must be called after the reset has begun.  Upon return, the
// interface is ready for sending packets.  Exits on timeout.
//
// *ifname* is the name of the interface.
// *fd* is the file descriptor to the main netmap socket.
void if_wait_for_phy_reset(char const *ifname, int fd);

// Get the size of the link layer header for the interface.
//
// *ifname* is the name of the interface.
// *fd* is the file descriptor to the main netmap socket.
size_t if_get_data_link_size(char const *ifname, int fd);

// Opaque context for the if_stats_* set of functions.
struct if_stats_ctx;
typedef struct if_stats_ctx if_stats_ctx_t;

// Initialise interface statistics.
//
// *ifname* is the name of the interface.
// *fd* is the file descriptor to the netmap socket used for recv.
if_stats_ctx_t *if_stats_init(char const *ifname, int fd);

// Returns true if the count of received packets is available
// through if_stats_get(), false otherwise.  If this returns
// false, the caller will need to count received packets.
bool if_stats_have_recv_ctr(if_stats_ctx_t *ctx);

// Get recv, drop and ifdrop counters.
// Some interfaces do not report any received packets while in
// netmap mode.  In that case, *ps_recv* will not be set.
// Check if_stats_have_recv_ctr() for whether the interface
// supports received packet count in netmap mode.
int if_stats_get(if_stats_ctx_t *ctx, uint32_t *ps_recv, uint32_t *ps_drop, uint32_t *ps_ifdrop);

// Clean up and invalidate the if_stats_* context.
void if_stats_fini(if_stats_ctx_t *ctx);

#endif /* ZMAP_IF_NETMAP_H */

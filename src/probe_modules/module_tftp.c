/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "../../lib/xalloc.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "module_udp.h"

#define TFTP_QUERY "\0\1ay9mfwq7xxmd4w6cz\0octet\0" // try to read random filename
static const char *tftp_query = TFTP_QUERY;
static const long unsigned int tftp_query_len = sizeof(TFTP_QUERY) - 1; // -1 for terminating zero

probe_module_t module_tftp;

int tftp_global_initialize(struct state_conf *state)
{
    int num_ports = state->source_port_last - state->source_port_first + 1;
    udp_set_num_ports(num_ports);
    return EXIT_SUCCESS;
}

int tftp_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
            port_h_t dst_port,
            __attribute__((unused)) void **arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);
    struct ether_header *eth_header = (struct ether_header *)buf;
    make_eth_header(eth_header, src, gw);
    struct ip *ip_header = (struct ip *)(&eth_header[1]);

    uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) +
                 tftp_query_len);
    make_ip_header(ip_header, IPPROTO_UDP, len);

    struct udphdr *udp_header = (struct udphdr *)(&ip_header[1]);
    len = sizeof(struct udphdr) + tftp_query_len;
    make_udp_header(udp_header, dst_port, len);

    char *payload = (char *)(&udp_header[1]);

    assert(sizeof(struct ether_header) + sizeof(struct ip) +
           sizeof(struct udphdr) + tftp_query_len <=
           MAX_PACKET_SIZE);

    assert(MAX_PACKET_SIZE - ((char *)payload - (char *)buf) >
           (int)tftp_query_len);
    memcpy(payload, tftp_query, tftp_query_len);

    return EXIT_SUCCESS;
}

int tftp_validate_packet(const struct ip *ip_hdr, uint32_t len,
             uint32_t *src_ip, uint32_t *validation)
{
    if ((ip_hdr->ip_p != IPPROTO_UDP) && (ip_hdr->ip_p != IPPROTO_ICMP)) {
        return PACKET_INVALID;
    }
    return PACKET_VALID;
}

void tftp_process_packet(const u_char *packet,
             __attribute__((unused)) uint32_t len, fieldset_t *fs,
             __attribute__((unused)) uint32_t *validation)
{
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    struct udphdr *udp =
            (struct udphdr *)((char *)ip_hdr + ip_hdr->ip_hl * 4);
    char *payload = (char *)(&udp[1]);
    uint16_t plen = ntohs(udp->uh_ulen);

    if (ip_hdr->ip_p == IPPROTO_UDP && plen > 1 && payload[0] == 0 && payload[1] == 5) {
        fs_add_string(fs, "classification", (char *)"TFTP", 0);
        fs_add_bool(fs, "success", 1);
        fs_add_binary(fs, "data",
                  (ntohs(udp->uh_ulen) - sizeof(struct udphdr)),
                  (void *)&udp[1], 0);
    } else {
        fs_add_string(fs, "classification", (char *)"other", 0);
        fs_add_bool(fs, "success", 0);
        fs_add_null(fs, "data");
    }
}

static fielddef_t fields[] = {
    {.name = "classification",
     .type = "string",
     .desc = "packet classification"},
    {.name = "success",
     .type = "bool",
     .desc = "is response considered success"},
    {.name = "data", .type = "binary", .desc = "UDP payload"}};

probe_module_t module_tftp = {
    .name = "tftp",
    .packet_length = 125,
    .pcap_filter = "udp || icmp",
    .pcap_snaplen = 2048,
    .port_args = 1,
    .global_initialize = &tftp_global_initialize,
    .thread_initialize = &tftp_init_perthread,
    .make_packet = &udp_make_packet,
    .print_packet = &udp_print_packet,
    .process_packet = &tftp_process_packet,
    .validate_packet = &tftp_validate_packet,
    // UPnP isn't actually dynamic, however, we don't handle escaping
    // properly in the CSV module and this will force users to use JSON.
    .output_type = OUTPUT_TYPE_DYNAMIC,
    .close = NULL,
    .helptext = "Probe module that sends a TFTP read request for random filename and expects TFTP error packet in response.",
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};
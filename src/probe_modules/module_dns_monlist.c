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
#include <stdbool.h>

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "../../lib/xalloc.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "module_udp.h"
#include "../murmur3.h"

// Based on zgrab2/modules/dns/scanner.go
// https://kb.iweb.com/hc/en-us/articles/230267428-Guide-to-DNS-Open-Recursion-Amplification-Issues
// https://www.us-cert.gov/ncas/alerts/TA13-088A
// dig +short test.openresolver.com TXT @216.59.57.99
// sudo nmap -sU -p 53 -sV -P0 --script "dns-recursion" 8.8.4.4
// DNSSEC and its potential for DDoS attacks: a comprehensive measurement study 10.1145/2663716.2663731
// We use REQ_MON_GETLIST_1 because it gets more responses than REQ_MON_GETLIST
// and servers that respond to former almost always respond to latter.

// 12 is header size, see rfc1035 4.1.1
#define DNS_HEADER_SIZE 12

// see https://github.com/packetloop/zgrab2/blob/master/modules/dns/scanner.go#L103
#define REQ_MON_GETLIST_1_QUERY "\xf7\x23\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x09\x77\x69\x6b\x69\x70\x65\x64\x69\x61\x03\x6f\x72\x67\x00\x00\x01\x00\x01"
static const char *dns_monlist_query = REQ_MON_GETLIST_1_QUERY;
static const long unsigned int dns_monlist_query_len = sizeof(REQ_MON_GETLIST_1_QUERY) - 1; // -1 for terminating zero

probe_module_t module_dns_monlist;

static int num_ports;
void dns_monlist_set_num_ports(int x) { num_ports = x; }

int dns_monlist_global_initialize(struct state_conf *conf)
{
    int num_ports = conf->source_port_last - conf->source_port_first + 1;
    dns_monlist_set_num_ports(num_ports);

    return EXIT_SUCCESS;
}

int dns_monlist_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
            port_h_t dst_port,
            __attribute__((unused)) void **arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);
    struct ether_header *eth_header = (struct ether_header *)buf;
    make_eth_header(eth_header, src, gw);
    struct ip *ip_header = (struct ip *)(&eth_header[1]);

    uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) +
                 dns_monlist_query_len);
    make_ip_header(ip_header, IPPROTO_UDP, len);

    struct udphdr *udp_header = (struct udphdr *)(&ip_header[1]);
    len = sizeof(struct udphdr) + dns_monlist_query_len;
    make_udp_header(udp_header, dst_port, len);

    char *payload = (char *)(&udp_header[1]);

    assert(sizeof(struct ether_header) + sizeof(struct ip) +
           sizeof(struct udphdr) + dns_monlist_query_len <=
           MAX_PACKET_SIZE);

    assert(MAX_PACKET_SIZE - ((char *)payload - (char *)buf) >
           (int)dns_monlist_query_len);
    memcpy(payload, dns_monlist_query, dns_monlist_query_len);

    return EXIT_SUCCESS;
}

int dns_monlist_make_packet(void *buf, UNUSED size_t *buf_len, ipaddr_n_t src_ip,
            ipaddr_n_t dst_ip, uint32_t *validation, int probe_num,
            __attribute__((unused)) void *arg)
{
    struct ether_header *eth_header = (struct ether_header *)buf;
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    struct udphdr *udp_header = (struct udphdr *)&ip_header[1];

    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    udp_header->uh_sport =
        htons(get_src_port(num_ports, probe_num, validation));

    // make random transaction id(first 2 bytes)
    uint16_t *transaction_id = (uint16_t *)&udp_header[1];
    *transaction_id = probe_num; // much faster than AES random number generator, just as good for this

    ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

    return EXIT_SUCCESS;
}

int dns_monlist_validate_packet(const struct ip *ip_hdr, uint32_t len,
             uint32_t *src_ip, uint32_t *validation)
{
    if (!udp_validate_packet(ip_hdr, len, src_ip, validation)) {
        return PACKET_INVALID;
    }

    return PACKET_VALID;
}

void dns_monlist_process_packet(const u_char *packet,
             __attribute__((unused)) uint32_t len, fieldset_t *fs,
             __attribute__((unused)) uint32_t *validation)
{
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    struct udphdr *udp =
            (struct udphdr *)((char *)ip_hdr + ip_hdr->ip_hl * 4);
    char *payload = (char *)(&udp[1]);
    uint16_t data_len = ntohs(udp->uh_ulen);
    uint32_t overhead = (sizeof(struct udphdr) + (ip_hdr->ip_hl * 4));
    uint32_t max_rlen = len - overhead;
    uint32_t max_ilen = ntohs(ip_hdr->ip_len) - overhead;
    // Verify that the UDP length is inside of our received
    // buffer
    if (data_len > max_rlen) {
        data_len = max_rlen;
    }
    // Verify that the UDP length is inside of our IP packet
    if (data_len > max_ilen) {
        data_len = max_ilen;
    }

    if (ip_hdr->ip_p == IPPROTO_UDP && data_len >= DNS_HEADER_SIZE) {
        // QR == 1 and RA == 1 and RCODE == 0 - is response and recursion available and no error, see rfc1035 4.1.1(page 26)
        if (((payload[2] & 0x80) == 0x80) && ((payload[3] & 0x85) == 0x80)) {
            fs_add_string(fs, "classification", (char *)"monlist", 0);
            fs_add_bool(fs, "success", 1);
        } else {
            fs_add_string(fs, "classification", (char *)"dns", 0);
            fs_add_bool(fs, "success", 0);
        }
        fs_add_uint64(fs, "udp_pkt_size", data_len + 8);
        uint64_t hash[2];
        MurmurHash3_x86_128(payload + 2, data_len - 2, 0, hash); // we skip transaction_id
        fs_add_uint64(fs, "payload_hash", hash[0]);
        fs_add_uint64(fs, "sport", ntohs(udp->uh_sport));
        fs_add_uint64(fs, "dport", ntohs(udp->uh_dport));
        //fs_add_binary(fs, "data",
        //          (ntohs(udp->uh_ulen) - sizeof(struct udphdr)),
        //          (void *)&udp[1], 0);
    } else {
        fs_add_string(fs, "classification", (char *)"other", 0);
        fs_add_bool(fs, "success", 0);
        fs_add_null(fs, "udp_pkt_size");
        fs_add_null(fs, "payload_hash");
        fs_add_null(fs, "sport");
        fs_add_null(fs, "dport");
    }
}

static fielddef_t fields[] = {
    {.name = "classification",
     .type = "string",
     .desc = "packet classification"},
    {.name = "success",
     .type = "bool",
     .desc = "is response considered success"},
    {.name = "udp_pkt_size", .type = "int", .desc = "Total amount of response bytes"}, // as in udp probe
    {.name = "payload_hash", .type = "int", .desc = "Hash of payload"},
    {.name = "sport", .type = "int", .desc = "UDP source port"},
    {.name = "dport", .type = "int", .desc = "UDP destination port"}};

probe_module_t module_dns_monlist = {
    .name = "dns_monlist",
    .packet_length = 1024,
    .pcap_filter = "udp || icmp",
    .pcap_snaplen = 8 * 1024,
    .port_args = 1,
    .global_initialize = &dns_monlist_global_initialize,
    .thread_initialize = &dns_monlist_init_perthread,
    .make_packet = &dns_monlist_make_packet,
    .print_packet = &udp_print_packet,
    .process_packet = &dns_monlist_process_packet,
    .validate_packet = &dns_monlist_validate_packet,
    .output_type = OUTPUT_TYPE_STATIC,
    .close = NULL,
    .helptext = "Probe module that sends a DNS monlist request for wikipedia.org.",
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};
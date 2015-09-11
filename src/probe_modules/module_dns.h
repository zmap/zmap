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

typedef struct __attribute__((packed)) {
    uint16_t id;       /* transaction ID */
    uint16_t rd:1;     /* recursion desired */
    uint16_t tc:1;     /* truncation */
    uint16_t aa:1;     /* authoritative answer */
    uint16_t opcode:4; /* opcode 0=std query 1=Inverse query 2=srv status request */
    uint16_t qr:1;     /* query/response */
    
    uint16_t rcode:4;  /* response code */
    uint16_t cd :1;    /* checking disabled */
    uint16_t ad :1;    /* authenticated data */
    uint16_t z:1;      /* reserved set to 0 */
    uint16_t ra:1;     /* recursion available */

    uint16_t qdcount;  /* # entries in question section */
    uint16_t ancount;  /* # RR in answer section */
    uint16_t nscount;  /* # name server RR in authority section */
    uint16_t arcount;  /* # RR in additional information section */
} dns_header;

typedef struct __attribute__((packed)) {
    uint16_t qtype;
    uint16_t qclass;
} dns_question_tail;

// XXX
typedef struct __attribute__((packed)) {
    uint16_t name;
    uint16_t type;
    uint16_t addr_class;
    uint32_t ttl;
    uint16_t length;
    uint32_t addr;
} dnsans;

typedef enum {
    DNS_QTYPE_A     = 1,
    DNS_QTYPE_NS    = 2,
    DNS_QTYPE_CNAME = 5,
    DNS_QTYPE_SOA   = 6,
    DNS_QTYPE_PTR   = 12,
    DNS_QTYPE_MX    = 15,
    DNS_QTYPE_TXT   = 16,
    DNS_QTYPE_AAAA  = 28,
    DNS_QTYPE_RRSIG = 46,
    DNS_QTYPE_ALL   = 255
} dns_qtype;

// XXX here until end

#define DNS_QR_QUERY    0   /* Msg is a dns query */
#define DNS_QR_ANSWER   1   /* Msg is a dns answer */

#define DNS_OPCODE_STDQUERY 0   /* Msg is a standard query */
#define DNS_OPCODE_INVQUERY 1   /* Msg is a inverse query */
#define DNS_OPCODE_SRVSTATUS    2   /* Msg is a server status query */

#define DNS_RCODE_NOERR     0   /* Response code NO ERROR */
#define DNS_RCODE_FORMATERR 1   /* Response code NO ERROR */
#define DNS_RCODE_SRVFAILURE    2   /* Response code NO ERROR */
#define DNS_RCODE_NXDOMAIN  3   /* Response code NO ERROR */
#define DNS_RCODE_QTYPENOTIMPL  4   /* Response code NO ERROR */
#define DNS_RCODE_QRYREFUSED    5   /* Response code NO ERROR */

void dns_print_packet(FILE *fp, void* packet);

int dns_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
        uint32_t *validation, int probe_num, void *arg);

int dns_validate_packet(const struct ip *ip_hdr, uint32_t len,
        __attribute__((unused))uint32_t *src_ip, uint32_t *validation);

extern const char *udp_unreach_strings[];

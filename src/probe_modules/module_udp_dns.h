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

struct dnshdr
{
  u_int16_t id;		/* transaction ID */

#  if __BYTE_ORDER == __LITTLE_ENDIAN
  u_int16_t rd:1;	/* recursion desired */
  u_int16_t tc:1;	/* truncation */
  u_int16_t aa:1;	/* authoritative answer */
  u_int16_t opcode:4;	/* opcode 0=std query 1=Inverse query 2=srv status request */
  u_int16_t qr:1;	/* query/response */
  u_int16_t rcode:4;	/* response code */
  u_int16_t cd :1;      /* checking disabled */
  u_int16_t ad :1;      /* authenticated data */
  u_int16_t z:1;	/* reserved set to 0 */
  u_int16_t ra:1;	/* recursion available */
#  endif

#  if __BYTE_ORDER == __BIG_ENDIAN
  u_int16_t qr:1;	/* query/response */
  u_int16_t opcode:4;	/* opcode 0=std query 1=Inverse query 2=srv status request */
  u_int16_t aa:1;	/* authoritative answer */
  u_int16_t tc:1;	/* truncation */
  u_int16_t rd:1;	/* recursion desired */
  u_int16_t ra:1;	/* recursion available */
  u_int16_t z:3;	/* reserved set to 0 */
  u_int16_t rcode:4;	/* response code */
#  endif

  u_int16_t qdcount;	/* # entries in question section */
  u_int16_t ancount;	/* # RR in answer section */
  u_int16_t nscount;	/* # name server RR in authority section */
  u_int16_t arcount;	/* # RR in additional information section */
};

#define DNS_QR_QUERY	0	/* Msg is a dns query */
#define DNS_QR_ANSWER	1	/* Msg is a dns answer */

#define DNS_OPCODE_STDQUERY	0	/* Msg is a standard query */
#define DNS_OPCODE_INVQUERY	1	/* Msg is a inverse query */
#define DNS_OPCODE_SRVSTATUS	2	/* Msg is a server status query */

#define DNS_RCODE_NOERR		0	/* Response code NO ERROR */
#define DNS_RCODE_FORMATERR	1	/* Response code NO ERROR */
#define DNS_RCODE_SRVFAILURE	2	/* Response code NO ERROR */
#define DNS_RCODE_NXDOMAIN	3	/* Response code NO ERROR */
#define DNS_RCODE_QTYPENOTIMPL	4	/* Response code NO ERROR */
#define DNS_RCODE_QRYREFUSED	5	/* Response code NO ERROR */

void udp_dns_print_packet(FILE *fp, void* packet);

int udp_dns_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip, 
		uint32_t *validation, int probe_num);

int udp_dns_validate_packet(const struct ip *ip_hdr, uint32_t len, 
		__attribute__((unused))uint32_t *src_ip, uint32_t *validation);

extern const char *udp_dns_unreach_strings[];

void udp_dns_set_num_ports(int x);

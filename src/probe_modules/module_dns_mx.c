/*
  ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// send module for performing massive UDP DNS OpenResolver scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../lib/includes.h"
#include "../../lib/random.h"
#include "probe_modules.h"
#include "packet.h"
#include "logger.h"
#include "module_udp.h"
#include "module_dns_mx.h"

#define MAX_UDP_PAYLOAD_LEN 1472
#define UNUSED __attribute__((unused))
#define DNS_HEAD_LEN 12
#define DNS_TAIL_LEN 4

//static char *udp_send_msg = NULL;
//static int udp_send_msg_len = 0;
//static int udp_send_substitutions = 0;

// std query recursive for www.google.com type A
// HEADER 12 bytes
// \random -> TransactionID
// \x01\x20 -> Flags: 0x Standard query (0100?)
// \x00\x01 -> Questions: 1
// \x00\x00 -> Answer RRs: 0
// \x00\x00 -> Authority RRs: 0
// \x00\x00 -> Additional RRs: 0
// DOMAIN NAME 16 bytes
// default will be replaced by passed in argument
// \x05\x67\x6d\x61\x69\x6c\x03\x63\x6f\x6d\x00
// TAILER 4 bytes
// \x00\x0f -> Type: MX (Mail Exchange)
// \x00\x01 -> Class: IN (0x0001)

//default sends to gmail.com
//static const char dns_msg_default[] = {0xd2,0x8c,0x01,0x20,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x05,0x67,0x6d,0x61,0x69,0x6c,0x03,0x63,0x6f,0x6d,0x00,0x00,0x0f,0x00,0x01,0x00,0x00,0x29,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

// ;; alt1
static const unsigned char dns_msg_default[] = {0xb9, 0x58, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x61, 0x6c, 0x74, 0x34, 0x0d, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2d, 0x73, 0x6d, 0x74, 0x70, 0x2d, 0x69, 0x6e, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};

const char *dns_response_strings[] = {
    "DNS no error",
    "DNS format error",
    "DNS server failure",
    "DNS domain name error",
    "DNS query type not implemented",
    "DNS query refused",
    "DNS Reserved 6",
    "DNS Reserved 7",
    "DNS Reserved 8",
    "DNS Reserved 9",
    "DNS Reserved 10",
    "DNS Reserved 11",
    "DNS Resevered 12",
    "DNS Resevered 13",
    "DNS Resevered 14",
    "DNS Resevered 15"
};

probe_module_t module_dns_mx;
static int num_ports;

int dns_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
        uint32_t *validation, int probe_num, __attribute__((unused)) void *arg) {

    struct ether_header *eth_header = (struct ether_header *) buf;
    struct ip *ip_header = (struct ip*) (&eth_header[1]);
    struct udphdr *udp_header= (struct udphdr *) &ip_header[1];

    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    udp_header->uh_sport = htons(get_src_port(num_ports, probe_num, validation));
    
    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

    fprintf(stderr, "make packet finished\n");
    return EXIT_SUCCESS;
}

int dns_init_perthread(void* buf, macaddr_t *src,
        macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,
        __attribute__((unused)) void **arg_ptr) {
    fprintf(stderr, "in init_perthread\n");
    memset(buf, 0, MAX_PACKET_SIZE);
    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);
    struct ip *ip_header = (struct ip*)(&eth_header[1]);
    uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) + sizeof(dns_msg_default));
    make_ip_header(ip_header, IPPROTO_UDP, len);

    struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
    len = sizeof(struct udphdr) + sizeof(dns_msg_default);
    make_udp_header(udp_header, zconf.target_port, len);

    char* payload = (char*)(&udp_header[1]);
    module_dns_mx.packet_length = sizeof(struct ether_header) + sizeof(struct ip)
                + sizeof(struct udphdr) + sizeof(dns_msg_default);
    assert(module_dns_mx.packet_length <= MAX_PACKET_SIZE);
    
    memcpy(payload, dns_msg_default, sizeof(dns_msg_default));

    uint32_t seed = aesrand_getword(zconf.aes);
    aesrand_t *aes = aesrand_init_from_seed(seed);
    *arg_ptr = aes;

    return EXIT_SUCCESS;
}


void dns_print_packet(FILE *fp, void* packet) {
    struct ether_header *ethh = (struct ether_header *) packet;
    struct ip *iph = (struct ip *) &ethh[1];
    struct udphdr *udph  = (struct udphdr*) (iph + 4*iph->ip_hl);
    fprintf(fp, "udp_dns { source: %u | dest: %u | checksum: %u }\n",
        ntohs(udph->uh_sport),
        ntohs(udph->uh_dport),
        ntohl(udph->uh_sum));
    fprintf_ip_header(fp, iph);
    fprintf_eth_header(fp, ethh);
    fprintf(fp, "------------------------------------------------------\n");
}

int dns_validate_packet(const struct ip *ip_hdr, uint32_t len,
        uint32_t *src_ip, uint32_t *validation)
{
    if (!udp_validate_packet(ip_hdr, len, src_ip, validation)) {
        return 0;
    }
    if (ip_hdr->ip_p == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
        uint16_t sport = ntohs(udp->uh_sport);
        if (sport != zconf.target_port) {
            return 0;
        }
    }
    return 1;
}

//void remove_erroneous_characters(char* input, int length){
//    int i =0;
//    char[1] slash = "\\";
//    char* to_return;
//    to_return = malloc(sizeof(char)*length);
//    for(i; i < length; i++){
//        if strncmp(input[i], slash, 1){
//            
//        }
//    }
//}

void dns_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs) {
    struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];    
    //char char2[2];
    //char query_num[2];
    if(ip_hdr->ip_p == IPPROTO_UDP){
       struct udphdr *udp = (struct udphdr*) ((char*) ip_hdr+ip_hdr->ip_hl * 4);
        uint8_t *ptr = (uint8_t *) &udp[1];
        if(len >= 69){ 
        fs_add_string(fs, "classification", (char*) "dns_mx", 0);
        fs_add_uint64(fs, "success", 1);
        fs_add_uint64(fs, "sport", ntohs(udp->uh_sport));
        fs_add_uint64(fs, "dport", ntohs(udp->uh_dport));
        fs_add_null(fs, "icmp_responder");
        fs_add_null(fs, "icmp_type");
        fs_add_null(fs, "icmp_code");
        fs_add_null(fs, "icmp_unreach_str");
//        memcpy(char2, ptr, 2);
//        temp16 = ntohs(*((uint16_t *)ptr+1));
//        fs_add_uint64(fs, "query_response", temp16);
//        temp16 = ntohs(*((uint16_t *)ptr+2));
//        fs_add_uint64(fs, "query_num", temp16);
//        temp16 = ntohs(*((uint16_t *)ptr+3));
//        fs_add_uint64(fs, "answers_rrs", temp16);
//        temp16 = ntohs(*((uint16_t *)ptr+4));
//        fs_add_uint64(fs, "authority_rrs", temp16);
//        temp16 = ntohs(*((uint16_t *)ptr+5));
//        fs_add_uint64(fs, "additional_rrs", temp16);
//        //for(i; i<2; i++){
//        //    fprintf(stderr, "byte %i %02x", i, char2[i]);
//        //}
//        //fs_add_uint64(fs, "query_response", *char2); 
//        //memcpy(query_num, (ptr+2), 2);
//        //for(i=0; i<2; i++){
//        //    fprintf(stderr, "byte %i %02x", i, *query_num);
//        //}
//        //fs_add_uint64(fs, "query_num", *query_num);
//        //memcpy(answer_rrs, (ptr+4), 2);
//        //fs_add_uint64(fs, "answer_rrs", *answer_rrs); 
//        //memcpy(authority_rrs, (ptr+6), 2);
//        //fs_add_uint64(fs, "authority_rrs", *authority_rrs); 
//        //memcpy(additional_rrs, (ptr+8), 2);
//        //fs_add_uint64(fs, "additional_rrs", *additional_rrs); 
//        //memcpy(char2, (ptr+10), 2);
//        
//        //27 bytes
//        data = malloc(sizeof(char)*(len - 69));
//        //fs_add_uint64(fs, "answers", data);
        fs_add_binary(fs, "answers", (len-42), (void *)&ptr[0], 0);
        //memcpy(data, (ptr+14), len-35);
        //fs_add_binary(fs, "answers", len-35, data, 0);
//        fs_add_null(fs, "query_num");
//        fs_add_null(fs, "answer_rrs");
//        fs_add_null(fs, "authority_rrs");
//        fs_add_null(fs, "additional_rrs");
//        fs_add_null(fs, "answers");
//        free(char2);
//        free(query_num);
//        free(answer_rrs);
//        free(authority_rrs);
//        free(additional_rrs);
//        free(data);
        }else{

            fs_add_string(fs, "classification", (char*) "dns_mx", 0);
            fs_add_uint64(fs, "success", 0);
            fs_add_uint64(fs, "sport", ntohs(udp->uh_sport));
            fs_add_uint64(fs, "dport", ntohs(udp->uh_dport));
            fs_add_null(fs, "icmp_responder");
            fs_add_null(fs, "icmp_type");
            fs_add_null(fs, "icmp_code");
            fs_add_null(fs, "icmp_unreach_str");
            fs_add_null(fs, "answers");
//            fs_add_null(fs, "query_response");
//            fs_add_null(fs, "query_num");
//            fs_add_null(fs, "answer_rrs");
//            fs_add_null(fs, "authority_rrs");
//            fs_add_null(fs, "additional_rrs");
//            fs_add_null(fs, "answers");
        }

    }else if (ip_hdr->ip_p == IPPROTO_ICMP){
        struct icmp *icmp = (struct icmp *) ((char *) ip_hdr + ip_hdr -> ip_hl *4); 
        struct ip *ip_inner = (struct ip *) &icmp[1];
        fs_modify_string(fs, "saddr", make_ip_str(ip_inner->ip_dst.s_addr), 1);
        fs_add_string(fs, "classification", (char*) "icmp-unreach", 0);
        fs_add_uint64(fs, "success", 0);
        fs_add_null(fs, "sport");
        fs_add_null(fs, "dport");
        fs_add_string(fs, "icmp_responder", make_ip_str(ip_hdr->ip_src.s_addr), 1);
        fs_add_uint64(fs, "icmp_type", icmp->icmp_type);
        fs_add_uint64(fs, "icmp_code", icmp->icmp_code);
        fs_add_null(fs, "icmp_unreach_str");
        
//        fs_add_null(fs, "query_response");
//        fs_add_null(fs, "query_num");
//        fs_add_null(fs, "answer_rrs");
//        fs_add_null(fs, "authority_rrs");
//        fs_add_null(fs, "additional_rrs");
        fs_add_null(fs, "answers");
        
    }else{
        fs_add_string(fs, "classification", (char*) "other", 0);
        fs_add_uint64(fs, "success", 0);
        fs_add_null(fs, "sport");
        fs_add_null(fs, "dport");
        fs_add_null(fs, "icmp_responder");
        fs_add_null(fs, "icmp_type");
        fs_add_null(fs, "icmp_code");
        fs_add_null(fs, "icmp_unreach_str");
        
//        fs_add_null(fs, "query_response");
//        fs_add_null(fs, "query_num");
//        fs_add_null(fs, "answer_rrs");
//        fs_add_null(fs, "authority_rrs");
//        fs_add_null(fs, "additional_rrs");
        fs_add_null(fs, "answers");

    }
}

static fielddef_t fields[] = {
    {.name = "classification", .type="string", .desc = "packet classification"},
    {.name = "success", .type="int", .desc = "is response considered success"},
    {.name = "sport",  .type = "int", .desc = "UDP source port"},
    {.name = "dport",  .type = "int", .desc = "UDP destination port"},
    {.name = "icmp_responder", .type = "string", .desc = "Source IP of ICMP_UNREACH message"},
    {.name = "icmp_type", .type = "int", .desc = "icmp message type"},
    {.name = "icmp_code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp_unreach_str", .type = "string", .desc = "for icmp_unreach responses, the string version of icmp_code (e.g. network-unreach)"},
//    {.name = "query_response", .type = "string", .desc = "for DNS responses, the response code meaning of dns answer pkt"},
//    {.name = "query_num", .type = "int", .desc ="query_num for packet"},
//    {.name = "answer_rrs", .type="int", .desc = "number of answer_rrs for packet"},
//    {.name = "authority_rrs", .type="int", .desc = "number of authority_rrs"},
//    {.name = "additional_rrs", .type="int", .desc = "number of additional_rrs"},
    {.name = "answers", .type="binary", .desc = "answers in binary format"},
};

probe_module_t module_dns_mx = {
    .name = "dns_mx",
    .packet_length = 1,
    .pcap_filter = "udp || icmp",
    .pcap_snaplen = 1500,            // TO BE CHANGED FOR EXSTIMATE REFLECTION SIZE
    .port_args = 1,
    .thread_initialize = &dns_init_perthread,
    .global_initialize = &udp_global_initialize,
    .make_packet = &udp_make_packet,
    .print_packet = &dns_print_packet,
    .validate_packet = &dns_validate_packet,
    .process_packet = &dns_process_packet,
    .close = &udp_global_cleanup,
    .fields = fields,
    .numfields = sizeof(fields)/sizeof(fields[0])
};

////this will convert www.google.com to 
//void convert_to_dns_mx_name_format(unsigned char* dns,unsigned char* host) {
//    int lock = 0;
//    strcat((char*)host,".");
//    for(int i = 0; i < ((int) strlen((char*)host)); i++) {
//        if(host[i]=='.') {
//            *dns++=i-lock;
//            for(;lock<i;lock++) {
//                *dns++=host[lock];
//            }
//            lock++;
//        }
//    }
//    *dns++ = '\0';
//}

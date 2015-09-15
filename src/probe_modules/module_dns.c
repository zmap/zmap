/*
 * ZMap Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* Module for scanning for open UDP DNS resolvers. 
 *
 * This module optionally takes in an argument of the form "TYPE,QUESTION"
 * (e.g. "A,google.com").  Given no arguments it will default to asking for an
 * A record for www.google.com.
 * 
 * This module does minimal answer verification. It only verifies that the 
 * response roughly looks like a DNS response. It will not, for example,
 * require the QR bit be set to 1. All such analysis should happen offline.
 * Specifically, it checks for:
 * - That the response packet is >= the query packet.
 * - That the response bytes that should be the ID field matches the send bytes.
 * - That the response bytes that should be question match send bytes.
 * 
 * Example: zmap -p 53 --probe-module=dns --probe-args="ANY,www.example.com" -O json --output-fields=* 8.8.8.8
 * 
 * Based on a deprecated udp_dns module. 
 */ 

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/random.h"
#include "../../lib/xalloc.h"
#include "probe_modules.h"
#include "packet.h"
#include "logger.h"
#include "module_dns.h"
#include "module_udp.h"
#include "../fieldset.h"

#define DNS_SEND_LEN 512    // This is arbitrary 
#define UDP_HEADER_LEN 8
#define PCAP_SNAPLEN 3000   // This is even more arbitrary
#define UNUSED __attribute__((unused))
#define MAX_QTYPE 255
#define ICMP_UNREACH_HEADER_SIZE 8
#define BAD_QTYPE_STR "BAD QTYPE"
#define BAD_QTYPE_VAL -1

// Note: each label has a max length of 63 bytes. So someone has to be doing
// something really annoying. Will raise a warning.
// THIS INCLUDES THE NULL BYTE
#define MAX_NAME_LENGTH 512 

typedef uint8_t bool;

// zmap boilerplate
probe_module_t module_dns;
static int num_ports;

const char default_domain[] = "www.google.com";
const uint16_t default_qtype = DNS_QTYPE_A; 

static char *dns_packet = NULL;
static uint16_t dns_packet_len = 0; // Not including udp header
static uint16_t qname_len = 0;
static char* qname = NULL;
static uint16_t qtype = 0;

/* Array of qtypes we support. Jumping through some hoops (1 level of 
 * indirection) so the per-packet processing time is fast. Keep this in sync with:
 * dns_qtype (.h)
 * qtype_strid_to_qtype (below)
 * qtype_qtype_to_strid (below, and _setup_qtype_str_map())
 */
const char *qtype_strs[] = {
        "A",
        "NS",
        "CNAME",
        "SOA",
        "PTR",
        "MX",
        "TXT",
        "AAAA",
        "RRSIG",
        "ALL"
};

const dns_qtype qtype_strid_to_qtype[] = { DNS_QTYPE_A, DNS_QTYPE_NS, DNS_QTYPE_CNAME, 
        DNS_QTYPE_SOA, DNS_QTYPE_PTR, DNS_QTYPE_MX, DNS_QTYPE_TXT, 
        DNS_QTYPE_AAAA, DNS_QTYPE_RRSIG, DNS_QTYPE_ALL
};

#define DNS_QR_ANSWER   1

int8_t qtype_qtype_to_strid[256] = { BAD_QTYPE_VAL };

void _setup_qtype_str_map() 
{ 
    qtype_qtype_to_strid[DNS_QTYPE_A] = 0;
    qtype_qtype_to_strid[DNS_QTYPE_NS] = 1;
    qtype_qtype_to_strid[DNS_QTYPE_CNAME] = 2;
    qtype_qtype_to_strid[DNS_QTYPE_SOA] = 3;
    qtype_qtype_to_strid[DNS_QTYPE_PTR] = 4;
    qtype_qtype_to_strid[DNS_QTYPE_MX] = 5;
    qtype_qtype_to_strid[DNS_QTYPE_TXT] = 6;
    qtype_qtype_to_strid[DNS_QTYPE_AAAA] = 7;
    qtype_qtype_to_strid[DNS_QTYPE_RRSIG] = 8;
    qtype_qtype_to_strid[DNS_QTYPE_ALL] = 9;
}

uint16_t _qtype_str_to_code(char* str) 
{
    for (int i = 0; i < (int) (sizeof(qtype_strs)/sizeof(qtype_strs[0])); i++) {
        if (strcmp(qtype_strs[i], str) == 0)
            return qtype_strid_to_qtype[i];
    }
    return 0;
}


static uint16_t _domain_to_qname(char** qname_handle, char* domain) 
{   
    // String + 1byte header + null byte
    uint16_t len = strlen(domain) + 1 + 1;
    char* qname = xmalloc(len);
    // Add a . before the domain. This will make the following simpler.
    qname[0] = '.';
    // Move the domain into the qname buffer.
    memcpy(qname + 1, domain, strlen(domain));
    for (int i = 0; i < len; i++) {
        if (qname[i] == '.') {
            int j;
            for (j = i+1; j < (len-1); j++) {
                if (qname[j] == '.') {
                    break;
                }
            }
            qname[i] = j - i - 1;
        }
    }
    *qname_handle = qname;
    assert((*qname_handle)[len-1] == '\0');
    return len;
}

static int _build_global_dns_packet(char* domain) 
{    
    qname_len = _domain_to_qname(&qname, domain);
    dns_packet_len = sizeof(dns_header) + qname_len + sizeof(dns_question_tail);

    if (dns_packet_len > DNS_SEND_LEN) {
            log_fatal("dns", "DNS packet bigger (%d) than our limit (%d)", 
                    dns_packet_len, DNS_SEND_LEN);
            return EXIT_FAILURE;
    }
    
    dns_packet = xmalloc(dns_packet_len);
    memset(dns_packet, 0x00, dns_packet_len);

    dns_header* dns_header_p = (dns_header*)dns_packet;
    char* qname_p = dns_packet + sizeof(dns_header);
    dns_question_tail* tail_p = (dns_question_tail*)(dns_packet + sizeof(dns_header) + qname_len);

    // All other header fields should be 0. Except id, which we set per thread.
    dns_header_p->rd = 1; // Is one bit. Don't need htons
    dns_header_p->qdcount = htons(1);

    memcpy(qname_p, qname, qname_len);

    tail_p->qtype = htons(qtype);
    tail_p->qclass = htons(0x01); // MAGIC NUMBER. Let's be honest. This is only ever 1

    return EXIT_SUCCESS;
}

static uint16_t _decode_labels(char* name, uint16_t name_len, char* data, uint16_t data_len, bool stop)
{
    // We don't handle null bytes in name in this function.
    int bytes_used = 0;

    while(data_len > 0) { 
        uint16_t seg_len = *data;

        // We've now consumed another byte.
        data_len--;
        data++;

        // We don't support pointer calls (stop == 1) that call other pointers
        if (stop && (seg_len >= 0xc0)) {
            return 0;
        }

        // Are we done? Our next byte is either an offset pointer or null.
        if (seg_len >= 0xc0 || seg_len == '\0') {
            return bytes_used;
        }

        // Do we need to add a dot?
        if (bytes_used > 0) { 
           
            if (name_len < 1) {
                log_warn("dns", "Exceeded static name field allocation.");
                return 0;
            }
            
            name[0] = '.';
            name++;
            name_len--;

            bytes_used += 1;
        }

        // Do we have enough data left?
        if (seg_len > data_len) {
            return 0;
        }

        // Did we run out of our arbitrary buffer?
        if (seg_len > name_len) {
            log_warn("dns", "Exceeded static name field allocation.");
            return 0;
        }

        assert(data_len > 0);

        memcpy(name, data, seg_len);
    
        name += seg_len;
        name_len -= seg_len;
    
        data_len -= seg_len;
        data += seg_len;
        bytes_used += seg_len;
    }

    return bytes_used;
}

char* _get_name(char* data, uint16_t data_len, char* payload, 
        uint16_t payload_len, uint16_t* bytes_consumed)
{

    uint8_t byte = 0;

    char* name = xmalloc(MAX_NAME_LENGTH);

    memset(name, 0x00, MAX_NAME_LENGTH);
    
    uint16_t name_pos = 0;

    int i = 0;
    while(i < data_len) { 
        byte = data[i];
   
        // Is this a pointer?
        if (byte >= 0xc0) {
          
            // Not enough bytes
            if ((i + 1) >= data_len) {
                free(name);
                return NULL;      
            }

            // No. ntohs isn't needed here. It's because of
            // the upper 2 bits indicating a pointer.
            uint16_t offset = ((byte & 0x03) << 8) | (uint8_t)data[i+1];

            if (offset >= payload_len) { 
                free(name);
                return NULL;      
            }

            uint16_t name_bytes_used = _decode_labels(name + name_pos, 
                        MAX_NAME_LENGTH - name_pos - 1, payload + offset, 
                        payload_len - offset, 1); // -1 to make room for \0

            if (name_bytes_used == 0 && payload[offset] != '\0') { // thx root
                free(name);
                return NULL;      
            }

            name_pos += name_bytes_used;

            // We've consumed 2 bytes here.
            i = i + 2;

            // Once we hit a pointer we are done.
            break;

        } else if (byte == '\0') {
            // Done
            i += 1;
            break;
        } else {

            uint16_t name_bytes_used = _decode_labels(name + name_pos, 
                        MAX_NAME_LENGTH - name_pos - 1, data + i , data_len - i, 0); 
                        // -1 to make room for \0

            if (name_bytes_used == 0 && data[i] != '\0') { // thx root
                free(name);
                return NULL;      
            }

            // XXX off by something in parsing? check this.
            // Is name bytes used always the right value here?
            // It is for current uses. Not sure about future extensions.
            
            // We consumed the size plus the label.
            i += name_bytes_used + 1;

            name_pos += name_bytes_used;
            
            // We don't handle null bytes in the decode helper
            
            assert(i < data_len);

            // Peak ahead.
            if (data[i] != '\0') {

                // We need to add a dot. Make sure we have room.
                if ((name_pos + 1) < MAX_NAME_LENGTH) {
                    
                    name[name_pos++] = '.';

                } else {
                    log_warn("dns", "Exceeded static name field allocation.");
                    free(name);
                    return NULL;      
                }
            }
        } 
    }

    *bytes_consumed = i;

    // Our memset ensured null byte.
    assert(name[name_pos] == '\0');             

    return name;

}


static bool _process_response_question(char **data, uint16_t* data_len, char* payload,
        uint16_t payload_len, fieldset_t* list)
{   
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work with.
    // This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;

    char* question_name = _get_name(*data, *data_len, payload, payload_len,  &bytes_consumed);

    // Error.
    if (question_name == NULL) {
        return 1;
    }

    assert(bytes_consumed > 0);

    if ( (bytes_consumed + sizeof(dns_question_tail)) > *data_len) {
        free(question_name);
        return 1;
    }

    dns_question_tail* tail = (dns_question_tail*)(*data + bytes_consumed);

    uint16_t qtype = ntohs(tail->qtype);
    uint16_t qclass = ntohs(tail->qclass);
    
    // Build our new question fieldset
    fieldset_t *qfs = fs_new_fieldset(); 
    fs_add_string(qfs, "name", question_name, 1);
    fs_add_uint64(qfs, "qtype", qtype);
    if (qtype > MAX_QTYPE || qtype_qtype_to_strid[qtype] == BAD_QTYPE_VAL) {
        fs_add_string(qfs, "qtype_str", (char*) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be fast.
        fs_add_string(qfs, "qtype_str", (char*)qtype_strs[qtype_qtype_to_strid[qtype]], 0);
    }
    fs_add_uint64(qfs, "qclass", qclass);

    // Now we're adding the new fs to the list.
    fs_add_fieldset(list, "question", qfs);

    // Now update the pointers.
    *data = *data + bytes_consumed + sizeof(dns_question_tail);
    *data_len = *data_len - bytes_consumed - sizeof(dns_question_tail);

    return 0;
}

// XXX This should be merged with _process_response_question. 
// Ended up being almost exactly the same
bool _process_response_answer(char **data, uint16_t* data_len, char* payload,
        uint16_t payload_len, fieldset_t* list)
{   
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work with.
    // This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;

    char* answer_name = _get_name(*data, *data_len, payload, payload_len,  &bytes_consumed);

    // Error.
    if (answer_name == NULL) {
        return 1;
    }

    assert(bytes_consumed > 0);

    if ( (bytes_consumed + sizeof(dns_answer_tail)) > *data_len) {
        free(answer_name);
        return 1;
    }

    dns_answer_tail* tail = (dns_answer_tail*)(*data + bytes_consumed);

    uint16_t type = ntohs(tail->type);
    uint16_t class = ntohs(tail->class);
    uint32_t ttl = ntohl(tail->ttl);
    uint16_t rdlength = ntohs(tail->rdlength);
    char* rdata = tail->rdata;

    if ((rdlength + bytes_consumed + sizeof(dns_answer_tail)) > *data_len) {
        free(answer_name);
        return 1;
    }

    // Build our new question fieldset
    fieldset_t *afs = fs_new_fieldset(); 
    fs_add_string(afs, "name", answer_name, 1);
    fs_add_uint64(afs, "type", type);
    if (type > MAX_QTYPE || qtype_qtype_to_strid[type] == BAD_QTYPE_VAL) {
        fs_add_string(afs, "type_str", (char*) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be fast.
        fs_add_string(afs, "type_str", (char*)qtype_strs[qtype_qtype_to_strid[type]], 0);
    }
    fs_add_uint64(afs, "class", class);
    fs_add_uint64(afs, "ttl", ttl);
    fs_add_uint64(afs, "rdlength", rdlength);
    
    // XXX Fill this out for the other types we care about.
    if (type == DNS_QTYPE_NS || type == DNS_QTYPE_CNAME) {

        uint16_t rdata_bytes_consumed = 0;
        char* rdata_name = _get_name(rdata, rdlength, payload, payload_len,  
                &rdata_bytes_consumed);

        if (rdata_name == NULL) {
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            fs_add_uint64(afs, "rdata_is_parsed", 1);
            fs_add_string(afs, "rdata", rdata_name, 1);
        }

     } else if (type == DNS_QTYPE_MX) {

        uint16_t rdata_bytes_consumed = 0;

        if (rdlength <= 4) {
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {

            char* rdata_name = _get_name(rdata + 2, rdlength-2, payload, payload_len,  
                    &rdata_bytes_consumed);

            if (rdata_name == NULL) {
                fs_add_uint64(afs, "rdata_is_parsed", 0);
                fs_add_binary(afs, "rdata", rdlength, rdata, 0);
            } else {
            
                //answer + "pref:" + "xxxxx" (largest value 16bit) + "," + null
                //XXX: paul  fix now
                char* rdata_with_pref = xmalloc(strlen(rdata_name) + 5 + 5 + 1 + 1);
                memcpy(rdata_with_pref, rdata_name, strlen(rdata_name));
                memcpy(rdata_with_pref + strlen(rdata_name), ",pref:", 6);
                snprintf(rdata_with_pref + strlen(rdata_name) + 6, 5, "%hu",
                        ntohs( *(uint16_t*)rdata));

                fs_add_uint64(afs, "rdata_is_parsed", 1);
                fs_add_string(afs, "rdata", rdata_with_pref, 1);
            }
        }
    } else if (type == DNS_QTYPE_TXT) {

        if (rdlength >= 1 && (rdlength - 1) != *(uint8_t*)rdata ) {
            log_warn("dns", "TXT record with wrong TXT len. Not processing.");
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            fs_add_uint64(afs, "rdata_is_parsed", 1);
            char* txt = xmalloc(rdlength);
            memset(txt, 0x00, rdlength);
            memcpy(txt, rdata + 1, rdlength-1);
            fs_add_string(afs, "rdata", txt, 1);
        }
    } else if (type == DNS_QTYPE_A) {

        if (rdlength != 4) {
            log_warn("dns", "A record with IP of length %d. Not processing.", rdlength);
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            fs_add_uint64(afs, "rdata_is_parsed", 1);
            fs_add_string(afs, "rdata", 
                (char*) inet_ntoa( *(struct in_addr*)rdata ), 0);
        }
    } else if (type == DNS_QTYPE_AAAA) {

        if (rdlength != 16) {
            log_warn("dns", "AAAA record with IP of length %d. Not processing.", rdlength);
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            fs_add_uint64(afs, "rdata_is_parsed", 1);
            char* ipv6_str = xmalloc(INET6_ADDRSTRLEN);

            inet_ntop(AF_INET6, (struct sockaddr_in6*)rdata, 
                    ipv6_str,INET6_ADDRSTRLEN);

            fs_add_string(afs, "rdata", ipv6_str, 1);
        }
    } else {
        fs_add_uint64(afs, "rdata_is_parsed", 0);
        fs_add_binary(afs, "rdata", rdlength, rdata, 0);
    }

    // Now we're adding the new fs to the list.
    fs_add_fieldset(list, "question", afs);

    // Now update the pointers.
    *data = *data + bytes_consumed + sizeof(dns_answer_tail) + rdlength;
    *data_len = *data_len - bytes_consumed - sizeof(dns_answer_tail) - rdlength;

    return 0;
}

/*
 * Start of required zmap exports.
 */

static int dns_global_initialize(struct state_conf *conf) 
{
    char *qtype_str = NULL;
    char *domain = NULL;

    // This is zmap boilerplate. Why do I have to write this? 
    num_ports = conf->source_port_last - conf->source_port_first + 1;
    udp_set_num_ports(num_ports);

    _setup_qtype_str_map();

    // Want to add support for multiple questions? Start here. 
    if (!conf->probe_args) { // no parameters passed in. Use defaults
        domain = (char*) default_domain; 
        qtype = default_qtype;
    } else {
        char *probe_arg_delimiter_p = strchr(conf->probe_args, ','); 
        if (probe_arg_delimiter_p == NULL || 
                probe_arg_delimiter_p == conf->probe_args ||
                conf->probe_args + strlen(conf->probe_args) == probe_arg_delimiter_p + 1) {
            log_fatal("dns", "Invalid probe args. Format: \"A,google.com\"");
        }
        domain = probe_arg_delimiter_p + 1;
        qtype_str = xmalloc(probe_arg_delimiter_p - conf->probe_args + 1);
        strncpy(qtype_str, conf->probe_args, 
                probe_arg_delimiter_p - conf->probe_args);
        qtype_str[probe_arg_delimiter_p - conf->probe_args] = '\0'; 

        qtype = _qtype_str_to_code(qtype_str);
        
        if (!qtype) {
            log_fatal("dns", "Incorrect qtype supplied. %s", qtype_str);
            return EXIT_FAILURE;
        }
    }

    free(qtype_str);

    return _build_global_dns_packet(domain);
}
 
int dns_global_cleanup(UNUSED struct state_conf *zconf, 
        UNUSED struct state_send *zsend, UNUSED struct state_recv *zrecv) 
{
    if (dns_packet) {
        free(dns_packet);
    }
    dns_packet = NULL;

    if (qname) {
        free(qname);
    }
    qname = NULL;

    return EXIT_SUCCESS;
}

int dns_init_perthread(void* buf, macaddr_t *src,
        macaddr_t *gw, UNUSED port_h_t dst_port,
        UNUSED void **arg_ptr) 
{
    memset(buf, 0, MAX_PACKET_SIZE);
    
    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);
    
    struct ip *ip_header = (struct ip*)(&eth_header[1]);
    uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) + 
        dns_packet_len);
    make_ip_header(ip_header, IPPROTO_UDP, len);

    struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
    len = sizeof(struct udphdr) + dns_packet_len;
    make_udp_header(udp_header, zconf.target_port, len);

    char* payload = (char*)(&udp_header[1]);

    module_dns.packet_length = sizeof(struct ether_header) + sizeof(struct ip)
                + sizeof(struct udphdr) + dns_packet_len;
    assert(module_dns.packet_length <= MAX_PACKET_SIZE);

    memcpy(payload, dns_packet, dns_packet_len);

    return EXIT_SUCCESS;
}

int dns_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
        uint32_t *validation, int probe_num, UNUSED void *arg) 
{
    struct ether_header *eth_header = (struct ether_header *) buf;
    struct ip *ip_header = (struct ip*) (&eth_header[1]);
    struct udphdr *udp_header= (struct udphdr *) &ip_header[1];

    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    udp_header->uh_sport = htons(get_src_port(num_ports, probe_num,
                     validation));
    
    dns_header* dns_header_p = (dns_header*) &udp_header[1];
    dns_header_p->id = validation[2] & 0xFFFF;
    
    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

    return EXIT_SUCCESS;
}

void dns_print_packet(FILE *fp, void* packet) 
{
    struct ether_header *ethh = (struct ether_header *) packet;
    struct ip *iph = (struct ip *) &ethh[1];
    struct udphdr *udph  = (struct udphdr*) (iph + 4*iph->ip_hl);
    fprintf(fp, "------------------------------------------------------\n");
    fprintf(fp, "dns { source: %u | dest: %u | checksum: %#04X }\n",
        ntohs(udph->uh_sport),
        ntohs(udph->uh_dport),
        ntohs(udph->uh_sum));
    fprintf_ip_header(fp, iph);
    fprintf_eth_header(fp, ethh);
    fprintf(fp, "------------------------------------------------------\n");
}

int dns_validate_packet(const struct ip *ip_hdr, uint32_t len,
        uint32_t *src_ip, uint32_t *validation)
{
    // This does the heavy lifting.
    if (!udp_validate_packet(ip_hdr, len, src_ip, validation)) {
        return 0;
    }

    uint16_t sport = 0;

    // This entire if..elif..else block is getting at the udp body
    struct udphdr *udp = NULL;
    if (ip_hdr->ip_p == IPPROTO_UDP) {
        udp = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
        sport = ntohs(udp->uh_sport);
    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        
        // UDP can return ICMP Destination unreach
        // IP( ICMP( IP( UDP ) ) ) for a destination unreach
        uint32_t min_len = 4*ip_hdr->ip_hl + ICMP_UNREACH_HEADER_SIZE
                + sizeof(struct ip) + sizeof(struct udphdr);
        if (len < min_len) {
            // Not enough information for us to validate
            return 0;
        }

        struct icmp *icmp = (struct icmp*) ((char *) ip_hdr + 4*ip_hdr->ip_hl);
        // We want to handle more of this.
        /*if (icmp->icmp_type != ICMP_UNREACH) {
            return 0;
        }*/

        struct ip *ip_inner = (struct ip*) ((char *) icmp + ICMP_UNREACH_HEADER_SIZE);
        // Now we know the actual inner ip length, we should recheck the buffer
        if (len < 4*ip_inner->ip_hl - sizeof(struct ip) + min_len) {
            return 0;
        }
        
        // This is the packet we sent
        udp = (struct udphdr *) ((char*) ip_inner + 4*ip_inner->ip_hl);
    
        sport = ntohs(udp->uh_dport);
    } else {
        // We should never get here unless udp_validate_packet() has changed.
        assert(0);
        return 0;
    }

    // Verify our source port.
    if (sport != zconf.target_port) {
        return 0;
    }

    // Verify our packet length.
    uint16_t udp_len = ntohs(udp->uh_ulen);
    if (udp_len < dns_packet_len) {
        return 0;
    }

    // Verify the packet length is ok.
    if (len < udp_len) {
        return 0;
    }

    // Looks good.
    return 1;
}

void dns_process_packet(const u_char *packet, uint32_t len, fieldset_t *fs,
        uint32_t *validation) 
{    
    struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];

    //fs_add_string(fs, "icmp_responder", make_ip_str(ip_hdr->ip_src.s_addr), 1);
    if (ip_hdr->ip_p == IPPROTO_UDP) {

        struct udphdr *udp_hdr = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
        uint16_t udp_len = ntohs(udp_hdr->uh_ulen);

        // Handles in validate.
        assert(udp_len >= dns_packet_len); 

        char* qname_p = NULL;
        dns_question_tail* tail_p = NULL;
        bool is_valid = 0;
        
        dns_header* dns_header_p = (dns_header*) &udp_hdr[1];
     
        // verify our dns transaction id
        if (dns_header_p->id == (validation[2] & 0xFFFF)) {

            // Verify our question
            qname_p = (char*) dns_header_p + sizeof(dns_header);
            tail_p = (dns_question_tail*)(dns_packet + sizeof(dns_header) + qname_len);

            // Verify our qname
            if (strcmp(qname, qname_p) == 0) {
            
                // Verify the qtype and qclass.
                if (tail_p->qtype == htons(qtype) && tail_p->qclass == htons(0x01)) {
                    is_valid = 1;
                }
            }
        }
    
        dns_header* dns_hdr = (dns_header*) &udp_hdr[1];
        
        uint16_t qr = dns_hdr->qr;
        uint16_t rcode = dns_hdr->rcode;

        // Success: Has the right validation bits and the right Q
        // App success: has qr and rcode bits right
        // Any app level parsing issues: dns_parse_err

        // High level info
        fs_add_string(fs, "classification", (char*) "dns", 0);
        fs_add_uint64(fs, "success", is_valid);
        fs_add_uint64(fs, "app_success", (qr == DNS_QR_ANSWER) && (rcode == DNS_RCODE_NOERR));
        
        // UDP info
        fs_add_uint64(fs, "udp_sport", ntohs(udp_hdr->uh_sport));
        fs_add_uint64(fs, "udp_dport", ntohs(udp_hdr->uh_dport));
        fs_add_uint64(fs, "udp_len", udp_len);
        
        // ICMP info
        fs_add_null(fs, "icmp_responder");
        fs_add_null(fs, "icmp_type");
        fs_add_null(fs, "icmp_code");
        fs_add_null(fs, "icmp_unreach_str");
        
        if (!is_valid) {
            // DNS header
            fs_add_null(fs, "dns_id"); 
            fs_add_null(fs, "dns_rd"); 
            fs_add_null(fs, "dns_tc"); 
            fs_add_null(fs, "dns_aa"); 
            fs_add_null(fs, "dns_opcode"); 
            fs_add_null(fs, "dns_qr"); 
            fs_add_null(fs, "dns_rcode"); 
            fs_add_null(fs, "dns_cd"); 
            fs_add_null(fs, "dns_ad"); 
            fs_add_null(fs, "dns_z"); 
            fs_add_null(fs, "dns_ra"); 
            fs_add_null(fs, "dns_qdcount"); 
            fs_add_null(fs, "dns_ancount"); 
            fs_add_null(fs, "dns_nscount"); 
            fs_add_null(fs, "dns_arcount"); 

            fs_add_null(fs, "dns_questions");
            fs_add_null(fs, "dns_answers");
            fs_add_null(fs, "dns_authorities");
            fs_add_null(fs, "dns_additionals");

            fs_add_uint64(fs, "dns_parse_err", 1); 

        } else {

            // DNS header
            fs_add_uint64(fs, "dns_id", ntohs(dns_hdr->id)); 
            fs_add_uint64(fs, "dns_rd", dns_hdr->rd); 
            fs_add_uint64(fs, "dns_tc", dns_hdr->tc); 
            fs_add_uint64(fs, "dns_aa", dns_hdr->aa); 
            fs_add_uint64(fs, "dns_opcode", dns_hdr->opcode); 
            fs_add_uint64(fs, "dns_qr", qr); 
            fs_add_uint64(fs, "dns_rcode", rcode); 
            fs_add_uint64(fs, "dns_cd", dns_hdr->cd); 
            fs_add_uint64(fs, "dns_ad", dns_hdr->ad); 
            fs_add_uint64(fs, "dns_z", dns_hdr->z); 
            fs_add_uint64(fs, "dns_ra", dns_hdr->ra); 
            fs_add_uint64(fs, "dns_qdcount", ntohs(dns_hdr->qdcount)); 
            fs_add_uint64(fs, "dns_ancount", ntohs(dns_hdr->ancount)); 
            fs_add_uint64(fs, "dns_nscount", ntohs(dns_hdr->nscount)); 
            fs_add_uint64(fs, "dns_arcount", ntohs(dns_hdr->arcount)); 

            // And now for the complicated part. Hierarchical data. 
            char* data = ((char*)dns_hdr) + sizeof(dns_header);
            uint16_t data_len = udp_len - sizeof(udp_hdr) - sizeof(dns_header);
            bool err = 0;

            // Questions
            fieldset_t *list = fs_new_repeated_fieldset();
            for (int i = 0; i < ntohs(dns_hdr->qdcount) && !err; i++) {
                err = _process_response_question(&data, &data_len, (char*)dns_hdr, 
                            udp_len, list);    
            }
            fs_add_repeated(fs, "dns_questions", list);

            // Answers
            list = fs_new_repeated_fieldset();
            for (int i = 0; i < ntohs(dns_hdr->ancount) && !err; i++) {
                err = _process_response_answer(&data, &data_len, (char*)dns_hdr, udp_len, list); 
            }
            fs_add_repeated(fs, "dns_answers", list);

            // Authorities
            list = fs_new_repeated_fieldset();
            for (int i = 0; i < ntohs(dns_hdr->nscount) && !err; i++) {
                err = _process_response_answer(&data, &data_len, (char*)dns_hdr, udp_len, list);  
            }
            fs_add_repeated(fs, "dns_authorities", list);

            // Additionals
            list = fs_new_repeated_fieldset();
            for (int i = 0; i < ntohs(dns_hdr->arcount) && !err; i++) {
                err = _process_response_answer(&data, &data_len, (char*)dns_hdr, udp_len, list);   
            }
            fs_add_repeated(fs, "dns_additionals", list);

            // Do we have unconsumed data?
            if (data_len != 0) {
                err = 1;
            }

            // Did we parse OK?
            fs_add_uint64(fs, "dns_parse_err", err); 
        }
    
        // Now the raw stuff.
        fs_add_binary(fs, "raw_data", (udp_len - sizeof(struct udphdr)), (void*) &udp_hdr[1], 0);
   
        return;
    
    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        struct icmp *icmp = (struct icmp *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
        struct ip *ip_inner = (struct ip *) &icmp[1];
 
        // This is the packet we sent
        struct udphdr *udp_hdr = (struct udphdr *) ((char*) ip_inner + 4*ip_inner->ip_hl);
        uint16_t udp_len = ntohs(udp_hdr->uh_ulen);

        // High level info    
        fs_add_string(fs, "classification", (char*) "dns", 0);
        fs_add_uint64(fs, "success", 0);
        fs_add_uint64(fs, "app_success", 0);
        
        // UDP info
        fs_add_uint64(fs, "udp_sport", ntohs(udp_hdr->uh_sport));
        fs_add_uint64(fs, "udp_dport", ntohs(udp_hdr->uh_dport));
        fs_add_uint64(fs, "udp_len", udp_len);
        
        // ICMP info
        // XXX This is legacy. not well tested.
        fs_add_string(fs, "icmp_responder", make_ip_str(ip_hdr->ip_src.s_addr), 1);
        fs_add_uint64(fs, "icmp_type", icmp->icmp_type);
        fs_add_uint64(fs, "icmp_code", icmp->icmp_code);
        if (icmp->icmp_code <= ICMP_UNREACH_PRECEDENCE_CUTOFF) {
            fs_add_string(fs, "icmp_unreach_str",
                (char *) udp_unreach_strings[icmp->icmp_code], 0);
        } else {
            fs_add_string(fs, "icmp_unreach_str", (char *) "unknown", 0);
        }
        
        // DNS header
        fs_add_null(fs, "dns_id"); 
        fs_add_null(fs, "dns_rd"); 
        fs_add_null(fs, "dns_tc"); 
        fs_add_null(fs, "dns_aa"); 
        fs_add_null(fs, "dns_opcode"); 
        fs_add_null(fs, "dns_qr"); 
        fs_add_null(fs, "dns_rcode"); 
        fs_add_null(fs, "dns_cd"); 
        fs_add_null(fs, "dns_ad"); 
        fs_add_null(fs, "dns_z"); 
        fs_add_null(fs, "dns_ra"); 
        fs_add_null(fs, "dns_qdcount"); 
        fs_add_null(fs, "dns_ancount"); 
        fs_add_null(fs, "dns_nscount"); 
        fs_add_null(fs, "dns_arcount"); 

        fs_add_null(fs, "dns_questions");
        fs_add_null(fs, "dns_answers");
        fs_add_null(fs, "dns_authorities");
        fs_add_null(fs, "dns_additionals");

        fs_add_uint64(fs, "dns_parse_err", 1); 
        fs_add_binary(fs, "raw_data", len, (char*)packet, 0);
        
        return;

    } else {
        // This should not happen. Both the pcap filter and validate packet prevent this.
        assert(0);
        return;
    }
}

static fielddef_t fields[] = {
    {.name = "classification", .type="string", .desc = "packet protocol"},
    {.name = "success", .type="int", .desc = "Are the validation bits and question correct"},
    {.name = "app_success", .type="int", .desc = "Is the RA bit set with no error code?"},
    {.name = "udp_sport",  .type = "int", .desc = "UDP source port"},
    {.name = "udp_dport",  .type = "int", .desc = "UDP destination port"},
    {.name = "udp_len", .type="int", .desc = "UDP packet lenght"},
    {.name = "icmp_responder", .type = "string", .desc = "Source IP of ICMP_UNREACH message"},
    {.name = "icmp_type", .type = "int", .desc = "icmp message type"},
    {.name = "icmp_code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp_unreach_str", .type = "string", .desc = "for icmp_unreach responses, the string version of icmp_code (e.g. network-unreach)"},
    {.name = "dns_id", .type = "int", .desc ="DNS transaction ID"},
    {.name = "dns_rd", .type = "int", .desc ="DNS recursion desired"},
    {.name = "dns_tc", .type = "int", .desc ="DNS packet truncated"},
    {.name = "dns_aa", .type = "int", .desc ="DNS authoritative answer"},
    {.name = "dns_opcode", .type = "int", .desc ="DNS opcode (query type)"},
    {.name = "dns_qr", .type = "int", .desc ="DNS query(0) or response (1)"},
    {.name = "dns_rcode", .type = "int", .desc ="DNS response code"},
    {.name = "dns_cd", .type = "int", .desc ="DNS checking disabled"},
    {.name = "dns_ad", .type = "int", .desc ="DNS authenticated data"},
    {.name = "dns_z", .type = "int", .desc ="DNS reserved"},
    {.name = "dns_ra", .type = "int", .desc ="DNS recursion available"},
    {.name = "dns_qdcount", .type = "int", .desc ="DNS number questions"},
    {.name = "dns_ancount", .type = "int", .desc ="DNS number answer RR's"},
    {.name = "dns_nscount", .type = "int", .desc ="DNS number NS RR's in authority section"},
    {.name = "dns_arcount", .type = "int", .desc ="DNS number additional RR's"},
    {.name = "dns_questions", .type = "repeated", .desc ="DNS question list"},
    {.name = "dns_answers", .type = "repeated", .desc ="DNS answer list"},
    {.name = "dns_authorities", .type = "repeated", .desc ="DNS authority list"},
    {.name = "dns_additionals", .type = "repeated", .desc ="DNS additional list"},
    {.name = "dns_parse_err", .type = "int", .desc ="Problem parsing the DNS response"},
    {.name = "raw_data", .type="binary", .desc = "UDP payload"},
};

probe_module_t module_dns = {
    .name = "dns",
    .packet_length = DNS_SEND_LEN + UDP_HEADER_LEN,
    .pcap_filter = "udp || icmp",
    .pcap_snaplen = PCAP_SNAPLEN,
    .port_args = 1, 
    .thread_initialize = &dns_init_perthread,
    .global_initialize = &dns_global_initialize,
    .make_packet = &dns_make_packet,
    .print_packet = &dns_print_packet,
    .validate_packet = &dns_validate_packet,
    .process_packet = &dns_process_packet,
    .close = &dns_global_cleanup,
    .output_type = OUTPUT_TYPE_DYNAMIC,
    .fields = fields,
    .numfields = sizeof(fields)/sizeof(fields[0]),
    .helptext = "This module sends out DNS queries and parses basic responses. "
                "By default, the module will perform an A record lookup for "
                "google.com. You can specify other queries using the --probe-args "
                "argument in the form: 'type,query', e.g. 'A,google.com'. The module "
                "supports sending the the following types: of queries: A, NS, CNAME, SOA, "
                "PTR, MX, TXT, AAAA, RRSIG, and ALL. The module will accept and attempt "
                "to parse all DNS responses. There is currently support for parsing out "
                "full data from A, NS, CNAME, MX, TXT, and AAAA. Any other types will be "
                "output in raw form."

};

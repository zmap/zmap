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
typedef uint8_t bool;

// zmap boilerplate
probe_module_t module_dns;
static int num_ports;

const char default_domain[] = "www.google.com";
const uint16_t default_qtype = DNS_QTYPE_A; 

static char *dns_packet = NULL;
static uint16_t dns_packet_len = 0;
static uint16_t qname_len = 0;
static char* qname = NULL;
uint16_t qtype = 0;

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

int8_t qtype_qtype_to_strid[256] = { -1 };

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
    for (unsigned long i = 0; i < sizeof(qtype_strs)/sizeof(qtype_strs[0]); i++) {
        if (strcmp(qtype_strs[i], str) == 0)
            return qtype_strid_to_qtype[i];
    }
    return 0;
}

// xxx: Paul hasn't reviewed or rewritten this function. But it works.
//this will convert www.google.com to \3www\6google\3com
void _domain_to_qname(char* dns, char* host) {
	int lock = 0;
	strcat((char*)host,".");
	for(int i = 0; i < ((int) strlen((char*)host)); i++) {
		if(host[i]=='.') {
			*dns++=i-lock;
			for(;lock<i;lock++) {
				*dns++=host[lock];
			}
			lock++;
		}
	}
	*dns++ = '\0';
}

// xxx: Paul hasn't even looked at this.
// allocates and returns a string representation of a hexadecimal IP
// hexadecimal ip must be passed in network byte order
char* _hex_to_ip(void* hex_ip) {

	if(!hex_ip){
		return NULL;
	}
	char* addrstr = malloc(INET_ADDRSTRLEN);
	if(addrstr == NULL){
		exit(1);
	}
	//fprintf(stderr, "hex_ip %s\n", (char*)hex_ip);

	//memcpy(addrstr, hex_ip, sizeof(&hex_ip));
	if(inet_ntop(AF_INET, (struct sockaddr_in *)hex_ip, addrstr, INET_ADDRSTRLEN) == NULL){
		free(addrstr);
		return NULL;
	}
	return addrstr;
}

// xxx: Paul hasn't even looked at this. Given the comments below from deprication
// this may take some time. I suspect it will be completely deleted.
char* _parse_dns_ip_results(struct dnshdr* dns_hdr) {
	(void) dns_hdr;
	return strdup(""); // This is why we don't accept pull requests
#if 0
	// parse through dns_query since it can be of variable length
	char* dns_ans_start = (char *) (&dns_hdr[1]);
	while (*dns_ans_start++); // <---- SERIOUSLY FUCK THAT
	// skip  qtype and qclass octets
	dns_ans_start += 4;
	// number of answers * 16 chars each (each followed by space or null, and quotes)
	size_t size = ntohs(dns_hdr->ancount)*INET_ADDRSTRLEN+2;
	char* ip_addrs = malloc(size);

	// should always be 4 for ipv4 addrs, but include in case of unexpected response
	//uint16_t prev_data_len = 4;
	int output_pos = 0;
	if(ntohs(dns_hdr->ancount) > 1000){
		return NULL;
	}
	for (int i = 0; i < ntohs(dns_hdr->ancount); i++) {
		//dnsans* dns_ans = (dnsans *) ((char*) dns_ans_start + (12 + prev_data_len)*i);
		dnsans* dns_ans = (dnsans *) ((char*) dns_ans_start + (12)*i);
		if(!dns_ans->addr){
			//prev_data_len = ntohs(dns_ans->length);
			continue;
		}
		char* ip_addr = hex_to_ip(&dns_ans->addr);
		if (!ip_addr) {
			//prev_data_len = ntohs(dns_ans->length);
			continue;
		}
		output_pos += i == 0 ? sprintf(ip_addrs + output_pos, "\"%s", ip_addr) : sprintf(ip_addrs + output_pos, " %s", ip_addr);
		//prev_data_len = ntohs(dns_ans->length);
	}
	if (output_pos) {
		sprintf(ip_addrs + output_pos, "\"");
	}
	return ip_addrs;
#endif
}

uint8_t _build_global_dns_packet(char* domain) 
{    
    // domain + null + 1 byte head
    qname_len = strlen(domain) + 1 + 1;
 
    dns_packet_len = sizeof(dns_header) + qname_len + sizeof(dns_question_tail);

    if (dns_packet_len > DNS_SEND_LEN) {
            log_fatal("dns", "DNS packet bigger (%d) than our limit (%d)", 
                    dns_packet_len, DNS_SEND_LEN);
            return EXIT_FAILURE;
    }
    
    qname = xmalloc(qname_len);
    _domain_to_qname(qname, domain);

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

// XXX: Paul needs to write this.
bool _process_response_question(char **data, uint16_t* data_len, fieldset_t* list)
{    
    return 0;
}

// XXX: Paul needs to write this.
bool _process_response_answer(char **data, uint16_t* data_len, fieldset_t* list)
{    
    return 0;
}

/*
 * Start of required zmap exports.
 */

static int dns_global_initialize(struct state_conf *conf) 
{
    char *probe_arg_delimiter_p = NULL;
	char *qtype_str = NULL;
	char* domain = NULL;

    // This is zmap boilerplate. Why do I have to write this? 
	num_ports = conf->source_port_last - conf->source_port_first + 1;
	udp_set_num_ports(num_ports);

    _setup_qtype_str_map();

    // Want to add support for multiple questions? Start here. 
	if (conf->probe_args == NULL) {
        domain = (char*)default_domain; 
        qtype = default_qtype;
    } else {

	    probe_arg_delimiter_p = strchr(conf->probe_args, ','); 
		
        if (probe_arg_delimiter_p == NULL || 
                probe_arg_delimiter_p == conf->probe_args ||
                conf->probe_args + strlen(conf->probe_args) == probe_arg_delimiter_p + 1) {
            log_fatal("dns", "Incorrect probe args. Format: \"A,google.com\"");
            return EXIT_FAILURE;
        }

        domain = probe_arg_delimiter_p + 1;
    
        qtype_str = xmalloc( probe_arg_delimiter_p - conf->probe_args + 1);
        strncpy(qtype_str, conf->probe_args, 
                probe_arg_delimiter_p - conf->probe_args);
        qtype_str[probe_arg_delimiter_p - conf->probe_args] = '\0'; 

        qtype = _qtype_str_to_code(qtype_str);
        
        if (qtype == 0) {  
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

// XXX: Paul hasn't looked at this.
void dns_print_packet(FILE *fp, void* packet) {
	return;
#if 0
    struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
	struct udphdr *udph  = (struct udphdr*) (iph + 4*iph->ip_hl);
	fprintf(fp, "dns { source: %u | dest: %u | checksum: %#04X }\n",
		ntohs(udph->uh_sport),
		ntohs(udph->uh_dport),
		ntohs(udph->uh_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
#endif
}

int dns_validate_packet(const struct ip *ip_hdr, uint32_t len,
		uint32_t *src_ip, uint32_t *validation)
{
    // This does the heavy lifting.
    if (!udp_validate_packet(ip_hdr, len, src_ip, validation)) {
		return 0;
	}

    // This entire if..elif..else block is getting at the udp body
    struct udphdr *udp = NULL;
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		udp = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
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
		if (icmp->icmp_type != ICMP_UNREACH) {
			return 0;
		}

		struct ip *ip_inner = (struct ip*) ((char *) icmp + ICMP_UNREACH_HEADER_SIZE);
		// Now we know the actual inner ip length, we should recheck the buffer
		if (len < 4*ip_inner->ip_hl - sizeof(struct ip) + min_len) {
			return 0;
		}
		// This is the packet we sent
		udp = (struct udphdr *) ((char*) ip_inner + 4*ip_inner->ip_hl);
	} else {
        // We should never get here unless udp_validate_packet() has changed.
        assert(0);
		return 0;
	}

    // Verify our source port.
	uint16_t sport = ntohs(udp->uh_sport);
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
    
    // Verify our dns transaction id
    dns_header* dns_header_p = (dns_header*) &udp[1];
    if (dns_header_p->id != (validation[2] & 0xFFFF)) {
        return 0;
    }

    // Verify our question
    char* qname_p = (char*) dns_header_p + sizeof(dns_header);
    dns_question_tail* tail_p = (dns_question_tail*)(dns_packet + sizeof(dns_header) + qname_len);

    // Verify our qname
    if (strcmp(qname, qname_p) != 0) {
        return 0;
    }

    // Verify the qtype and qclass.
    if (tail_p->qtype != htons(qtype) || tail_p->qclass != htons(0x01)) {
        return 0;
    }

    // **phew**
	return 1;
}

void dns_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs) 
{    
    struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];
	
    if (ip_hdr->ip_p == IPPROTO_UDP) {
        
        struct udphdr *udp_hdr = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
        dns_header* dns_hdr = (dns_header*) &udp_hdr[1];

        // This is part of validate.
		assert(ntohs(udp_hdr->uh_ulen) >= dns_packet_len);
		
        uint16_t qr = dns_hdr->qr;
		uint16_t rcode = dns_hdr->rcode;
    
        // High level info    
        fs_add_string(fs, "classification", (char*) "dns", 0);
		fs_add_uint64(fs, "success", (qr == DNS_QR_ANSWER) && (rcode == DNS_RCODE_NOERR));
		
        // UDP info
        fs_add_uint64(fs, "udp_sport", ntohs(udp_hdr->uh_sport));
		fs_add_uint64(fs, "udp_dport", ntohs(udp_hdr->uh_dport));
		fs_add_uint64(fs, "udp_len", ntohs(udp_hdr->uh_ulen));
		
        // ICMP info
        fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		
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
        char* data = (char*)dns_hdr + sizeof(dns_hdr);
        uint16_t data_len = ntohs(udp_hdr->uh_ulen) - sizeof(dns_hdr);
        bool err = 0;

        // Questions
        fieldset_t *list = fs_new_repeated_fieldset();
        for (int i = 0; i < ntohs(dns_hdr->qdcount) && !err; i++) {
            err = _process_response_question(&data, &data_len, list);    
        }
        fs_add_repeated(fs, "dns_questions", list);

        // Answers
        list = fs_new_repeated_fieldset();
        for (int i = 0; i < ntohs(dns_hdr->ancount) && !err; i++) {
            err = _process_response_answer(&data, &data_len, list); 
        }
        fs_add_repeated(fs, "dns_answers", list);

        // Authorities
        list = fs_new_repeated_fieldset();
        for (int i = 0; i < ntohs(dns_hdr->nscount) && !err; i++) {
            err = _process_response_answer(&data, &data_len, list);  
        }
        fs_add_repeated(fs, "dns_authorities", list);

        // Additionals
        list = fs_new_repeated_fieldset();
        for (int i = 0; i < ntohs(dns_hdr->arcount) && !err; i++) {
            err = _process_response_answer(&data, &data_len, list);   
        }
        fs_add_repeated(fs, "dns_additionals", list);

        // Did we parse OK?
        fs_add_uint64(fs, "dns_parseerr", err); 
    
        // Now the raw stuff.
		fs_add_binary(fs, "raw_data", (ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr)), (void*) &udp_hdr[1], 0);
	
    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        assert(0);
        //xxx: Paul hasn't gotten to this part yet.
        return;

        #if 0
		struct icmp *icmp = (struct icmp *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
		struct ip *ip_inner = (struct ip *) &icmp[1];
		// ICMP unreachable comes from another server, set saddr to original dst
		fs_modify_string(fs, "saddr", make_ip_str(ip_inner->ip_dst.s_addr), 1);
		fs_add_string(fs, "classification", (char*) "icmp-unreach", 0);
		fs_add_uint64(fs, "success", 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_string(fs, "icmp_responder", make_ip_str(ip_hdr->ip_src.s_addr), 1);
		fs_add_uint64(fs, "icmp_type", icmp->icmp_type);
		fs_add_uint64(fs, "icmp_code", icmp->icmp_code);
		if (icmp->icmp_code <= ICMP_UNREACH_PRECEDENCE_CUTOFF) {
			fs_add_string(fs, "icmp_unreach_str",
				(char *) udp_unreach_strings[icmp->icmp_code], 0);
		} else {
			fs_add_string(fs, "icmp_unreach_str", (char *) "unknown", 0);
		}
		fs_add_null(fs, "app_response_str");
		fs_add_null(fs, "app_response_code");
		fs_add_null(fs, "udp_pkt_size");
		fs_add_null(fs, "data");
		fs_add_null(fs, "addrs");
	    #endif
    } else {
	    // This should not happen. Both the pcap filter and validate packet prevent this.
        assert(0);
        return;
    }
}

static fielddef_t fields[] = {
	{.name = "classification", .type="string", .desc = "packet protocol"},
	{.name = "success", .type="int", .desc = "Is the RA bit set with no error code?"},
	{.name = "udp_sport",  .type = "int", .desc = "UDP source port"},
	{.name = "udp_dport",  .type = "int", .desc = "UDP destination port"},
	{.name = "udp_len", .type="int", .desc = "UDP packet lenght"},
	{.name = "icmp_responder", .type = "string", .desc = "Source IP of ICMP_UNREACH message"},
	{.name = "icmp_type", .type = "int", .desc = "icmp message type"},
	{.name = "icmp_code", .type = "int", .desc = "icmp message sub type code"},
	{.name = "icmp_unreach_str", .type = "string", .desc = "for icmp_unreach responses, the string version of icmp_code (e.g. network-unreach)"},
	{.name = "dns_id", .type = "uint64", .desc ="DNS transaction ID"},
	{.name = "dns_rd", .type = "uint64", .desc ="DNS recursion desired"},
	{.name = "dns_tc", .type = "uint64", .desc ="DNS packet truncated"},
	{.name = "dns_aa", .type = "uint64", .desc ="DNS authoritative answer"},
	{.name = "dns_opcode", .type = "uint64", .desc ="DNS opcode (query type)"},
	{.name = "dns_qr", .type = "uint64", .desc ="DNS query(0) or response (1)"},
	{.name = "dns_rcode", .type = "uint64", .desc ="DNS response code"},
	{.name = "dns_cd", .type = "uint64", .desc ="DNS checking disabled"},
	{.name = "dns_ad", .type = "uint64", .desc ="DNS authenticated data"},
	{.name = "dns_z", .type = "uint64", .desc ="DNS reserved"},
	{.name = "dns_ra", .type = "uint64", .desc ="DNS recursion available"},
	{.name = "dns_qdcount", .type = "uint64", .desc ="DNS number questions"},
	{.name = "dns_ancount", .type = "uint64", .desc ="DNS number answer RR's"},
	{.name = "dns_nscount", .type = "uint64", .desc ="DNS number NS RR's in authority section"},
	{.name = "dns_arcount", .type = "uint64", .desc ="DNS number additional RR's"},
	{.name = "dns_questions", .type = "repeated", .desc ="DNS question list"},
    {.name = "dns_answers", .type = "repeated", .desc ="DNS answer list"},
	{.name = "dns_authorities", .type = "repeated", .desc ="DNS authority list"},
	{.name = "dns_additionals", .type = "repeated", .desc ="DNS additional list"},
    {.name = "dns_parseerr", .type = "uint64", .desc ="Problem parsing the DNS response"},
	{.name = "raw_data", .type="binary", .desc = "UDP payload"},
};

probe_module_t module_dns = {
	.name = "dns",
	.packet_length = DNS_SEND_LEN + UDP_HEADER_LEN,
	.pcap_filter = "udp || icmp",
	.pcap_snaplen = PCAP_SNAPLEN,
	.port_args = 1, // I have no idea what this does. Zakir made me do it
	.thread_initialize = &dns_init_perthread,
	.global_initialize = &dns_global_initialize,
	.make_packet = &dns_make_packet,
	.print_packet = &dns_print_packet,
	.validate_packet = &dns_validate_packet,
	.process_packet = &dns_process_packet,
	.close = &dns_global_cleanup,
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
};

/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* send module for performing arbitrary UDP scans */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../../lib/lockfd.h"
#include "../../lib/pbm.h"
#include "logger.h"
#include "probe_modules.h"
#include "packet.h"
#include "aesrand.h"
#include "state.h"
#include "module_udp.h"



#define MAX_UDP_PAYLOAD_LEN 1472
#define UNUSED __attribute__((unused))



static inline uint32_t MakeQuicTag(char a, char b, char c, char d) {
	return (uint32_t)(a) |
		(uint32_t)(b) << 8 |
		(uint32_t)(c) << 16 |
		(uint32_t)(d) << 24;
}

static void GetQuicTag(uint32_t* tag, char out[4]) {
	memcpy(&out[0], (char*)tag+3, 1);
	memcpy(&out[1], (char*)tag+2, 1);
	memcpy(&out[2], (char*)tag+1, 1);
	memcpy(&out[3], (char*)tag, 1);
}


#define QUIC_HDR_LEN_HASH 27
typedef struct {
	uint8_t public_flags;   // should be 0x01 | 0x0C  during sending and should not contain version on recv.
#define PUBLIC_FLAG_HAS_VERS 0x01
#define PUBLIC_FLAG_HAS_RST 0x02
#define PUBLIC_FLAG_8BYTE_CONN_ID 0x08 | 0x00
	uint64_t connection_id; // unique!
	uint32_t quic_version; // should be MakeQuicTag('Q', '0', '2', '5') but server may provide list
	uint8_t seq_num;		// must start with 1, increases strictly monotonic by one
	uint8_t fnv1a_hash[12];  // 12 byte fnv1a hash
#define PRIVATE_FLAG_NOTHING 0x00
#define PRIVATE_FLAG_HAS_ENTROPY 0x01
#define PRIVATE_FLAG_HAS_FEC_GROUP 0x02
#define PRIVATE_FLAG_IS_FEC 0x04
	//uint8_t private_flags;  // 0 or 1
} __attribute__ ((__packed__)) quic_common_hdr;


typedef struct {
	uint8_t public_flags;   // should be 0x01 | 0x0C  will have these set
	uint64_t connection_id; // unique!
	uint32_t versions[];	// 4 byte versions appended
} __attribute__ ((__packed__)) quic_version_neg;

// this is already memory aligned no need to pack
#define INCHOATE_CHLO_LEN 24
typedef struct {
	uint32_t tag;            // MakeQuicTag('C', 'H', 'L', 'O')
	uint16_t num_entries;    // 1
	uint16_t __padding;      // 0
	uint32_t p_tag;			// MakeQuicTag('P', 'A', 'D', '\0')
	uint32_t p_offset;		// offset from value start to end+1 of pad
	uint32_t v_tag;    // MakeQuicTag('V', 'E', 'R', 'S')
	uint32_t v_offset; // offset from value start to end+1 of vers
} quic_inchoate_chlo;


// also memory aligned
#define STREAM_FRAME_LEN 4
typedef struct {
	uint8_t type;			 //Positions (mask): 0x80 | 0x40 | 0x20 |0x1C | 0x03
#define FRAME_TYPE_STREAM 0x80
#define FRAME_STREAM_FIN 0x40
#define FRAME_STREAM_HAS_DATA 0x20
#define FRAME_STREAM_GET_OFFSET_LEN(x) ((x & 0x1C) >> 2)
#define FRAME_STREAM_CREATE_OFFSET_LEN(x) ((x & 0x07) << 2)
#define FRAME_STREAM_GET_SID_LEN(x) ((x & 0x03))
#define FRAME_STREAM_CREATE_SID_LEN(x) (x & 0x03)
							  //                   1  | FIN  | Data Len Present |
								//                offset (0,16,24,32,40,48,56,64) |
								//					len stream id (8,16,24,32)
	
	uint8_t stream_id;
#define FRAME_STREAM_CRYPTO_STREAM 0x01
	uint16_t data_len;			// len of data
} quic_stream_frame_packet;


#define CLIENTHELLO_MIN_SIZE (1200 - INCHOATE_CHLO_LEN)


static int num_ports;

probe_module_t module_quic_chlo;
static char filter_rule[30];
uint64_t connection_id;


uint8_t** checker_bitmap;



void chlo_quic_set_num_ports(int x)
{
	num_ports = x;
}

int chlo_quic_global_initialize(struct state_conf *conf) {
	num_ports = conf->source_port_last - conf->source_port_first + 1;
	
	char port[16];
	sprintf(port, "%d", conf->target_port);
	// answers have the target port as source
	memcpy(filter_rule, "udp src port \0", 14);

	module_quic_chlo.pcap_filter = strncat(filter_rule, port, 16);
	module_quic_chlo.pcap_snaplen = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + QUIC_HDR_LEN_HASH + STREAM_FRAME_LEN + INCHOATE_CHLO_LEN + CLIENTHELLO_MIN_SIZE;
	
	connection_id = MakeQuicTag('S', 'C', 'A', 'N')  | ((uint64_t)MakeQuicTag('N', 'I', 'N', 'G')) << 32;
	checker_bitmap = pbm_init();
	return EXIT_SUCCESS;
}

int chlo_quic_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
		__attribute__((unused)) struct state_send *zsend,
		__attribute__((unused)) struct state_recv *zrecv)
{

	return EXIT_SUCCESS;
}

int chlo_quic_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,\
		__attribute__((unused)) void **arg_ptr)
{
	int udp_send_msg_len = sizeof(quic_common_hdr) + STREAM_FRAME_LEN + INCHOATE_CHLO_LEN + CLIENTHELLO_MIN_SIZE;
	log_debug("prepare", "UDP PAYLOAD LEN: %d", udp_send_msg_len);

	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) + udp_send_msg_len);
	log_debug("prepare", "IP LEN IN HEX %#010x", len);
	make_ip_header(ip_header, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
	len = sizeof(struct udphdr) + udp_send_msg_len;
	make_udp_header(udp_header, zconf.target_port, len);

	char* payload = (char*)(&udp_header[1]);

	module_quic_chlo.packet_length = sizeof(struct ether_header) + sizeof(struct ip)
				+ sizeof(struct udphdr) + udp_send_msg_len;
	assert(module_quic_chlo.packet_length <= MAX_PACKET_SIZE);
	memset(payload, 0, udp_send_msg_len);

	
	// Seed our random number generator with the global generator
	/*
     uint32_t seed = aesrand_getword(zconf.aes);
	aesrand_t *aes = aesrand_init_from_seed(seed);
	*arg_ptr = aes;
     */
	return EXIT_SUCCESS;
}


// then use this to update the hash
__uint128_t fnv1a_128_inc(__uint128_t hash, const uint8_t* data, size_t len) {
	__uint128_t FNV_primeHI = 16777216;
	__uint128_t FNV_primeLO = 315;
	__uint128_t FNV_prime = FNV_primeHI << 64 | FNV_primeLO;
	
	
	for(size_t i = 0; i < len; i++) {
		hash = hash ^ (__uint128_t)data[i];
		hash = hash * FNV_prime;
	}
	
	return hash;
}

// start with this
__uint128_t fnv1a_128(const uint8_t* data, size_t len) {
	__uint128_t hashHI = 7809847782465536322;
	__uint128_t hashLO = 7113472399480571277;
	__uint128_t hash = hashHI << 64 | hashLO;
	return fnv1a_128_inc(hash, data, len);
}

void serializeHash(__uint128_t hash, uint8_t out_hash[12]) {
	// endianess I don't care....
	memcpy(out_hash, &hash, 12);
}


int chlo_quic_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
		uint32_t *validation, int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip *ip_header = (struct ip*) (&eth_header[1]);
	struct udphdr *udp_header= (struct udphdr *) &ip_header[1];
	//struct = (struct udphdr*) (&ip_header[1]);

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	udp_header->uh_sport = htons(get_src_port(num_ports, probe_num,
	                             validation));

	char *payload = (char *) &udp_header[1];
	int payload_len = 0;

	memset(payload, 0, MAX_UDP_PAYLOAD_LEN);

	// put quic chlo here!
	quic_common_hdr* common_hdr = (quic_common_hdr*)payload;
	common_hdr->public_flags = PUBLIC_FLAG_HAS_VERS | PUBLIC_FLAG_8BYTE_CONN_ID;
	// this should be unique
	common_hdr->connection_id = connection_id;
    common_hdr->quic_version = 0x0A0A0A0A;//MakeQuicTag('Q', '0', '4', '1');
	common_hdr->seq_num = 1;
	// Fill the hash later, but don't hash the hash itself
	memset(common_hdr->fnv1a_hash, 0, sizeof(common_hdr->fnv1a_hash));
	//common_hdr->private_flags = PRIVATE_FLAG_HAS_ENTROPY; // has entropy ...
	payload_len += sizeof(quic_common_hdr);
	
	
	// hash the public header
	__uint128_t hash = 0;
	hash = fnv1a_128((uint8_t*)payload, 14);

	// add a frame
	quic_stream_frame_packet* frame = (quic_stream_frame_packet*)(payload + payload_len);
	frame->type = FRAME_TYPE_STREAM | FRAME_STREAM_HAS_DATA | FRAME_STREAM_CREATE_SID_LEN(0);
	frame->stream_id = FRAME_STREAM_CRYPTO_STREAM;
	
	// there is a minimum length of a hello.. don't know to what that actually referers, total length?
	int pad_len = (CLIENTHELLO_MIN_SIZE - sizeof(uint32_t));
	frame->data_len = INCHOATE_CHLO_LEN + pad_len + sizeof(uint32_t);
	
	payload_len += STREAM_FRAME_LEN;

	quic_inchoate_chlo* chlo = (quic_inchoate_chlo*)(payload + payload_len);
	chlo->tag = MakeQuicTag('C', 'H', 'L', 'O');
	chlo->num_entries = 2;
	chlo->__padding = 0;
	chlo->p_tag = MakeQuicTag('P', 'A', 'D', '\0');
	chlo->p_offset = pad_len;		// offset from value start to end+1 of pad
	chlo->v_tag = MakeQuicTag('V', 'E', 'R', '\0');
	chlo->v_offset = pad_len + sizeof(uint32_t);
	
	payload_len += INCHOATE_CHLO_LEN;
	
	char* value_data = payload + payload_len;
	memset(value_data, 0x2d, pad_len);
//	printf("PADDING LENGTH: %d\n", pad_len);
	payload_len += pad_len;
	value_data += pad_len;
    *((uint32_t*)value_data) = 0x0A0A0A0A;//MakeQuicTag('Q', '0', '4', '1');
	payload_len += sizeof(uint32_t);
	

	// hash the payload (private + frames), excluding the hash field itself
	hash = fnv1a_128_inc(hash, (uint8_t*)payload+26, payload_len-26);

	uint8_t serializedHash[12];
	serializeHash(hash, serializedHash);
	
	memcpy(common_hdr->fnv1a_hash, serializedHash, sizeof(serializedHash));
	
	
	// Update the IP and UDP headers to match the new payload length
	ip_header->ip_len   = htons(sizeof(struct ip) + sizeof(struct udphdr) + payload_len);
	udp_header->uh_ulen = ntohs(sizeof(struct udphdr) + payload_len);
	

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void chlo_quic_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
    struct udphdr *udph = (struct udphdr*)(&iph[1]); 
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %u }\n",
		ntohs(udph->uh_sport),
		ntohs(udph->uh_dport),
		ntohl(udph->uh_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void chlo_quic_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs, UNUSED uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);

		
		// Verify that the UDP length is big enough for the header and at least one byte
		uint16_t data_len = ntohs(udp->uh_ulen);
		if (data_len > sizeof(struct udphdr)) {
			uint8_t* payload = (uint8_t*)&udp[1];
			if (data_len > (QUIC_HDR_LEN_HASH - 13 - sizeof(struct udphdr))) {
                quic_common_hdr* quic_header = ((quic_common_hdr*)payload);
				if(quic_header->connection_id == connection_id) {
					fs_add_string(fs, "classification", (char*) "quic", 0);
					fs_add_uint64(fs, "success", 1);
				}
				
                
				// probably we got back a version packet
				if (data_len < (QUIC_HDR_LEN_HASH + CLIENTHELLO_MIN_SIZE - sizeof(struct udphdr))) {
					quic_version_neg* vers = (quic_version_neg*)payload;
					if ((vers->public_flags & PUBLIC_FLAG_HAS_VERS) > 0) {
						// contains version flag
						int num_versions = (data_len - sizeof(struct udphdr) - 8 - 1) / 4;
                        if (num_versions > 0) {

                            // create a list of the versions
                            // 4 bytes each + , + [SPACE] + \0
                            char* versions = malloc(num_versions * 8 + (num_versions-1) + 1);
                            int next_ver = 0;
                            
                            if (*((uint32_t*)&vers->versions[0]) == MakeQuicTag('Q', '0', '0', '1')) {
                                // someone replied with our own version... probalby UDP echo
                                fs_modify_string(fs, "classification", (char*) "udp", 0);
                                fs_modify_uint64(fs, "success", 0);
                                free(versions);
                                return;
                            }
                            fs_add_bool(fs, "has_reserved_vers", 0);
                            for (int i = 0; i < num_versions; i++) {
                                if ((vers->versions[i] & 0x0f0f0f0f) == 0x0a0a0a0a) {
                                    fs_modify_bool(fs, "has_reserved_vers", 1);
                                    //continue;
                                }
                                uint8_t* v = (uint8_t*)&vers->versions[i];
                                sprintf(&versions[next_ver], "%02X%02X%02X%02X", v[0], v[1], v[2], v[3]);
                                //memcpy(&versions[next_ver], &vers->versions[i], sizeof(uint32_t));
                                next_ver += 8;
                                if(i != num_versions-1) {
                                    versions[next_ver++] = ',';
                                }
                            }
                            versions[next_ver] = '\0';
                            fs_add_string(fs, "versions", versions, 1);
                            //fs_add_binary(fs, "versions", num_versions * sizeof(uint32_t), vers->versions, 0);
                            
                        }
                    }else if ((vers->public_flags & PUBLIC_FLAG_HAS_RST) > 0) {
                        fs_modify_string(fs, "info", (char*) "RST", 0);
                    }
				}
			}
		} else {
			fs_add_string(fs, "classification", (char*) "udp", 0);
			fs_add_uint64(fs, "success", 0);
		}
	}
}

int chlo_quic_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip, UNUSED uint32_t *validation)
{
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		if ((4*ip_hdr->ip_hl + sizeof(struct udphdr)) > len) {
			// buffer not large enough to contain expected udp header
			return 0;
		}
		
		
		int already_checked = pbm_check(checker_bitmap, ntohl(ip_hdr->ip_src.s_addr));
		if (already_checked) {
			return 0;
		}
		
		pbm_set(checker_bitmap, ntohl(ip_hdr->ip_src.s_addr));
		
		return 1;
	}

	
	return 0;
}

int quic_chlo_pcap_filter(char* out_filter, size_t max_len) {
    unsigned int len = snprintf(out_filter, 0, "udp src port %d", zconf.target_port);
    
    if (len <= max_len) {
        snprintf(out_filter, max_len, "udp src port %d", zconf.target_port);
        log_info("quic_chlo", "Using Filter %s", out_filter);
        return 0;
    }
    
    return -1;
}


static fielddef_t fields[] = {
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="int", .desc = "is response considered success"},
	{.name = "versions", .type="string", .desc = "versions if reported"},
    {.name = "has_reserved_vers", .type="bool", .desc = "versions included reserved ones"},
    {.name = "info", .type="string", .desc = "info"}
};

probe_module_t module_quic_chlo = {
	.name = "quic_chlo",
	// we are resetting the actual packet length during initialization of the module
	.packet_length = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(quic_common_hdr) + STREAM_FRAME_LEN + INCHOATE_CHLO_LEN + CLIENTHELLO_MIN_SIZE,
	// this gets replaced by the actual port during global init
	.pcap_filter = "udp src port 443",
    //.pcap_filter_func = &quic_chlo_pcap_filter,
	// this gets replaced by the actual payload we expect to get back
	.pcap_snaplen = 1500,
	.port_args = 1,
	.thread_initialize = &chlo_quic_init_perthread,
	.global_initialize = &chlo_quic_global_initialize,
	.make_packet = &chlo_quic_make_packet,
	.print_packet = &chlo_quic_print_packet,
	.validate_packet = &chlo_quic_validate_packet,
	.process_packet = &chlo_quic_process_packet,
	.close = &chlo_quic_global_cleanup,
	.helptext = "Probe module that sends QUIC CHLO packets to hosts.",
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
};

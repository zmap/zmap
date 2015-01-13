//probe module for NTP scans
//following RFC for NTP

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "probe_modules.h"
#include "module_udp.h"
#include "module_ntp.h"
#include "packet.h"
#include "logger.h"

#define MAX_NTP_PAYLOAD_LEN 1472
#define UNUSED __attribute__((unused))

probe_module_t module_ntp;

static int num_ports;
static int udp_send_msg_len = 0;
static char *udp_send_msg = NULL;

static const char *udp_send_msg_default = "GET / HTTP/1.1\r\nHost: www\r\n\r\n";

int ntp_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
                    uint32_t *validation, int probe_num)
{
 
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip *ip_header = (struct ip*) (&eth_header[1]);
	struct udphdr *udp_header= (struct udphdr *) &ip_header[1];
    struct ntphdr *ntp = (struct ntphdr *) &udp_header[1];
    
	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	udp_header->uh_sport = htons(get_src_port(num_ports, probe_num,
                                              validation));
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

    //Sets LI_VN_MODE to 11100011
    //Sends a packet with NTP version 4 and as a client (to a server)
    ntp->LI_VN_MODE = 227;
    
	return EXIT_SUCCESS;
}

void ntp_process_packet(const void *packet, __attribute__((unused)) uint32_t len, fieldset_t *fs)
{
    udp_process_packet(packet, len, fs);

    struct ip *ip_hdr = (struct ip *) &((struct ether_header *)packet)[1];
    int *ptr;
    uint64_t temp64;
    uint8_t temp8;
    uint32_t temp32;

    if(ip_hdr->ip_p ==  IPPROTO_UDP){
        struct udphdr *udp = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
        struct module_ntp *ntp = (struct module_ntp *) &udp[1];
        
        fs_modify_string(fs, "classification", (char*) "ntp", 0);
        
        ptr = (int *)ntp;

        temp8 = *((uint8_t *)ptr); 
        fs_add_uint64(fs, "LI_VN_MODE", temp8);
        temp8 = *((uint8_t *)ptr +1);
        fs_add_uint64(fs, "stratum", temp8);
        temp8 = *((uint8_t *)ptr +2);
        fs_add_uint64(fs, "poll", temp8);
        temp8 = *((uint8_t *)ptr + 3);
        fs_add_uint64(fs, "precision", temp8);
    
        temp32 = *((uint32_t *)ptr + 4);
        fs_add_uint64(fs, "root_delay", temp32);
        temp32 = *((uint32_t *)ptr + 8);
        fs_add_uint64(fs, "root_dispersion", temp32);
        temp32 = *((uint32_t *)ptr + 12);
        fs_add_uint64(fs, "reference_clock_identifier", temp32);

        temp64 = *((uint64_t *)ptr + 16);
        fs_add_uint64(fs, "reference_timestamp", temp64);
        temp64 = *((uint64_t *)ptr + 24);
        fs_add_uint64(fs, "originate_timestap", temp64);
        temp64 = *((uint64_t *)ptr + 32);
        fs_add_uint64(fs, "receive_timestamp", temp64);
        temp64 = *((uint64_t *)ptr + 40);
        fs_add_uint64(fs, "transmit_timestamp", temp64);

    }
}

int ntp_init_perthread(void *buf, macaddr_t *src, 
        macaddr_t *gw, __attribute__((unused)) port_h_t dst_port, void **arg){
   

    udp_send_msg = strdup(udp_send_msg_default);
    udp_send_msg_len = strlen(udp_send_msg);

    memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct ntphdr));
	make_ip_header(ip_header, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
	struct ntphdr *ntp_header = (struct ntphdr*)(&udp_header[1]);
    ntp_header -> LI_VN_MODE = 227;
    len = sizeof(struct udphdr) + sizeof(struct ntphdr);

	make_udp_header(udp_header, zconf.target_port, len);

	char* payload = (char*)(&ntp_header[1]);

	module_ntp.packet_length = sizeof(struct ether_header) + sizeof(struct ip) 
				+ sizeof(struct udphdr) + sizeof(struct ntphdr);


	assert(module_ntp.packet_length <= MAX_PACKET_SIZE);


	memcpy(payload, ntp_header, module_ntp.packet_length);

    uint32_t seed = aesrand_getword(zconf.aes);
    aesrand_t *aes = aesrand_init_from_seed(seed);
    *arg = aes;

	return EXIT_SUCCESS;
}

void ntp_print_packet(FILE *fp, const void *packet){
    
    struct ether_header *ethh = (struct ether_header *)packet;
    struct ip *iph = (struct ip *) &ethh[1];
    struct udphdr *udph = (struct udphdr *) (iph + 4*iph->ip_hl);
    struct ntphdr *ntph = (struct ntphdr *) &udph[1];
    fprintf(fp, "ntp { LI_VN_MODE: %u | stratum: %u | poll: %u }\n",
            ntph->LI_VN_MODE, ntph->stratum, ntph->poll);
    udp_print_packet(fp, packet);
}

static fielddefset_t fields = {
  .fielddefs = {
    {.name = "LI_VN_MODE", .type = "int", .desc = "leap indication, version number, mode"},
    {.name = "stratum", .type = "int", .desc = "stratum"},
    {.name = "poll", .type ="int", .desc = "poll"},
    {.name = "precision", .type = "int", .desc = "precision"},
    {.name = "root_delay", .type = "int", .desc = "root delay"},
    {.name = "root_dispersion", .type = "int", .desc = "root dispersion"},
    {.name = "reference_clock_identifier", .type = "int", .desc = "code identifying clock reference"},
    {.name = "reference_timestamp", .type = "int", .desc = "local time at which local clock was last set or corrected"},
    {.name = "originate_timestamp", .type = "int", .desc = "local time at which request deparated client for service"},
    {.name = "receive_timestamp", .type = "int", .desc = "local time at which request arrvied at service host"},
    {.name = "transmit_timestamp", .type = "int", .desc = "local time which reply departed service host for client"},
  },
  .len = 11
};

probe_module_t module_ntp = {
    .name = "ntp",
    .packet_length = 1,
    .pcap_filter = "udp || icmp",
    .pcap_snaplen = 1500,
    .port_args = 1,
    .thread_initialize = &ntp_init_perthread,
    .global_initialize = &udp_global_initialize,
    .make_packet = &udp_make_packet,
    .print_packet = &ntp_print_packet,
    .validate_packet = &udp_validate_packet,
    .process_packet = &ntp_process_packet,
    .close = &udp_global_cleanup,
    .fieldsets = (fielddefset_t*[]){
        &ip_fields,
	&udp_fields,
        &fields
    },
    .num_fieldsets = 2
};

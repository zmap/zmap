/* heavily copied from module_udp.c */
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/blocklist.h"
#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../../lib/lockfd.h"
#include "../../lib/logger.h"
#include "../../lib/xalloc.h"

#include "../state.h"
#include "../validate.h"

#include "probe_modules.h"
#include "packet.h"

#define MAX_UDP_PAYLOAD_LEN 200
#define ICMP_UNREACH_HEADER_SIZE 8
#define UNUSED __attribute__((unused))

#define SOURCE_PORT_VALIDATION_MODULE_DEFAULT true; // default to validating source port
static bool should_validate_src_port = SOURCE_PORT_VALIDATION_MODULE_DEFAULT
static char *udp_send_msg = NULL;
static int udp_send_msg_len = 0;

static const char *udp_send_msg_default = "GET / HTTP/1.1\r\nHost: www\r\n\r\n";
#define DEFUALT_PAYLOAD_LEN (30)

const char *ipip_usage_error =
    "unknown UDP probe specification (expected file:/path or text:STRING or hex:01020304)";

static int num_ports;

probe_module_t module_ipip;

int ipip_global_initialize(struct state_conf *conf)
{
	char *args, *c;
	int i;
	unsigned int n;

	FILE *inp;

	num_ports = conf->source_port_last - conf->source_port_first + 1;
	if (conf->validate_source_port_override == VALIDATE_SRC_PORT_DISABLE_OVERRIDE) {
		log_debug("ipip", "disabling source port validation");
		should_validate_src_port = false;
	}

	udp_send_msg = strdup(udp_send_msg_default);
	udp_send_msg_len = strlen(udp_send_msg);

	if (!(conf->probe_args && strlen(conf->probe_args) > 0))
		return (0);

	args = strdup(conf->probe_args);
	assert(args);

	c = strchr(args, ':');
	if (!c) {
		free(args);
		free(udp_send_msg);
		log_fatal("ipip", "%s", ipip_usage_error);
	}

	*c++ = 0;

	if (strcmp(args, "text") == 0) {
		free(udp_send_msg);
		udp_send_msg = strdup(c);
		udp_send_msg_len = strlen(udp_send_msg);

	} else if (strcmp(args, "file") == 0) {
		inp = fopen(c, "rb");
		if (!inp) {
			free(udp_send_msg);
			// c points to memory in args, let exit free args
			log_fatal("ipip", "could not open UDP data file '%s'",
				  c);
		}
		free(udp_send_msg);
		udp_send_msg = xmalloc(MAX_UDP_PAYLOAD_LEN);
		udp_send_msg_len =
		    fread(udp_send_msg, 1, MAX_UDP_PAYLOAD_LEN, inp);
		fclose(inp);

	} else if (strcmp(args, "hex") == 0) {
		udp_send_msg_len = strlen(c) / 2;
		free(udp_send_msg);
		udp_send_msg = xmalloc(udp_send_msg_len);

		for (i = 0; i < udp_send_msg_len; i++) {
			if (sscanf(c + (i * 2), "%2x", &n) != 1) {
				char nonhexchr = c[i * 2];
				free(args);
				free(udp_send_msg);
				log_fatal("ipip", "non-hex character: '%c'",
					  nonhexchr);
			}
			udp_send_msg[i] = (n & 0xff);
		}
	} else {
		free(udp_send_msg);
		free(args);
		log_fatal("ipip", "%s", ipip_usage_error);
	}

	if (udp_send_msg_len > MAX_UDP_PAYLOAD_LEN) {
		log_warn("ipip",
			 "warning: reducing UDP payload to %d "
			 "bytes (from %d) to fit on the wire",
			 MAX_UDP_PAYLOAD_LEN, udp_send_msg_len);
		udp_send_msg_len = MAX_UDP_PAYLOAD_LEN;
	}

	module_ipip.max_packet_length = sizeof(struct ether_header) +
					sizeof(struct ip) * 2 +
					sizeof(struct udphdr) + udp_send_msg_len;
	assert(module_ipip.max_packet_length <= MAX_PACKET_SIZE);

	free(args);
	return EXIT_SUCCESS;
}

int ipip_global_cleanup(UNUSED struct state_conf *zconf,
			UNUSED struct state_send *zsend,
			UNUSED struct state_recv *zrecv)
{
	if (udp_send_msg) {
		free(udp_send_msg);
		udp_send_msg = NULL;
	}

	return EXIT_SUCCESS;
}

int ipip_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw,
			UNUSED void *arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) * 2 + sizeof(struct udphdr) +
			     udp_send_msg_len);
	make_ip_header(ip_header, IPPROTO_IPIP, len);
	struct ip *ip_header2 = &ip_header[1];
	len =
	    htons(sizeof(struct ip) + sizeof(struct udphdr) + udp_send_msg_len);
	make_ip_header(ip_header2, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr *)(&ip_header2[1]);
	len = sizeof(struct udphdr) + udp_send_msg_len;
	make_udp_header(udp_header, len);

	char *payload = (char *)(&udp_header[1]);

	memcpy(payload, udp_send_msg, udp_send_msg_len);

	return EXIT_SUCCESS;
}

int ipip_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip,
		     ipaddr_n_t dst_ip, port_n_t dport, UNUSED uint8_t ttl,
		     uint32_t *validation, int probe_num, uint16_t ip_id,
		     UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct ip *ip_header2 = (struct ip *)(&ip_header[1]);
	struct udphdr *udp_header = (struct udphdr *)&ip_header2[1];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_id = ip_id;
	ip_header2->ip_src.s_addr = dst_ip;
	ip_header2->ip_dst.s_addr = src_ip; // TODO put "external_ip"
	ip_header2->ip_id = ip_id;
	udp_header->uh_sport =
	    htons(get_src_port(num_ports, probe_num, validation));
	udp_header->uh_dport = dport;

	ip_header2->ip_sum = 0;
	ip_header2->ip_sum = zmap_ip_checksum((unsigned short *)ip_header2);
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	// Output the total length of the packet
	const size_t header_len = sizeof(struct ether_header) + sizeof(struct ip) +
				  sizeof(struct ip) + sizeof(struct udphdr);
	*buf_len = header_len + udp_send_msg_len;
	return EXIT_SUCCESS;
}

void ipip_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct ip *iph2 = (struct ip *)&iph[1];
	struct udphdr *udph = (struct udphdr *)(&iph2[1]);
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %#04X }\n",
		ntohs(udph->uh_sport), ntohs(udph->uh_dport),
		ntohs(udph->uh_sum));
	fprintf_ip_header(fp, iph2);
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void ipip_process_packet(const u_char *packet, UNUSED uint32_t len,
			 fieldset_t *fs, UNUSED uint32_t *validation,
			 UNUSED const struct timespec ts)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr *udp =
		    (struct udphdr *)((char *)ip_hdr + ip_hdr->ip_hl * 4);
		fs_add_constchar(fs, "classification", "udp");
		fs_add_bool(fs, "success", 1);
		fs_add_uint64(fs, "sport", ntohs(udp->uh_sport));
		fs_add_uint64(fs, "dport", ntohs(udp->uh_dport));
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_uint64(fs, "udp_pkt_size", ntohs(udp->uh_ulen));
		// Verify that the UDP length is big enough for the header and
		// at least one byte
		uint16_t data_len = ntohs(udp->uh_ulen);
		if (data_len > sizeof(struct udphdr)) {
			uint32_t overhead =
			    (sizeof(struct udphdr) + (ip_hdr->ip_hl * 4));
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
			fs_add_binary(fs, "data", data_len, (void *)&udp[1], 0);
			// Some devices reply with a zero UDP length but still
			// return data, ignore the data
		} else {
			fs_add_null(fs, "data");
		}
	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		struct icmp *icmp =
		    (struct icmp *)((char *)ip_hdr + ip_hdr->ip_hl * 4);
		struct ip *ip_inner =
		    (struct ip *)((char *)icmp + ICMP_UNREACH_HEADER_SIZE);
		// ICMP unreach comes from another server (not the one we sent a
		// probe to); But we will fix up saddr to be who we sent the
		// probe to, in case you care.
		fs_modify_string(fs, "saddr",
				 make_ip_str(ip_inner->ip_dst.s_addr), 1);
		fs_add_string(fs, "classification", (char *)"icmp-unreach", 0);
		fs_add_bool(fs, "success", 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_string(fs, "icmp_responder",
			      make_ip_str(ip_hdr->ip_src.s_addr), 1);
		fs_add_uint64(fs, "icmp_type", icmp->icmp_type);
		fs_add_uint64(fs, "icmp_code", icmp->icmp_code);
		if (icmp->icmp_code <= ICMP_UNREACH_PRECEDENCE_CUTOFF) {
			fs_add_string(
			    fs, "icmp_unreach_str",
			    (char *)icmp_unreach_strings[icmp->icmp_code], 0);
		} else {
			fs_add_string(fs, "icmp_unreach_str", (char *)"unknown",
				      0);
		}
		fs_add_null(fs, "udp_pkt_size");
		fs_add_null(fs, "data");
	} else {
		fs_add_string(fs, "classification", (char *)"other", 0);
		fs_add_bool(fs, "success", 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_null(fs, "udp_pkt_size");
		fs_add_null(fs, "data");
	}
}

int ipip_validate_packet(const struct ip *ip_hdr, uint32_t len,
			 uint32_t *src_ip, uint32_t *validation,
			 const struct port_conf *ports)
{
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		if ((4 * ip_hdr->ip_hl + sizeof(struct udphdr)) > len) {
			// buffer not large enough to contain expected udp
			// header
			return PACKET_INVALID;
		}
		struct udphdr *udp =
		    (struct udphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
		uint16_t dport = ntohs(udp->uh_dport);
		if (should_validate_src_port && !check_src_port(dport, ports)) {
			return PACKET_INVALID;
		}
		if (!blocklist_is_allowed(*src_ip)) {
			return PACKET_INVALID;
		}
		uint16_t sport = ntohs(udp->uh_sport);
		if (check_dst_port(sport, num_ports, validation)) {
			return PACKET_VALID;
		}
		for (unsigned i = 0; i < zconf.number_source_ips; i++) {
			validate_gen(
			    zconf.source_ip_addresses[i],
			    ip_hdr->ip_src.s_addr, udp->uh_dport, (uint8_t *)validation);
			if (check_dst_port(sport, num_ports, validation)) {
				return PACKET_VALID;
			}
		}
	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		// IPIP can return ICMP Destination unreach
		// IP( ICMP( IP ( IP( UDP ) ) ) ) for a destination unreach
		uint32_t min_len =
		    4 * ip_hdr->ip_hl + ICMP_UNREACH_HEADER_SIZE +
		    sizeof(struct ip) + sizeof(struct ip) + sizeof(struct udphdr);
		if (len < min_len) {
			return PACKET_INVALID;
		}
		struct icmp *icmp =
		    (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
		if (icmp->icmp_type != ICMP_UNREACH) {
			return PACKET_INVALID;
		}
		struct ip *ip_inner1 =
		    (struct ip *)((char *)icmp + ICMP_UNREACH_HEADER_SIZE);
		// update min_len according to first internal IP packet
		min_len = min_len - sizeof(struct ip) + 4 * ip_inner1->ip_hl;
		if (len < min_len) {
			return PACKET_INVALID;
		}
		uint32_t dest = ip_inner1->ip_dst.s_addr;
		if (!blocklist_is_allowed(dest)) {
			return PACKET_INVALID;
		}
		struct ip *ip_inner2 =
		    (struct ip *)((char *)ip_inner1 + 4 * ip_inner1->ip_hl);
		// update min_len according to second internal IP packet
		min_len = min_len - sizeof(struct ip) + 4 * ip_inner2->ip_hl;
		if (len < min_len) {
			return PACKET_INVALID;
		}
		// ensure the internal dst addr is the outer src addr and vice versa
		if (ip_inner1->ip_dst.s_addr != ip_inner2->ip_src.s_addr ||
		    ip_inner1->ip_src.s_addr != ip_inner2->ip_dst.s_addr) {
			return PACKET_INVALID;
		}
		struct udphdr *udp =
		    (struct udphdr *)((char *)ip_inner2 + 4 * ip_inner2->ip_hl);
		// we can always check the destination port because this is the
		// original packet and wouldn't have been altered by something
		// responding on a different port
		uint16_t dport = ntohs(udp->uh_dport);
		if (should_validate_src_port && !check_src_port(dport, ports)) {
			return PACKET_INVALID;
		}
		uint16_t sport = ntohs(udp->uh_sport);
		if (!check_dst_port(sport, num_ports, validation)) {
			return PACKET_INVALID;
		}
		return PACKET_VALID;
	}
	return PACKET_INVALID;
}

static fielddef_t fields[] = {
    {.name = "classification",
     .type = "string",
     .desc = "packet classification"},
    {.name = "success",
     .type = "bool",
     .desc = "is response considered success"},
    {.name = "sport", .type = "int", .desc = "UDP source port"},
    {.name = "dport", .type = "int", .desc = "UDP destination port"},
    {.name = "icmp_responder",
     .type = "string",
     .desc = "Source IP of ICMP_UNREACH message"},
    {.name = "icmp_type", .type = "int", .desc = "icmp message type"},
    {.name = "icmp_code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp_unreach_str",
     .type = "string",
     .desc =
	 "for icmp_unreach responses, the string version of icmp_code (e.g. network-unreach)"},
    {.name = "udp_pkt_size", .type = "int", .desc = "UDP packet length"},
    {.name = "data", .type = "binary", .desc = "UDP payload"}};

probe_module_t module_ipip = {
    .name = "ipip",
    .max_packet_length = sizeof(struct ether_header) + sizeof(struct ip) * 2 +
			 sizeof(struct udphdr) + DEFUALT_PAYLOAD_LEN,
    .pcap_filter = "udp || icmp",
    .pcap_snaplen = 1500,
    .port_args = 1,
    .global_initialize = &ipip_global_initialize,
    .prepare_packet = &ipip_prepare_packet,
    .make_packet = &ipip_make_packet,
    .print_packet = &ipip_print_packet,
    .validate_packet = &ipip_validate_packet,
    .process_packet = &ipip_process_packet,
    .close = &ipip_global_cleanup,
    .helptext = "Probe module that sends UDP packets to hosts. Packets can "
		"optionally be templated based on destination host. Specify"
		" packet file with --probe-args=file:/path_to_packet_file "
		"and templates with template:/path_to_template_file.",
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};

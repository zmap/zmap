/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include <pcap.h>
#include <pcap/pcap.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/pbm.h"

#include "state.h"
#include "validate.h"
#include "fieldset.h"
#include "expression.h"
#include "probe_modules/probe_modules.h"
#include "output_modules/output_modules.h"

#define PCAP_PROMISC 1
#define PCAP_TIMEOUT 1000

static uint32_t num_src_ports;
static pcap_t *pc = NULL;

// bitmap of observed IP addresses
static uint64_t **seen = NULL;

static u_char fake_eth_hdr[65535];

void packet_cb(u_char __attribute__((__unused__)) *user,
		const struct pcap_pkthdr *p, const u_char *bytes)
{
	if (!p) {
		return;
	}
	if (zrecv.success_unique >= zconf.max_results) {
		// Libpcap can process multiple packets per pcap_dispatch;
		// we need to throw out results once we've
		// gotten our --max-results worth.
		return;
	}
	// length of entire packet captured by libpcap
	uint32_t buflen = (uint32_t) p->caplen;

	if ((sizeof(struct ip) + (zconf.send_ip_pkts ? 0 : sizeof(struct ether_header))) > buflen) {
		// buffer not large enough to contain ethernet
		// and ip headers. further action would overrun buf
		return;
	}
	struct ip *ip_hdr = (struct ip *) &bytes[(zconf.send_ip_pkts ? 0 : sizeof(struct ether_header))];

	uint32_t src_ip = ip_hdr->ip_src.s_addr;

	uint32_t validation[VALIDATE_BYTES/sizeof(uint8_t)];
	// TODO: for TTL exceeded messages, ip_hdr->saddr is going to be different
	// and we must calculate off potential payload message instead
	validate_gen(ip_hdr->ip_dst.s_addr, ip_hdr->ip_src.s_addr, (uint8_t *) validation);

	if (!zconf.probe_module->validate_packet(ip_hdr, buflen - (zconf.send_ip_pkts ? 0 : sizeof(struct ether_header)),
				&src_ip, validation)) {
		return;
	}

	int is_repeat = pbm_check(seen, ntohl(src_ip));

	fieldset_t *fs = fs_new_fieldset();
	fs_add_ip_fields(fs, ip_hdr);
	// HACK:
	// probe modules (for whatever reason) expect the full ethernet frame
	// in process_packet. For VPN, we only get back an IP frame.
	// Here, we fake an ethernet frame (which is initialized to
	// have ETH_P_IP proto and 00s for dest/src).
	if (zconf.send_ip_pkts) {
		if (buflen > sizeof(fake_eth_hdr)) {
			buflen = sizeof(fake_eth_hdr);
		}
		memcpy(&fake_eth_hdr[sizeof(struct ether_header)], bytes, buflen);
		bytes = fake_eth_hdr;
	}
	zconf.probe_module->process_packet(bytes, buflen, fs);
	fs_add_system_fields(fs, is_repeat, zsend.complete);
	int success_index = zconf.fsconf.success_index;
	assert(success_index < fs->len);
	int is_success = fs_get_uint64_by_index(fs, success_index);

	if (is_success) {
		zrecv.success_total++;
		if (!is_repeat) {
			zrecv.success_unique++;
			pbm_set(seen, ntohl(src_ip));
		}
		if (zsend.complete) {
			zrecv.cooldown_total++;
			if (!is_repeat) {
				zrecv.cooldown_unique++;
			}
		}
	} else {
		zrecv.failure_total++;
	}
	fieldset_t *o = NULL;
	// we need to translate the data provided by the probe module
	// into a fieldset that can be used by the output module
	if (!is_success && zconf.filter_unsuccessful) {
		goto cleanup;
	}
	if (is_repeat && zconf.filter_duplicates) {
		goto cleanup;
	}
	if (!evaluate_expression(zconf.filter.expression, fs)) {
		goto cleanup;
	}
	o = translate_fieldset(fs, &zconf.fsconf.translation);
	if (zconf.output_module && zconf.output_module->process_ip) {
		zconf.output_module->process_ip(o);
	}
cleanup:
	fs_free(fs);
	free(o);
	if (zconf.output_module && zconf.output_module->update
			&& !(zrecv.success_unique % zconf.output_module->update_interval)) {
		zconf.output_module->update(&zconf, &zsend, &zrecv);
	}
}

int recv_update_pcap_stats(void)
{
	if (!pc) {
		return EXIT_FAILURE;
	}
	struct pcap_stat pcst;
	if (pcap_stats(pc, &pcst)) {
		log_error("recv", "unable to retrieve pcap statistics: %s",
				pcap_geterr(pc));
		return EXIT_FAILURE;
	} else {
		zrecv.pcap_recv = pcst.ps_recv;
		zrecv.pcap_drop = pcst.ps_drop;
		zrecv.pcap_ifdrop = pcst.ps_ifdrop;
	}
	return EXIT_SUCCESS;
}

int recv_run(pthread_mutex_t *recv_ready_mutex)
{
	log_debug("recv", "thread started");
	num_src_ports = zconf.source_port_last - zconf.source_port_first + 1;
	log_debug("recv", "using dev %s", zconf.iface);
	if (!zconf.dryrun) {
		char errbuf[PCAP_ERRBUF_SIZE];
		pc = pcap_open_live(zconf.iface, zconf.probe_module->pcap_snaplen,
						PCAP_PROMISC, PCAP_TIMEOUT, errbuf);
		if (pc == NULL) {
			log_fatal("recv", "could not open device %s: %s",
							zconf.iface, errbuf);
		}
		struct bpf_program bpf;
		if (pcap_compile(pc, &bpf, zconf.probe_module->pcap_filter, 1, 0) < 0) {
			log_fatal("recv", "couldn't compile filter");
		}
		if (pcap_setfilter(pc, &bpf) < 0) {
			log_fatal("recv", "couldn't install filter");
		}
		// set pcap_dispatch to not hang if it never receives any packets
		// this could occur if you ever scan a small number of hosts as
		// documented in issue #74.
		if (pcap_setnonblock (pc, 1, errbuf) == -1) {
			log_fatal("recv", "pcap_setnonblock error:%s", errbuf);
		}
	}
	if (zconf.send_ip_pkts) {
		struct ether_header *eth = (struct ether_header *) fake_eth_hdr;
		memset(fake_eth_hdr, 0, sizeof(fake_eth_hdr));
		eth->ether_type = htons(ETHERTYPE_IP);
	}
	// initialize paged bitmap
	seen = pbm_init();
	log_debug("recv", "receiver ready");
	if (zconf.filter_duplicates) {
		log_debug("recv", "duplicate responses will be excluded from output"); 
	} else {
		log_debug("recv", "duplicate responses will be included in output"); 
	}
	if (zconf.filter_unsuccessful) {
		log_debug("recv", "unsuccessful responses will be excluded from output"); 
	} else {
		log_debug("recv", "unsuccessful responses will be included in output"); 
	}
	
	pthread_mutex_lock(recv_ready_mutex);
	zconf.recv_ready = 1;
	pthread_mutex_unlock(recv_ready_mutex);
	zrecv.start = now();
	if (zconf.max_results == 0) {
		zconf.max_results = -1;
	}
	
	do {
		if (zconf.dryrun) {
			sleep(1);
		} else {
			if (pcap_dispatch(pc, 0, packet_cb, NULL) == -1) {
				log_fatal("recv", "pcap_dispatch error");
			}
			if (zconf.max_results && zrecv.success_unique >= zconf.max_results) {
				zsend.complete = 1;
				break;
			}
		}
	} while (!(zsend.complete && (now()-zsend.finish > zconf.cooldown_secs)));
	zrecv.finish = now();
	// get final pcap statistics before closing
	recv_update_pcap_stats();
	pcap_close(pc);
	zrecv.complete = 1;
	log_debug("recv", "thread finished");
	return 0;
}


/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "utility.h"

#include <stdio.h>
#include <arpa/inet.h>

#include "state.h"
#include "../lib/logger.h"

in_addr_t string_to_ip_address(char *t)
{
	in_addr_t r = inet_addr(t);
	if (r == INADDR_NONE) {
		log_fatal("send", "invalid ip address: `%s'", t);
	}
	return r;
}

void add_to_array(char *to_add)
{
	if (zconf.number_source_ips >= 256) {
		// log fatal here
		log_fatal("parse", "over 256 source IP addresses provided");
	}
	log_debug("SEND", "ipaddress: %s\n", to_add);
	zconf.source_ip_addresses[zconf.number_source_ips] =
	    string_to_ip_address(to_add);
	zconf.number_source_ips++;
}

void parse_source_ip_addresses(char given_string[])
{
	char *dash = strchr(given_string, '-');
	char *comma = strchr(given_string, ',');
	if (dash && comma) {
		*comma = '\0';
		parse_source_ip_addresses(given_string);
		parse_source_ip_addresses(comma + 1);
	} else if (comma) {
		while (comma) {
			*comma = '\0';
			add_to_array(given_string);
			given_string = comma + 1;
			comma = strchr(given_string, ',');
			if (!comma) {
				add_to_array(given_string);
			}
		}
	} else if (dash) {
		*dash = '\0';
		log_debug("SEND", "address: %s\n", given_string);
		log_debug("SEND", "address: %s\n", dash + 1);
		in_addr_t start = ntohl(string_to_ip_address(given_string));
		in_addr_t end = ntohl(string_to_ip_address(dash + 1)) + 1;
		while (start != end) {
			struct in_addr temp;
			temp.s_addr = htonl(start);
			add_to_array(strdup(inet_ntoa(temp)));
			start++;
		}
	} else {
		add_to_array(given_string);
	}
}

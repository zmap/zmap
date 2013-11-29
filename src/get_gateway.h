/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GET_GATEWAY_H
#define GET_GATEWAY_H

#include <netinet/in.h>

int get_hw_addr(struct in_addr *gw_ip, unsigned char *hw_mac);
int get_default_gw(struct in_addr *gw, char *iface);
int get_iface_ip(char *iface, struct in_addr *ip);
int get_iface_hw_addr(char *iface, unsigned char *hw_mac);
char* get_default_iface(void);

#endif

/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef _RECV_H
#define _RECV_H

int recv_update_pcap_stats(void);
int recv_run(pthread_mutex_t *recv_ready_mutex);

#endif //_RECV_H

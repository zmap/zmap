/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <pthread.h>
#include "iterator.h"

#ifndef MONITOR_H
#define MONITOR_H

void monitor_run(iterator_t *it, pthread_mutex_t *lock);
void monitor_init(void);

#endif

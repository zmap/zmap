/*
 * Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ZMAP_PBM_H
#define ZMAP_PBM_H

#include <stdint.h>

uint8_t **pbm_init(void);
int pbm_check(uint8_t **b, uint32_t v);
void pbm_set(uint8_t **b, uint32_t v);
uint32_t pbm_load_from_file(uint8_t **b, char *file);

#endif /* ZMAP_PBM_H */

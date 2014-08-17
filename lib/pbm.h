#ifndef ZMAP_PBM_H
#define ZMAP_PBM_H

#include <stdint.h>

uint8_t** pbm_init(void);
int pbm_check(uint8_t **b, uint32_t v);
void pbm_set(uint8_t **b, uint32_t v);

#endif /* ZMAP_PBM_H */

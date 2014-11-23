#ifndef ZMAP_RECV_INTERNAL_H
#define ZMAP_RECV_INTERNAL_H

#include <stdint.h>

void handle_packet(uint32_t buflen, const uint8_t *bytes);
void recv_init();
void recv_packets();
void recv_cleanup();

#endif /* ZMAP_RECV_INTERNAL_H */

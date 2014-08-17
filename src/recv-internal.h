#ifndef ZMAP_RECV_INTERNAL_H
#define ZMAP_RECV_INTERNAL_H

void handle_packet(uint32_t buflen, const u_char *bytes);
void recv_init();
void recv_packets();
void recv_cleanup();

#endif

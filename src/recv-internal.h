#ifndef ZMAP_RECV_INTERNAL_H
#define ZMAP_RECV_INTERNAL_H


static u_char fake_eth_hdr[65535];

// bitmap of observed IP addresses
static uint8_t **seen = NULL;

void handle_packet(uint32_t buflen, const u_char *bytes);
void recv_init();
void recv_packets();
void recv_cleanup();

#endif

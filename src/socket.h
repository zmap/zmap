#ifndef ZMAP_SOCKET_H
#define ZMAP_SOCKET_H

#ifdef PFRING

#include <pfring_zc.h>

typedef union {
	int sock;
	struct {
		pfring_zc_queue *queue;
		pfring_zc_pkt_buff **buffers;
		int idx;
	} pf;
} sock_t;

#else

typedef struct {
	int sock;
} sock_t;

#endif /* PFRING */

sock_t get_dryrun_socket(void);
sock_t get_socket(void);


#endif /* ZMAP_SOCKET_H */

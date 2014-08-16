#include "socket.h"

#include "../lib/includes.h"
#include "state.h"

#include <pfring_zc.h>

sock_t get_socket(uint32_t id)
{
	sock_t sock;
	sock.pf.queue = zconf.pf_queues[id];
	sock.pf.buffers = zconf.pf_buffers + 256*id;
	return sock;
}

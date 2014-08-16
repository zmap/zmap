#include "socket.h"

#include "../lib/includes.h"
#include "../lib/logger.h"

sock_t get_socket(void)
{
	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock <= 0) {
		log_fatal("send", "couldn't create socket. "
			"Are you root? Error: %s\n", strerror(errno));
	}
	sock_t s;
	s.sock = sock;
	return s;
}

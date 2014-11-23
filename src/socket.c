#include "socket.h"

#include <string.h>
#include <errno.h>

#include "../lib/includes.h"
#include "../lib/logger.h"

sock_t get_dryrun_socket(void)
{
	// we need a socket in order to gather details about the system
	// such as source MAC address and IP address. However, because
	// we don't want to require root access in order to run dryrun,
	// we just create a TCP socket.
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock <= 0) {
		log_fatal("send", "couldn't create socket. Error: %s\n",
			strerror(errno));
	}
	sock_t s;
	s.sock = sock;
	return s;
}

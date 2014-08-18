#ifndef ZMAP_SEND_BSD_H
#define ZMAP_SEND_BSD_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "../lib/includes.h"

#include <netinet/in.h>
#include <net/bpf.h>


#ifdef ZMAP_SEND_LINUX_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

int send_run_init(UNUSED sock_t sock)
{
	// Don't need to do anything on BSD-like variants
	return EXIT_SUCCESS;
}

int send_packet(int fd, void *buf, int len, UNUSED uint32_t idx)
{
	return write(fd, buf, len);
}

#endif /* ZMAP_SEND_BSD_H */

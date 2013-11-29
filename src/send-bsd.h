#ifndef ZMAP_SEND_BSD_H
#define ZMAP_SEND_BSD_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "../lib/includes.h"

#include <net/bpf.h>

#ifdef ZMAP_SEND_LINUX_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

#define UNUSED __attribute__((unused))

int get_socket(void)
{
	char file[32];
	int bpf;

	// Try to find a valid bpf
	for (int i = 0; i < 128; i++) {
		snprintf(file, sizeof(file), "/dev/bpf%d", i);
		bpf = open(file, O_WRONLY);
		if (bpf != -1 || errno != EBUSY)
			break;
	}
	
	// Make sure it worked
	if (bpf < 0)
		return -1;

	// Set up an ifreq to bind to
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, zconf.iface, sizeof(ifr.ifr_name));

	// Bind the bpf to the interface
	if (ioctl(bpf, BIOCSETIF, (char *) &ifr) < 0)
		return -1;

	// Enable writing the address in
	int write_addr_enable = 1;
	if (ioctl(bpf, BIOCSHDRCMPLT, &write_addr_enable) < 0)
		return -1;
	return bpf;
}

int send_run_init(UNUSED int sock)
{
	// Don't need to do anything on BSD-like variants
	return EXIT_SUCCESS;
}

int send_packet(int fd, void *buf, int len)
{
	return write(fd, buf, len);
}



#endif /* ZMAP_SEND_BSD_H */

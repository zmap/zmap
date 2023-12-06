//
// Created by Phillip Stephens on 12/4/23.
//

#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

#include <netpacket/packet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../lib/includes.h"
#include "./send.h"
#include "./send-linux.h"

#include <netpacket/packet.h>

int send_batch(sock_t sock, batch_t* batch) {
	printf("Entered send batch\n");
	struct mmsghdr msgvec [BATCH_SIZE]; // Array of multiple msg header structures
	printf("created msgvec\n");

	for (int i = 0; i < batch->len; ++i) {
		printf("loop iteration %d\n", i);
		struct iovec iov = {((void *)batch->packets) + (batch->lens[batch->len] * MAX_PACKET_SIZE), batch->lens[i]};
		struct msghdr message;
		memset(&message, 0, sizeof(struct msghdr));
		message.msg_name = &sockaddr;
		message.msg_namelen = sizeof(struct sockaddr_ll);
		message.msg_iov = &iov;
		message.msg_iovlen = 1;

		msgvec[i].msg_hdr = message;
		msgvec[i].msg_len = batch->lens[i];
	}

	// Use sendmmsg to send the batch of packets
	printf("about to sendmmsg\n");
	int rv = sendmmsg(sock.sock, msgvec, batch->len, 0);
	if (rv < 0) {
		perror("Error in sendmmsg");
	}
	printf("send mmsg returned %d\n", rv);
	return rv;
}




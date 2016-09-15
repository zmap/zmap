#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wflexible-array-extensions"
#include <dnet.h>
#pragma GCC diagnostic warning "-Wflexible-array-extensions"
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD 2
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <ifaddrs.h> // NOTE: net/if.h MUST be included BEFORE ifaddrs.h
#include <net/if.h>
#include <netdb.h>

#define MAC_ADDR_LEN ETHER_ADDR_LEN
#define UNUSED __attribute__((unused))

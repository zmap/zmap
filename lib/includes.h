#ifdef __linux__
#include <dumbnet.h>
#else
#include <dnet.h>
#endif


#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>        // NOTE: net/if.h MUST be included BEFORE ifaddrs.h
#include <arpa/inet.h>

ZMap: The Internet Scanner
==========================

![Build Status](https://github.com/zmap/zmap/actions/workflows/cmake.yml/badge.svg)

ZMap is a fast single packet network scanner designed for Internet-wide network
surveys. On a typical desktop computer with a gigabit Ethernet connection, ZMap
is capable scanning the entire public IPv4 address space in under 45 minutes. With
a 10gigE connection and [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/),
ZMap can scan the IPv4 address space in under 5 minutes.

ZMap operates on GNU/Linux, Mac OS, and BSD. ZMap currently has fully implemented
probe modules for TCP SYN scans, ICMP, DNS queries, UPnP, BACNET, and can send a
large number of [UDP probes](https://github.com/zmap/zmap/blob/master/examples/udp-probes/README).
If you are looking to do more involved scans, e.g.,
banner grab or TLS handshake, take a look at [ZGrab 2](https://github.com/zmap/zgrab2),
ZMap's sister project that performs stateful application-layer handshakes.

Installation
------------

The latest stable release of ZMap is version 2.1.1 and supports Linux, macOS, and
BSD. However, the release was tagged in 2015, and since then quite a bit has changed. Accordingly,
_we strongly encourage researchers to use [ZMap 3.0.0 Beta 1](https://github.com/zmap/zmap/releases/tag/v3.0.0-beta1)._

**Instructions on building ZMap from source** can be found in [INSTALL](INSTALL.md).

Usage
-----

A guide to using ZMap is found in our [GitHub Wiki](https://github.com/zmap/zmap/wiki).

License and Copyright
---------------------

ZMap Copyright 2017 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.




Command Usage.
--------------

Basic arguments:
  -p, --target-port=port    of    port number to scan (for TCP and UDP scans)
  -o, --output-file=name        Output file
  -b, --blacklist-file=path     File of subnets to exclude, in CIDR notation,
                                  e.g. 192.168.0.0/16
  -w, --whitelist-file=path     File of subnets to constrain scan to, in CIDR
                                  notation, e.g. 192.168.0.0/16

Scan options:
  -r, --rate=pps                Set send rate in packets/sec
  -B, --bandwidth=bps           Set send rate in bits/second (supports suffixes
                                  G, M and K)
  -n, --max-targets=n           Cap number of targets to probe (as a number or
                                  a percentage of the address space)
  -t, --max-runtime=ses         Cap length of time for sending packets
  -N, --max-results=n           Cap number of results to return
  -P, --probes=n                Number of probes to send to each IP
                                  (default=`1')
  -c, --cooldown-time=secs      How long to continue receiving after sending
                                  last probe  (default=`8')
  -e, --seed=n                  Seed used to select address permutation
      --retries=n               Max number of times to try to send packet if
                                  send fails  (default=`10')
  -d, --dryrun                  Don't actually send packets
      --shards=N                Set the total number of shards  (default=`1')
      --shard=n                 Set which shard this scan is (0 indexed)
                                  (default=`0')

Network options:
  -s, --source-port=port|range  Source port(s) for scan packets
  -S, --source-ip=ip|range      Source address(es) for scan packets
  -G, --gateway-mac=addr        Specify gateway MAC address
      --source-mac=addr         Source MAC address
  -i, --interface=name          Specify network interface to use                                                                               -X, --vpn                     Sends IP packets instead of Ethernet (for VPNs)                                                              
Probe Modules:
  -M, --probe-module=name       Select probe module  (default=`tcp_synscan')
      --probe-args=args         Arguments to pass to probe module
      --list-probe-modules      List available probe modules

Data Output:
  -f, --output-fields=fields    Fields that should be output in result set
  -O, --output-module=name      Select output module  (default=`default')
      --output-args=args        Arguments to pass to output module
      --output-filter=filter    Specify a filter over the response fields to
                                  limit what responses get sent to the output
                                  module                                                                                                           --list-output-modules     List available output modules
      --list-output-fields      List all fields that can be output by selected
                                  probe module

Logging and Metadata:
  -v, --verbosity=n             Level of log detail (0-5)  (default=`3')
  -l, --log-file=name           Write log entries to file
  -L, --log-directory=directory Write log entries to a timestamped file in this
                                  directory
  -m, --metadata-file=name      Output file for scan metadata (JSON)
  -u, --status-updates-file=name
                                Write scan progress updates to CSV file
  -q, --quiet                   Do not print status updates
      --disable-syslog          Disables logging messages to syslog
      --notes=notes             Inject user-specified notes into scan metadata
      --user-metadata=json      Inject user-specified JSON metadata into scan
                                  metadata

Additional options:
  -C, --config=filename         Read a configuration file, which can specify
                                  any of these options
                                  (default=`/etc/zmap/zmap.conf')
      --max-sendto-failures=n   Maximum NIC sendto failures before scan is
                                  aborted  (default=`-1')
      --min-hitrate=n           Minimum hitrate that scan can hit before scan
                                  is aborted  (default=`0.0')
  -T, --sender-threads=n        Threads used to send packets  (default=`1')
      --cores=STRING            Comma-separated list of cores to pin to
      --ignore-invalid-hosts    Ignore invalid hosts in whitelist/blacklist
                                  file
  -h, --help                    Print help and exit
  -V, --version                 Print version and exit

Examples:
    zmap -p 80 (scan the Internet for hosts on tcp/80 and output to stdout)
    zmap -N 5 -B 10M -p 80 (find 5 HTTP servers, scanning at 10 Mb/s)
    zmap -p 80 10.0.0.0/8 192.168.0.0/16 -o (scan both subnets on tcp/80)
    zmap -p 80 1.2.3.4 10.0.0.3 (scan 1.2.3.4, 10.0.0.3 on tcp/80)

Probe-module (tcp_synscan) Help:
Probe module that sends a TCP SYN packet to a specific port. Possible
classifications are: synack and rst. A SYN-ACK packet is considered a success
and a reset packet is considered a failed response.

Output-module (csv) Help:
 (e.g., SYN-ACK from
a TCP SYN scan) in ASCII form (e.g., 192.168.1.5) to stdout or the specified
output file. Internally this is handled by the "csv" output module and is
equivalent to running zmap --output-module=csv --output-fields=saddr
--output-filter="success = 1 && repeat = 0".

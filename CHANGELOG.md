# 1.0.0 2013-8-16
* Initial public release.

# 1.0.1 2013-8-17
## BUGFIX
* Issue #4 "Missing module_ssldb? Redis module won't compile." - removed dependencies on ssldb.

## SUPPORT
* Issue #3 "Error after running make" - added documentation that ZMap requires 64-bit system.
* Issue #1 "Failure at calloc for 'ip_seen' on KVM VPSs?" - added documentation on memory requirements for ZMap.

# 1.0.2 2013-8-18
## BUGFIX
* Issue #14 "gcc 4.7.2 -Wunprototyped-calls error with recv_run." - changed recv_run header to match def in recv.c.

# 1.0.3 2013-8-19
## BUGFIX
* Issues #21, #28 "fixed get_gateway malloc/memset errors".
* Issue #24 "Makefile does not respect LDFLAGS" - changed = to += for CFLAGS, LDFAGS, and LDLIBS.

# 1.1.0 2013-11-18
## BUGFIX
* Source port in UDP module corrected to use network order instead of host order.

## FEATURE
* Updated probe and output module interface that allows arbitrary data to be passed from the probe module (e.g. additional TCP fields) that can then be output as requested.
* Replaced simple_file, and redis_file output modules with csv module that allows user controlled output of what fields should be output to a csv file. As well, implemented `--list-output-fields` that allows users to find what fields are available.
* Added output-filters that allow users to control what types of packets that want output (e.g. classification = "SYNACK" && is_repeat = 0).
* Drop root privileges after opening necessary sockets if run as privileged user.
* Added paged bitmap for removing duplicate responses so that if small subnets are scanned, large amount of memory is no longer required.
* Fast scanning of small subnets. Scanning small subnets no longer requires iterating over the entire IPv4 address space, which allows ZMap-like speed for all network sizes.
* Scan CIDR blocks from the command-line instead of only through whitelist file (e.g. ZMap -p 443 192.168.0.0/16 10.0.0.0/8).
* Redis output module now allows connecting to arbitrary redis servers and lists from the command-line via output module parameter.
* JSON output module added.
* 32-bit support.
* UDP Packet Support.

# 1.1.1 2013-12-16
## BUGFIX
* Fixed bit-map, which was incorrectly deduplicating responses.
* CMake correctly installs files into /etc/zmap.

# 1.1.2 2014-01-21
## BUGFIX
* Off-by-one error in paged bitmap.

# 1.2.0 2014-03-10
## BUGFIX
* ICMP values added incorrectly, timestamp unavailable.
* Setting fixed number of probes may inadverantly target specific networks.
* Scans occasionally skip cooldown period due to lock issue.

## FEATURE
* Added MongoDB as a supported output module.
* Added context to allow easier packaging in Debian and Ubuntu and Fedora and Brew and Macports.
* Remove dnet dependency for Linux.
* Remove random extra printed saddr.
* Build with optimizations by default.
* Added JSON metadata output.
* Added syslog support.
* Added BSD/mac support.
* Removed bizarre executible bits on random example code in git repo.
* Added support for scanning by FQDN.
* Adding sharding support.

# 1.2.1 2014-06-09
## BUGFIX
* UDP scans sometimes double-counted IP header length.
* Properly check UDP packet length.
* Integer overflow in JSON metadata when printing generator.
* All calls to malloc checked for failure.

## FEATURE
* Autodetect number of sender threads.
* Add ignore-invalid-hosts option for blocklist.

# 2.1.0	2015-09-02
## BUGFIX
* ZMap now filters out packets that are from the local MAC instead of only capturing packets from the local gateway. The prior approach caused valid responses to be dropped for a fair number of users.
* ZMap would sometimes segfault if the number of threads was greater than the number of destination hosts.
* ZMap did not crash when it was unable to write to the output file. This would cause ZMap to continue running when it was piped into another application and that application died. We not log_fatal if the output is no longer accessible per ferror.
* Pcap filter captures outgoing packets.
* Install overwrites blocklist file.
* Output is sometimes colored.
* Use correct email for Zakir in AUTHORS.
* Random-number generator is now thread safe.
* Finding a generator would crash with low probability.

## CHANGED
* JSON output uses underscores instead of hyphens.
* Removes support for deprecated simple_file and extended_file options.
* Rename redis module to redis-packed.
* Probe module API takes user data argument.
* Output to `stdout` by default.
* Remove space in csv output header.
* Build with JSON support by default.
* Don't print blocklisted CIDR blocks to log. These are available in `--metadata-file` and end up flooding the log with a ton of metadata.
* Remove type field from JSON output module and get rid of header.
* Remove `--summary`. This has been replaced by `--metadata-file`.
* JSON metadata now uses ISO-8601 compatible timestamps instead of proprietary log format.
* Remove buggy and never officially-released DNS probe module.
* Add icmp-echo-time probe module for measuring RTT MongoDB output module.

## FEATURE
* zblocklist (a standalone utility that allows you to efficiently check IP addresses against a ZMap compatible whitelist and blocklist. This is helpful if you are doing something like ```cat list-of-ips | zgrab``` and to make sure that you're still following your blocklist.
* ztee (a standalone utility that buffers between ZMap and ZGrab) and allows extracting just IP address from a larger ZMap output in order to complete follow up handshakes without losing any data.
* NTP probe module.
* Status-updates-file (monitor output as a csv).
* Add redis-csv output module.
* Colored log output.
* Add pf_ring and 10GigE support.
* Optional app-success field output in monitor.

# 2.1.1	2015-09-11
## BUGFIX
* make install works on more systems

## CHANGED
* CMakeLists.txt is now much more sane and packager-friendly
* Switch CHANGELOG and INSTALL to Markdown
* Generate `*.ggo` files from `*.ggo.in` files that define ZMap version as a macro

# 3.0.0 2023-06-23
We're happy to provide ZMap 3.0.0, only slightly under six years late. We recommend using this release over any previous 2.x release.

ZMap 3.0.0 represents several years of development and contains more than a hundred small bug fixes from ZMap 2.1.1., including many fixes for UDP modules, sharding, and progress calculation. Below, are some of the most important changes:

## BUGFIX

* Fix send rate calculations
* Accept RST packets for SEQ+0 (per RFC)
* Packets per second is packets per second now instead of IPs per second
* MaxResults is now the number of packets that pass the output filter (#502)
* Try all routing tables in Linux
* Fix crash on invalid UDP packets
* Fix failed initialize on single-question DNS probes
* Fix inaccurate blocklist warning
* Use monotonic OS clocks for monitoring and rate estimation
* Fix bugs in UDP template arguments
* Increase UDP PCAP snaplen to prevent packet truncation
* Exit on failed sends
* Fix incorrect time remaining calculations on sharded scans

## FEATURE

* Added --list-of-ips feature which allows scanning a large number (e.g., hundreds of millions or billons) of individual IPS
* Improved user messages when network settings can't be automatically discovered
* Consistent ICMP support and handling across all probe modules (#470)
* Set TCP MSS flags to avoid filtering by destination hosts (#673)
* Sane default behavior that can be explained with other CLI flags
* Non-Flat Result output and JSON result encoding
* IP Fragment Checking
* DNS, TCP SYN-ACK, and Bacnet Probe Module
* Change Whitelist/Blacklist terms to Allowlist/Blocklist
* Add extended validation bytes for probe modules that can use greater entropy
* Support non-continuous source IP's (#516)
* Add NetBSD and DragonFly BSD compatibility code (#411)
* Improved ICMP validation based on returned packet (#419)

## REMOVED

* Drop Redis and MongoDB support (#661)


# 4.0.0 2023-11-06
ZMap 4.0.0 introduces the notion of multi-port scanning, which has been a long requested feature. This is a breaking change since ZMap now operates on a metric of (ip,port) target instead of simply IP (e.g., for scan rate). It also introduces new dependencies (e.g., libjudy) to support multi-port scanning and changes ZMap's command-line interface. Below are some of the most important changes:

## BUGFIX

* Fix segmentation fault when passing no port to the ICMP module (or any module without a port requirement)

## FEATURE

* Multi-port scanning support
* Store link-layer timestamp in icmp_echo_time module (#726)
* Build support for ARM-based Macs
* Use the network interface containing the default route for usability
* Improve the dst port validation


# 4.1.0 2024-03-21
ZMap 4.1.0 contains a number of bug fixes and performance enhancements, especially around the sending of probe packets. Additionally, the `IP_ID` is now randomized to prevent the fingerprinting of ZMap scan traffic. Below are some of the most important changes:

## BUGFIX

* Fixes a bug where an assertion error would always occur when the `-I` flag was used
* Fixes `--probe-args` parsing with the DNS module
* Prevents crash when `--batch` size overflowed the uint8 holding the batch_size
* Fixes size calculation with `--iplayer` option that caused an overflow in `fake_eth_hdr`
* Fixes shard initialization with multi-port that could cause the scan to scan port 0 
* Fixes inaccurate estimated time remaining and percentage complete calculations during a multi-port scan
* Fixes building from source on MidnightBSD
* Fixes hit-rate calculation with multiple `--probes` packets per target


## FEATURE

* Randomizes the IP packet ID to prevent fingerprinting of scan traffic
* Adds support for Netmap to increase performance on supported NIC's w/ the requisite drivers
* Adds send packet batching (using `sendmmsg`) to improve performance on Linux/BSD
* Adds hardware acceleration for AES to improve performance when the CPU begins to become the bottleneck
* Adds integration tests and compilation checks for supported OS's as Github Actions
* Adds --probe-args options to the TCP SYN scan module to send TCP header options identical to Ubuntu (default), MacOS, Windows, or No Options.
* Sets default number of sending threads to min(4, number of host cores)
* Handles IPv6 addresses in `blocklist.conf`
* Supports `--iplayer` on MacOS


# 4.1.1 2024-05-21

## DOCUMENTATION
* updated CHANGELOG.md and README.md to contain the changes from v4.1.0 and point to the latest version.

## ENHANCEMENT

* Use same IP TTL as ubuntu (#850)
* Add TCP options parsing in receive thread (#858)

## BUGFIX

* Fixed a bug which caused inaccurate ETA every 44 secs.
* Fixed a bug where a malformed TCP options returned to the scanner would cause the receive thread to hang.


# 4.2.0 2024-07-09

## BUGFIX

* Fixed a bug where ZMap's behavior with a --max-targets of a percentage with multiple ports was inconsistent with our documentation/expectations. (#886)

## ENHANCEMENT

* Bump the base Docker image from Ubuntu 20.04 to 24.04 (#888)


# 4.3.0 2024-11-27

## FEATURE
* New UDP probe for DTLS servers by @dlenskiSB in https://github.com/zmap/zmap/pull/890
* New UDP probes by @annalittle in https://github.com/zmap/zmap/pull/899
* Add source port validation CLI option and associated code to UDP module by @phillip-stephens in https://github.com/zmap/zmap/pull/901

## BUGFIX

* Fix 904 - multi-port scans lead to int overflow by @phillip-stephens in https://github.com/zmap/zmap/pull/905
* Fix ZMap not obeying `--rate` edge case by @phillip-stephens in https://github.com/zmap/zmap/pull/907
* Match JSON function to variable type by @phillip-stephens in https://github.com/zmap/zmap/pull/908
* Fix source port range size warning by @Murgeye in https://github.com/zmap/zmap/pull/891

## ENHANCEMENT
* Handle upgrade path for blacklist to blocklist by @phillip-stephens in https://github.com/zmap/zmap/pull/895
* Fixes ubuntu docker base image versions in github tests by @phillip-stephens in https://github.com/zmap/zmap/pull/898
* Fix Mac build CI step by @phillip-stephens in https://github.com/zmap/zmap/pull/906


# 4.3.1 2024-12-10

## BUGFIX

* Missed an uint32 which caused multi-port scans to end early by @phillip-stephens in https://github.com/zmap/zmap/pull/914
* Fix for #913 (where a handful of targets were scanned twice) and added IPv4 scan coverage integration test and python wrapper with --fast-dryrun by @phillip-stephens in https://github.com/zmap/zmap/pull/916

# 4.3.2 2025-01-28

## BUGFIX

* use the x86 ubuntu dockerfile base image, should fix failing daily test by @phillip-stephens in #920
* Fix typos by @BitHostDev in #923
* Fix leaks by @rex4539 in #921
* Fix NETLINK issues in ZMap caused by changes in latest linux kernel by @phillip-stephens in #925

# 4.3.3 2025-04-29

Misc bug fixes and improvements

## ENHANCEMENT

* Add QUIC init probe in #930

## BUGFIX

* Fix size of recv validation from uint32[16] to uint32[4] in #926

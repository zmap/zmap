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
* Add ignore-invalid-hosts option for blacklist.

# 2.1.0	2015-09-02
## BUGFIX
* ZMap now filters out packets that are from the local MAC instead of only capturing packets from the local gateway. The prior approach caused valid responses to be dropped for a fair number of users.
* ZMap would sometimes segfault if the number of threads was greater than the number of destination hosts.
* ZMap did not crash when it was unable to write to the output file. This would cause ZMap to continue running when it was piped into another application and that application died. We not log_fatal if the output is no longer accessible per ferror.
* Pcap filter captures outgoing packets.
* Install overwrites blacklist file.
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
* Don't print blacklisted CIDR blocks to log. These are available in `--metadata-file` and end up flooding the log with a ton of metadata.
* Remove type field from JSON output module and get rid of header.
* Remove `--summary`. This has been replaced by `--metadata-file`.
* JSON metadata now uses ISO-8601 compatible timestamps instead of proprietary log format.
* Remove buggy and never officially-released DNS probe module.
* Add icmp-echo-time probe module for measuring RTT MongoDB output module.

## FEATURE
* zblacklist (a standalone utility that allows you to efficiently check IP addresses against a ZMap compatible whitelist and blacklist. This is helpful if you are doing something like ```cat list-of-ips | zgrab``` and to make sure that you're still following your blacklist.
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

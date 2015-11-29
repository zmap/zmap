ZMap: The Internet Scanner
==========================

[![Build Status](https://travis-ci.org/zmap/zmap.svg?branch=travis-configuration)](https://travis-ci.org/zmap/zmap)

ZMap is a fast single packet network scanner designed for Internet-wide network
surveys. On a typical desktop computer with a gigabit Ethernet connection, ZMap
is capable scanning the entire public IPv4 address space in under 45 minutes.
With a 10gigE connection and PF_RING, ZMap can scan the IPv4 address space in
under 5 minutes.

While previous network tools have been designed to scan small network segments,
ZMap is specifically architected to scan the entire address space. It is built
in a modular manner in order to allow incorporation with other network survey
tools. 

ZMap operates on GNU/Linux, Mac OS, and BSD. ZMap currently has fully
implemented probe modules for TCP SYN scans, ICMP, DNS queries, UPnP, BACNET, 
and can send a large number of UDP probes. If you are looking to do more
involved scans, e.g., banner grab or TLS handshake, take a look at ZGrab
(https://github.com/zmap/zgrab), ZMap's sister project that does application
layer handshakes.

Documentation and examples can be found at https://zmap.io/.

License and Copyright
---------------------

ZMap Copyright 2013 Regents of the University of Michigan 

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.


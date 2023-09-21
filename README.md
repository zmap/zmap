ZMap: The Internet Scanner
==========================

![Build Status](https://github.com/zmap/zmap/actions/workflows/cmake.yml/badge.svg)

ZMap is a fast single packet network scanner designed for Internet-wide network
surveys. On a typical desktop computer with a gigabit Ethernet connection, ZMap
is capable scanning the entire public IPv4 address space on a single port in 
under 45 minutes. With a 10gigE connection and [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/),
ZMap can scan the IPv4 address space in under 5 minutes.

ZMap operates on GNU/Linux, Mac OS, and BSD. ZMap currently has fully implemented
probe modules for TCP SYN scans, ICMP, DNS queries, UPnP, BACNET, and can send a
large number of [UDP probes](https://github.com/zmap/zmap/blob/master/examples/udp-probes/README).
If you are looking to do more involved scans, e.g., banner grab or TLS handshake, 
take a look at [ZGrab 2](https://github.com/zmap/zgrab2), ZMap's sister project that performs stateful application-layer handshakes.

Installation
------------

The latest stable release of ZMap is version 3.0.0 and supports Linux, macOS, and
BSD.

**Instructions on building ZMap from source** can be found in [INSTALL](INSTALL.md).

Usage
-----

A guide to using ZMap is found in our [GitHub Wiki](https://github.com/zmap/zmap/wiki).

Architecture
------------

More information about ZMap's architecture and a comparison with other tools can be found in these two research papers:

 * [ZMap: Fast Internet-Wide Scanning and its Security Applications](https://zmap.io/paper.pdf)
 * [Zippier ZMap: Internet-Wide Scanning at 10 Gbps](https://jhalderm.com/pub/papers/zmap10gig-woot14.pdf)

If you use ZMap for published research, please cite the original research paper:

```
@inproceedings{durumeric2013zmap,
  title={{ZMap}: Fast Internet-wide scanning and its security applications},
  author={Durumeric, Zakir and Wustrow, Eric and Halderman, J Alex},
  booktitle={22nd USENIX Security Symposium},
  year={2013}
}
```

License and Copyright
---------------------

ZMap Copyright 2023 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.

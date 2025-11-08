ZMap: The Internet Scanner
==========================

![Build Status](https://github.com/zmap/zmap/actions/workflows/cmake.yml/badge.svg)

ZMap is a fast stateless single packet network scanner designed for Internet-wide network
surveys. On a typical desktop computer with a gigabit Ethernet connection, ZMap
is capable of scanning the entire public IPv4 address space on a single port in 
under 45 minutes. For example, sending a TCP SYN packet to every IPv4 address
on port 25 to find potential SMTP servers. With a 
10gigE connection and either [netmap](http://info.iet.unipi.it/~luigi/netmap/) or 
[PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/), ZMap can scan 
the IPv4 address space in under 5 minutes.

ZMap operates on GNU/Linux, Mac OS, and BSD. ZMap currently has fully implemented
probe modules for TCP SYN scans, ICMP, DNS queries, UPnP, BACNET, and can send a
large number of [UDP probes](https://github.com/zmap/zmap/blob/master/examples/udp-probes/README).
If you are looking to do more involved scans (e.g., banner grab or TLS handshake), 
take a look at [ZGrab 2](https://github.com/zmap/zgrab2), ZMap's sister project 
that performs stateful application-layer handshakes.

> [!CAUTION]
> Ethical Scanning
> 
> Performing Internet-wide scans can have serious ethical and operational implications. While ZMap defaults to usually safe
> settings, it is your responsibility to ensure that you're a good internet citizen. Rules of thumb are to scan at the
> slowest speed necessary, scan slower if you're scanning a smaller target space, and provide a way for network operators
> to opt-out. More information can be found [here](https://github.com/zmap/zmap/wiki/Getting-Started-Guide#%EF%B8%8F-warning-on-scanning-rate).


Using ZMap
----------

ZMap is easy to use. A simple scan of the entire IPv4 space on TCP port 80 can be performed with the following command (requires root privileges):

```sh
sudo zmap -p 80
```

```
$ sudo zmap -p 80
...
 0:00 0%; send: 5 1 p/s (185 p/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
52.8.107.196
...
 0:01 0%; send: 10327 10.3 Kp/s (10.1 Kp/s avg); recv: 118 118 p/s (115 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 1.14%
````

If you haven't used ZMap before, we have a step-by-step [Getting Started Guide](https://github.com/zmap/zmap/wiki/Getting-Started-Guide) that details how to perform basic scans. Documentation about all of ZMap's options and more advanced functionality can be found in our [Wiki](https://github.com/zmap/zmap/wiki). For best practices, see [Scanning Best Practices](https://github.com/zmap/zmap/wiki/Scanning-Best-Practices). 

If you have questions, please first check our [FAQ](https://github.com/zmap/zmap/wiki/FAQ). Still have questions? Ask the community in [Github Discussions](https://github.com/zmap/zmap/discussions/categories/q-a). Please do not create an Issue for usage or support questions.

Installation
------------

The latest stable release of ZMap is [4.3.4](https://github.com/zmap/zmap/releases/tag/v4.3.4) and supports Linux, macOS, and
BSD. See [INSTALL](INSTALL.md) for instructions on to install ZMap through a package manager or from source.

Architecture
------------

More information about ZMap's architecture and a comparison with other tools can be found in these research papers:

 * [ZMap: Fast Internet-Wide Scanning and its Security Applications](https://zmap.io/paper.pdf)
 * [Zippier ZMap: Internet-Wide Scanning at 10 Gbps](https://jhalderm.com/pub/papers/zmap10gig-woot14.pdf)
 * [Ten Years of ZMap](https://arxiv.org/pdf/2406.15585)

Citing ZMap
-----------

If you use ZMap for published research, please cite the original research paper:

```
@inproceedings{durumeric2013zmap,
  title={{ZMap}: Fast Internet-wide scanning and its security applications},
  author={Durumeric, Zakir and Wustrow, Eric and Halderman, J Alex},
  booktitle={22nd USENIX Security Symposium},
  year={2013}
}
```

Citing the ZMap paper helps us to track ZMap usage within the research community and to pursue funding for continued development.


License and Copyright
---------------------

ZMap Copyright 2024 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.

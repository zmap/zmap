# JA4TScan Usage

This fork simply implements a new probe module for Zmap that generates JA4T fingerprints. This achieved through a single file: `src/probe_modules/module_ja4ts.c`.

This is a modifed version of Zmap's default TCP scanner `src/probe_modules/module_tcp_synscan.c`. The main difference is that a new field `ja4ts` is added to the field set. The field is created by capturing the server's synack response parameters specified by the [JA4Ts specification](https://docs.google.com/document/d/1Q6-kk2BcWe5qa2FSwsR5cvbaf5jhaj4LDeFLwBlM6Bc/).

For building from source, follow Zmap's instructions in the installation section below.

## Usage

This tool can be used the same way as Zmap with a few caveats.

Example:
`sudo zmap -N 1000 -B 10M -p 443 -o output.csv --output-fields=saddr,ja4ts,timestamp,dport --probe-module=ja4ts --dedup-method none`

The `--probe-module` flag specifies the probe module to use. In this case, `ja4ts` is used. The `--output-fields` flag specifies the fields to include in the output. The `ja4ts` field is included in the output. Its very important to include the `timestamp` field in the output as it is used to calculate the JA4TScan fingerprint via post processing by measuring the time between first synack and following retransmissions.

Additionally, the `--dedup-method` flag is set to `none` to ensure that retransmission packets are captured.

Without the `dedup-method` flag and the `timestamp` field, you won't be able to calculate the JA4TScan fingerprint when post processing.

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
If you are looking to do more involved scans (e.g., banner grab or TLS handshake), 
take a look at [ZGrab 2](https://github.com/zmap/zgrab2), ZMap's sister project that performs stateful application-layer handshakes.


Using ZMap
----------

If you haven't used ZMap before, we have a step-by-step [Getting Started Guide](https://github.com/zmap/zmap/wiki/Getting-Started-Guide) that details how to perform basic scans. Documentation about all of ZMap's options and more advanced functionality can be found in our [GitHub Wiki](https://github.com/zmap/zmap/wiki). 

If you have questions, please first check our [FAQ](https://github.com/zmap/zmap/wiki/FAQ). Still have questions? Ask the community in [Github Discussions](https://github.com/zmap/zmap/discussions/categories/q-a). Please do not create an Issue for usage or support questions.

Installation
------------

The latest stable release of ZMap is version [3.0.0](https://github.com/zmap/zmap/releases/tag/v3.0.0) and supports Linux, macOS, and
BSD. ZMap [4.0.0-RC1](https://github.com/zmap/zmap/releases/tag/v4.0.0-RC1) adds support for scanning multiple ports.

**Instructions on building ZMap from source** can be found in [INSTALL](INSTALL.md).


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

Citing the ZMap paper helps us to track ZMap usage within the research community and to pursue funding for continued development.


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

10GigE (Zippier) ZMap
===========

It is possible to build ZMap to run at 95% of 10 GigE linespeed, sending over 14
million packets per second. This requires a compatible Intel 10 Gbps Ethernet
NIC and Linux.

### Prerequisites

  1. A [PF_RING ZC](http://www.ntop.org/products/pf_ring/pf_ring-zc-zero-copy/)
     license from ntop.
  2. PF_RING ZC headers and kernel module
  3. A 10 Gbps NIC with compatible "PF_RING-aware" drivers
  4. A Linux (not BSD or Mac) installation
  5. For best results, a computer with at least 8 *physical* cores on the same
     NUMA node.

### Building

Most build errors are due to incorrectly building or installing PF_RING. Make
sure you have build the drivers, the kernel module, and the userland library, as
well as install the headers and kernel module to the correct locations.

The PF_RING `make install` command might not copy `pfring_zc.h` to
`/usr/include`, in which case manually install the file and set permissions
correctly.

To build navigate to the root of the repository and run:

```
$ cmake -DWITH_PFRING=ON -DENABLE_DEVELOPMENT=OFF .
$ make
```

### Running

You'll have to carefully select the number of threads to use, as well as specify
as zero-copy interface, e.g. `zc:eth1`. Use the `--cores` option to pick which
cores to pin to. Make sure to pin to different physical cores, and note that
some machines interleave physical and "virtual" cores. 
```
$ sudo ./src/zmap -p 80 -i zc:eth7 -o output.csv -T 5
```

### Considerations

DO NOT TAKE THIS LIGHTLY!

Running ZMap at 10Gbps hits every /16 on the Internet over 200 times a second.
Even if you have a large source IP range to scan from, it's very obvious that
you're scanning. As always, follow scanning best practices, honor blacklist
requests, and signal benign/research intent via domain names and websites on
your scan IPs.

Remember, you're sending a lot of traffic. This is what happened at the
University of Michigan during a 10 Gbps scan.

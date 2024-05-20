Fast packet I/O using netmap
============================

ZMap can be built for sending and receiving packets using netmap(4), for very
high packet rates, especially on 10 GbE and faster links.
See [netmap/README.md](https://github.com/luigirizzo/netmap) for more
information on netmap.

Netmap is available by default on FreeBSD on many architectures, including
amd64 and arm64, and is easy to add to the kernel config on architectures where
it is not built by default.  On Linux, netmap itself and netmap-aware drivers
can be installed by following the instructions in
[netmap/LINUX/README.md](https://github.com/luigirizzo/netmap/blob/master/LINUX/README.md).


### Prerequisites

  0. A working ZMap development environment (see [INSTALL.md](INSTALL.md)).
  1. A kernel with netmap support (check for existence of `/dev/netmap`).
  2. For best results, a NIC with a driver that is netmap-aware, such as
     FreeBSD's `ixgbe` or `ixl`.


### Building

To build navigate to the root of the repository and run:

```
$ cmake -DWITH_NETMAP=ON -DENABLE_DEVELOPMENT=OFF .
$ make
```

For best results on hardware that supports AES acceleration, additionally use
`-DWITH_AES_HW=ON` to enable support for AES-NI and ARMv8 CE, where applicable.


### Running

Run zmap as you would normally.

```
$ sudo ./src/zmap -p 443 -i ix0 -o output.csv
```

Warning:  Netmap will disconnect the NIC from the host network stack for the
duration of the scan.  If you use an interface that you depend on for e.g. SSH
access, you will lose connectivity until ZMap exits.


### Performance tuning

For best results, use the `--cores` option to pick which cores to pin to,
pinning to different physical cores.  By default, the number of send threads is
set to the number of available cores after setting aside one core for the
receive thread, capped to 4 send threads, but you may still want to override
the number of send threads with `-T`.  The number of send threads cannot exceed
the number of TX rings of the NIC.

Tuning batch size can also have an effect on send rate.  `--batch 256` is not
an unreasonable starting point on 10 GbE hardware.


### Switch ports and STP

Going into and leaving Netmap mode causes the link to go down and up as part of
a PHY reset.  If the interface is connected to a switch with STP enabled, then
depending on port configuration, the switch might be muting the port for as
many as 30 seconds while the port goes through the listening and learning STP
states.  To work around this, use `--netmap-wait-ping` with an address that you
know will respond to ICMP echo requests.  ZMap will then only start scanning
after having received an ICMP echo reply from the address.

```
$ sudo ./src/zmap -p 443 -i ix0 -o output.csv --netmap-wait-ping 8.8.8.8
```


### Considerations

DO NOT TAKE THIS LIGHTLY!

Running ZMap at 10Gbps hits every /16 on the Internet over 200 times a second.
Even if you have a large source IP range to scan from, it's very obvious that
you're scanning. As always, follow scanning best practices, honor blocklist
requests, and signal benign/research intent via domain names and websites on
your scan IPs.

Remember, you're sending a lot of traffic.

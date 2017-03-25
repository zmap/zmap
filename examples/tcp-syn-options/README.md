# Documentation for tcp_synopt module 

This module allows to send arbitrary (<41 bytes) TCP options given as hex argument.

Advice: 
- Pick different TSecr and TSval values to allow for middlebox detection
- Use 0c0c0c0c0c as MPTCP key (hard coded in reply processing code)
- If using unkown option, use 40(hex)/64 (dec) as it is also hard coded

## Examples

### SACK only 

--probe-args=hex:04020101

### MSS only

02040578 (1400 mss)

### TS only 

080affffffff01010101

### Complex

--probe-args=hex:0402080affffffff0101010103030101220240021e0c00810c0c0c0c0c0c0c0c000000000

0402: sack permitted
080a: timestamps, len 10
	ffffffff: TSval
	01010101: TSecr
030301: wscale 1
01: nop for padding
2202: fast open cookie request
4002: unknown option
1e: MPTCP
	0c: len 12
	00: capable, v0
	81: flags
	0c...0c: sender key
00000000: end of options list

## Test Method

1. no options
2. very basic option (mss)
3. TS option
4. complex option set (excluding MSS, including unkn. option)


## Test Servers

./src/zmap -p 80 www.google.de  -M tcp_options -f saddr,sport,optionshex,optionstext,success,tcpmss,tsval,tsecr,tsdiff,wscale,mptcpkey,mptcpdiff,tfocookie

hosts:
multipath-tcp.org (true mptcp capable,adds mss, drops invalid)
baidu.com (ugly middlebox, echos, replaces TS with NOPs, echoes TFO, echoes MPTCP)
google.de (TFO), adds MSS, drops invalid)



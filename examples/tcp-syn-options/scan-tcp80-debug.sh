#!/bin/bash

if [ -z $1 ] || [ $1 -lt 1 ] || [ $1 -gt 3 ]
then
	printf "Please Provide host to test\n\t1) multipath-tcp.org (true mptcp capable,adds mss, drops invalid)\n\t2) baidu.com (ugly middlebox, echos, replaces TS with NOPs, echoes TFO, echoes MPTCP)\n\t3) google.de (TFO), adds MSS, drops invalid)"
	exit 1
fi

host=none
case $1 in
1)  host=multipath-tcp.org ;;
2)  host=baidu.com ;;
3)  host=google.de ;;
*)	printf "Please Provide test host\n\t1) multipath-tcp.org (true mptcp capable,adds mss, drops invalid)\n\t2) baidu.com (ugly middlebox, echos, replaces TS with NOPs, echoes TFO, echoes MPTCP)\n\t3) google.de (TFO), adds MSS, drops invalid)"
	exit 1 ;;
esac

zmap=../../src/zmap
#result="result-$(date).csv

../../src/zmap -C zmap-TCPv4-options.conf -p 80 $host

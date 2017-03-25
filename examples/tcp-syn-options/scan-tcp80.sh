#!/bin/bash

zmap=../../src/zmap
ztee=../../src/ztee
zgrab=../../bin/zgrab
result="result-$(date)"
port=80

mkdir $result

$zmap -C zmap-TCPv4-options.conf --output-file $result \
	-l $result/log-scanopt-complex-v4-p${port}.txt \
	-m $rp/meta-scanopt-complex-v4-p${port}.json \ 
	-u $rp/updates-scanopt-complex-v4-p${port}.csv
	--output-filter="success = 1" -p $port $1 \
	| $ztee -l $result/log-scanopt-complex-ztee-v4-p${port}.txt \
	$result/scanopt-complex-v4-p${port}.csv

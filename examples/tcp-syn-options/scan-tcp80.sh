#!/bin/bash

zmap=../../src/zmap
ztee=../../src/ztee
zgrab=../../bin/zgrab
result="result-$(date +'%d-%m-%Y')"
port=80

mkdir $result
touch $result/updates-scanopt-complex-v4-p${port}.csv

$zmap -C zmap-TCPv4-options.conf --output-file $result/output-scanopt-complex-v4-p${port}.csv \
        -l $result/log-scanopt-complex-v4-p${port}.txt \
        -m $result/meta-scanopt-complex-v4-p${port}.json \
        -u $result/updates-scanopt-complex-v4-p${port}.csv \
        --output-filter="success = 1" -p $port $1 \
        | $ztee -l $result/log-scanopt-complex-ztee-v4-p${port}.txt \
        $result/scanopt-complex-v4-p${port}.csv
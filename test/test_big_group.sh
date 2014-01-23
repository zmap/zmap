#!/bin/bash

../src/zmap -p 80 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 4 --shards=5 --shard=0 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort > shardfile
../src/zmap -p 80 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 4 --shards=5 --shard=1 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile
../src/zmap -p 80 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 4 --shards=5 --shard=2 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile
../src/zmap -p 80 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 4 --shards=5 --shard=3 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile
../src/zmap -p 80 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 4 --shards=5 --shard=4 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile

cat shardfile | sort > temp
mv temp shardfile
echo "Line Count"
cat shardfile | wc -l
echo "Duplicate Count"
cat shardfile | uniq -d | wc -l


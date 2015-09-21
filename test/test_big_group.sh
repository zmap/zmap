#!/bin/sh

../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 5 --shards=5 --shard=0 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort > shardfile
../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 5 --shards=5 --shard=1 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile
../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 5 --shards=5 --shard=2 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile
../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 5 --shards=5 --shard=3 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile
../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 -T 5 --shards=5 --shard=4 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile

cat shardfile | sort > temp
mv temp shardfile
echo "Line Count: (Should be 65536)"
cat shardfile | wc -l
echo "Duplicate Count"
cat shardfile | uniq -d | wc -l

rm outfile
rm shardfile

../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 141.212.0.0/16 5.6.0.0/16 -T 4 --shards=5 --shard=0 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort > shardfile
../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 141.212.0.0/16 5.6.0.0/16 -T 4 --shards=5 --shard=1 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile
../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 141.212.0.0/16 5.6.0.0/16 -T 4 --shards=5 --shard=2 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile
../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 141.212.0.0/16 5.6.0.0/16 -T 4 --shards=5 --shard=3 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile
../src/zmap -p 80 -c 1 -b configs/blacklist_shard.conf --seed=1234 --dryrun 1.1.0.0/16 141.212.0.0/16 5.6.0.0/16 -T 4 --shards=5 --shard=4 > outfile
cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | sort >> shardfile

cat shardfile | sort > temp
mv temp shardfile
echo "Line Count: (Should be 196608)"
cat shardfile | wc -l
echo "Duplicate Count"
cat shardfile | uniq -d | wc -l

rm outfile
rm shardfile

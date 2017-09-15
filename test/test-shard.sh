#!/bin/bash
set -e

SHARDS=19
for i in {0..18}; do
	../src/zmap -v 5 -p 80 --dryrun -G 00:00:00:00:00:00 --seed 1234 --shards=$SHARDS --shard=$i 1.2.3.0/24 | grep daddr | awk '{print $7}' > s$i.scanned
	../src/zmap -v 5 -p 80 --dryrun -G 00:00:00:00:00:00 --seed 8675309 --shards=$SHARDS --shard=$i 1.2.3.0/24 -T 3 | grep daddr | awk '{print $7}' > t$i.scanned
done

SHARDS=258
for i in {0..257}; do
	../src/zmap -v 5 -p 80 --dryrun -G 00:00:00:00:00:00 --seed 11043 --shards=$SHARDS --shard=$i 1.2.0.0/16 | grep daddr | awk '{print $7}' > bs$i.scanned
	../src/zmap -v 5 -p 80 --dryrun -G 00:00:00:00:00:00 --seed 829 --shards=$SHARDS --shard=$i 1.2.0.0/16 -T 3 | grep daddr | awk '{print $7}' > bt$i.scanned
done


../src/zmap -v 5 -p 80 --dryrun -G 00:00:00:00:00:00 --seed 18172017 1.2.3.0/24 -T 3 | grep daddr | awk '{print $7}' > one_t3$i.scanned
../src/zmap -v 5 -p 80 --dryrun -G 00:00:00:00:00:00 --seed 13332727813 1.2.3.0/24 -T 1 | grep daddr | awk '{print $7}' > one_one$i.scanned

echo "19 Shards - Expect: 256"
cat s*.scanned | wc -l 
echo "Duplicates:"
cat s*.scanned | sort | uniq -d | wc -l
echo ""

echo "258 Shards - Expect: 65536"
cat bs*.scanned | wc -l 
echo "Duplicates:"
cat bs*.scanned | sort | uniq -d | wc -l
echo ""

echo "258 Shards, 3 Threads - Expect: 65536"
cat bt*.scanned | wc -l 
echo "Duplicates:"
cat bt*.scanned | sort | uniq -d | wc -l
echo ""



echo "19 Shards, 3 Threads - Expect: 256"
cat t*.scanned | wc -l 
echo "Duplicates:"
cat t*.scanned | sort | uniq -d | wc -l
echo ""

echo "1 Shard, 3 Threads - Expect: 256"
cat one_t*.scanned | wc -l 
echo "Duplicates:"
cat one_t*.scanned | sort | uniq -d | wc -l
echo ""

echo "1 Shard, 1 Thread - Expect: 256"
cat one_one*.scanned | wc -l 
echo "Duplicates:"
cat one_one*.scanned | sort | uniq -d | wc -l
echo ""


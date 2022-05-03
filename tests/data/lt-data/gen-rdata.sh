#!/bin/bash
for i in {0..9}
do 
	dd if=/dev/urandom of=if.$i.bin bs=1M count=5
done

cat if.0.bin > tst_5M.bin

cat if.0.bin if.1.bin > tst_10M.bin

cat if.0.bin if.1.bin if.2.bin if.3.bin if.4.bin > tst_25M.bin

cat if.0.bin if.1.bin if.2.bin if.3.bin if.4.bin if.5.bin if.6.bin if.7.bin if.8.bin if.9.bin > tst_50M.bin

cat tst_50M.bin tst_50M.bin > tst_100M.bin

cat tst_100M.bin tst_50M.bin tst_100M.bin > tst_250M.bin

cat tst_250M.bin tst_250M.bin > tst_500M.bin

for i in {0..9}
do 
	rm -rf if.$i.bin
done

ls -lh

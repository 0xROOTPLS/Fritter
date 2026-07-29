#!/bin/bash
set -e
cd /mnt/c/Users/Brent/Desktop/Fritter-main
make -f Makefile.linux fritter 2>&1 | tail -2
echo
echo "--- 30 invocations, picked register per run ---"
rm -f test/calc-r*.bin
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    LINE=$(./fritter -i test/calc.exe -o "test/calc-r$i.bin" 2>&1 | grep rspalign | head -1)
    echo "run $i: $LINE"
done
echo
echo "--- distribution of save_reg across 30 runs ---"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    grep -ao "save_reg=[0-9]*" "test/calc-r$i.bin" 2>/dev/null || true
done
ls test/calc-r*.bin | wc -l | xargs -I{} echo "{} bins generated"
echo
echo "--- save_reg counts ---"
{
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    ./fritter -i test/calc.exe -o /tmp/_throw.bin 2>&1 | grep rspalign | grep -oE "save_reg=[0-9]+"
done
} | sort | uniq -c

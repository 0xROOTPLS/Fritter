#!/bin/bash
set -e
cd /mnt/c/Users/Brent/Desktop/Fritter-main
make -f Makefile.linux fritter 2>&1 | tail -2
echo
echo "--- 30 invocations, picked tramp config per run ---"
rm -f test/calc-t*.bin
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    LINE=$(./fritter -i test/calc.exe -o "test/calc-t$i.bin" 2>&1 | grep "tramp" | head -1)
    echo "run $i: $LINE"
done
echo
echo "--- distribution of (lea_reg, jmp_form) across 30 runs ---"
{
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    ./fritter -i test/calc.exe -o /tmp/_throw.bin 2>&1 | grep tramp | grep -oE "lea_reg=[0-9]+ jmp=[A-Z_0-9]+"
done
} | sort | uniq -c

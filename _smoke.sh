#!/bin/bash
set -e
cd /mnt/c/Users/Brent/Desktop/Fritter-main
rm -f test/calc-*.bin
for i in 1 2 3 4 5 6 7 8 9 10; do
    echo "=== Build $i (seed=$i) ==="
    # Deterministic seed per build so calc-N.bin is reproducible.
    BUILD_LOG=$(FRITTER_BUILD_SEED=$i make -f Makefile.linux fritter 2>&1)
    POLY_LINE=$(echo "$BUILD_LOG" | grep -E '^\[poly\]' || echo "[poly line missing]")
    echo "$BUILD_LOG" | tail -1
    echo "$POLY_LINE"
    ./fritter -i test/calc.exe -o "test/calc-$i.bin" 2>&1 | tail -3
    SHIM_BYTES=$(wc -c < veh_shim_exe_x64.h)
    SHIM_SHA=$(sha256sum veh_shim_exe_x64.h | cut -c1-16)
    BIN_BYTES=$(wc -c < "test/calc-$i.bin")
    BIN_SHA=$(sha256sum "test/calc-$i.bin" | cut -c1-16)
    printf "  shim_x64.h: %6d bytes  sha=%s\n" "$SHIM_BYTES" "$SHIM_SHA"
    printf "  calc-%d.bin: %6d bytes  sha=%s\n" "$i" "$BIN_BYTES" "$BIN_SHA"
    echo
done
echo "=== ALL DONE ==="
ls -la test/calc-*.bin
echo "--- sha256 of all 10 calc bins ---"
sha256sum test/calc-*.bin

"""Seed-sweep timing harness for Fritter.

Builds N random-seed variants under each compiler (MSVC + gcc/mingw via WSL),
runs each loader.bin through test/inject_local64.exe, and times how long it
takes calc.exe to appear in the process list. Reports per-seed times and the
per-compiler average.

Run from a vcvars-activated cmd so nmake works. WSL with mingw-w64 + musl-gcc
must be installed for the gcc side.

Usage:
    python tools/seed_sweep.py           # default: 5 seeds per compiler
    python tools/seed_sweep.py --count 3 # 3 seeds per compiler
    python tools/seed_sweep.py --msvc-only
    python tools/seed_sweep.py --gcc-only
"""

import argparse
import ctypes
import os
import random
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"C:\Users\Brent\Desktop\Fritter-main")
INJECT_EXE = ROOT / "test" / "inject_local64.exe"
LOADER_BIN = ROOT / "test" / "loader.bin"
TARGET_PE  = "test\\calc.exe"  # passed verbatim to fritter
POP_TIMEOUT_S = 30.0           # if calc doesn't appear within this, declare failure
POLL_INTERVAL_S = 0.05

# WSL paths (Linux side of the mounted Windows directory)
WSL_ROOT = "/mnt/c/Users/Brent/Desktop/Fritter-main"

# Fritter reflectively loads calc.exe inside the inject_local64 host process,
# so there is no separate calc.exe process. Detection is by window. The
# Win7-era calc.exe (which test/calc.exe almost certainly is) uses class
# `CalcFrame` and title `Calculator`. We also probe a couple of fallbacks
# in case it's the UWP-era launcher.
_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32
CALC_WINDOW_CLASSES = ["CalcFrame", "CalcFrame32"]
CALC_WINDOW_TITLES  = ["Calculator", "Calculator​"]  # zero-width fallback

PROCESS_TERMINATE = 0x0001


def _find_calc_hwnd():
    """Return the first calc-like window handle found, or 0."""
    for cls in CALC_WINDOW_CLASSES:
        hwnd = _user32.FindWindowW(cls, None)
        if hwnd:
            return hwnd
    for title in CALC_WINDOW_TITLES:
        hwnd = _user32.FindWindowW(None, title)
        if hwnd:
            return hwnd
    return 0


def calc_window_present():
    """Return True if any calculator-like window is visible."""
    return _find_calc_hwnd() != 0


def _hwnd_owner_pid(hwnd):
    """Return the PID of the process owning hwnd, or 0."""
    pid = ctypes.c_uint(0)
    _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def kill_calc():
    """Force-kill whatever process owns the visible calc window.

    Calc is reflectively loaded INTO a host process - typically
    inject_local64.exe but we don't assume that. We resolve the window
    owner via GetWindowThreadProcessId and TerminateProcess it directly.
    Then we also taskkill /F any straggling inject_local64.exe as a
    belt-and-suspenders cleanup for the next iteration."""
    hwnd = _find_calc_hwnd()
    if hwnd:
        pid = _hwnd_owner_pid(hwnd)
        if pid:
            h = _kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if h:
                _kernel32.TerminateProcess(h, 1)
                _kernel32.CloseHandle(h)
    # Fallback - kill the host name even if no window is currently visible
    subprocess.run(
        ["taskkill", "/IM", "inject_local64.exe", "/F"],
        capture_output=True, timeout=5,
    )


def wait_until_no_calc(deadline_s=8.0):
    """Block until no calc-like window is visible, up to deadline."""
    end = time.perf_counter() + deadline_s
    while time.perf_counter() < end:
        if not calc_window_present():
            return True
        kill_calc()
        time.sleep(0.3)
    # Diagnostic: tell the user what stuck around
    hwnd = _find_calc_hwnd()
    if hwnd:
        owner_pid = _hwnd_owner_pid(hwnd)
        buf = ctypes.create_unicode_buffer(256)
        _user32.GetClassNameW(hwnd, buf, 256)
        print(f" [stuck: hwnd=0x{hwnd:x} pid={owner_pid} class='{buf.value}']", end="")
    return False


def build_msvc(seed):
    """Build the MSVC fritter pipeline for a given seed.

    Returns True on success.
    """
    env = os.environ.copy()
    env["FRITTER_BUILD_SEED"] = str(seed)
    try:
        subprocess.run(
            ["nmake", "/f", "Makefile.msvc", "clean"],
            cwd=ROOT, env=env, capture_output=True, timeout=60, check=True,
        )
        result = subprocess.run(
            ["nmake", "/f", "Makefile.msvc", "fritter"],
            cwd=ROOT, env=env, capture_output=True, timeout=300,
        )
        if result.returncode != 0:
            print(f"\n  nmake exit {result.returncode}, stderr tail:")
            print((result.stderr.decode(errors='ignore'))[-800:])
            return False
        if not (ROOT / "fritter.exe").exists():
            print(f"\n  build claimed success but fritter.exe missing; stdout tail:")
            print((result.stdout.decode(errors='ignore'))[-800:])
            return False
        return True
    except subprocess.TimeoutExpired:
        print("\n  MSVC build TIMED OUT")
        return False


def build_gcc(seed):
    """Build the gcc/mingw fritter pipeline via WSL for a given seed.

    Returns True on success.
    """
    cmd = (
        f"FRITTER_BUILD_SEED={seed} make -f Makefile.linux clean && "
        f"FRITTER_BUILD_SEED={seed} make -f Makefile.linux fritter"
    )
    try:
        result = subprocess.run(
            ["wsl", "--cd", WSL_ROOT, "bash", "-c", cmd],
            capture_output=True, timeout=300,
        )
        if result.returncode != 0:
            print(f"\n  wsl make exit {result.returncode}, stderr tail:")
            print((result.stderr.decode(errors='ignore'))[-800:])
            return False
        if not (ROOT / "fritter").exists():
            print(f"\n  build claimed success but fritter (linux binary) missing")
            return False
        return True
    except subprocess.TimeoutExpired:
        print("\n  gcc build TIMED OUT")
        return False


def generate_loader_msvc():
    """Generate loader.bin using the MSVC-built fritter.exe."""
    fritter_exe = ROOT / "fritter.exe"
    if not fritter_exe.exists():
        print(f" (fritter.exe not found at {fritter_exe})", end="")
        return False
    # Remove stale loader.bin first so we can distinguish failure from success
    if LOADER_BIN.exists():
        LOADER_BIN.unlink()
    try:
        result = subprocess.run(
            [str(fritter_exe), "-i", TARGET_PE, "-o", "test\\loader.bin"],
            cwd=ROOT, capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            print(f" (fritter exit {result.returncode}: "
                  f"{result.stderr.decode(errors='ignore')[:200]})", end="")
            return False
        return LOADER_BIN.exists()
    except subprocess.TimeoutExpired:
        return False


def generate_loader_gcc():
    """Generate loader.bin using the WSL-built ./fritter."""
    if LOADER_BIN.exists():
        LOADER_BIN.unlink()
    try:
        result = subprocess.run(
            ["wsl", "--cd", WSL_ROOT, "bash", "-c",
             f"./fritter -i {TARGET_PE.replace(chr(92), '/')} -o test/loader.bin"],
            capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            print(f" (wsl fritter exit {result.returncode}: "
                  f"{result.stderr.decode(errors='ignore')[:200]})", end="")
            return False
        return LOADER_BIN.exists()
    except subprocess.TimeoutExpired:
        return False


def time_loader_run():
    """Run inject_local64.exe loader.bin and return seconds until a calc
    window appears. Returns None on timeout."""
    # Make sure the previous run's host is REALLY gone before we start.
    # The host process owns the calc window via reflective load - if we
    # don't wait for both to be torn down, the next FindWindow will hit
    # the stale window and we'll record a ~0s false positive.
    if not wait_until_no_calc(deadline_s=5.0):
        print(" (stale calc never cleared)", end="")
        return None

    start = time.perf_counter()
    proc = subprocess.Popen(
        [str(INJECT_EXE), "test\\loader.bin"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    elapsed = None
    while time.perf_counter() - start < POP_TIMEOUT_S:
        if calc_window_present():
            elapsed = time.perf_counter() - start
            break
        # if the injector died early with no window, stop polling
        if proc.poll() is not None and not calc_window_present():
            break
        time.sleep(POLL_INTERVAL_S)

    # Cleanup
    kill_calc()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
    wait_until_no_calc(deadline_s=3.0)

    return elapsed


def sweep(compiler, seeds, build_fn, gen_fn):
    """Run the sweep for one compiler. Returns dict {seed: elapsed_or_None}."""
    results = {}
    for i, seed in enumerate(seeds, 1):
        print(f"\n[{compiler} {i}/{len(seeds)}] seed={seed}")
        print(f"  building...", end="", flush=True)
        if not build_fn(seed):
            results[seed] = None
            continue
        print(" generating loader.bin...", end="", flush=True)
        if not gen_fn():
            print(" FAILED")
            results[seed] = None
            continue
        print(" running injector...", end="", flush=True)
        elapsed = time_loader_run()
        if elapsed is not None:
            print(f" calc popped in {elapsed:.2f}s")
        else:
            print(f" TIMEOUT (>{POP_TIMEOUT_S}s)")
        results[seed] = elapsed
        time.sleep(0.5)  # let system settle between runs
    return results


def print_summary(all_results):
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for compiler, results in all_results.items():
        valid = [v for v in results.values() if v is not None]
        print(f"\n{compiler}:")
        for seed, elapsed in results.items():
            status = f"{elapsed:6.2f}s" if elapsed is not None else "TIMEOUT"
            print(f"  seed {seed:6d}: {status}")
        if valid:
            avg = sum(valid) / len(valid)
            mn  = min(valid)
            mx  = max(valid)
            print(f"  {len(valid)}/{len(results)} popped | avg={avg:.2f}s min={mn:.2f}s max={mx:.2f}s")
        else:
            print(f"  0/{len(results)} popped")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=5, help="seeds per compiler (default 5)")
    ap.add_argument("--msvc-only", action="store_true")
    ap.add_argument("--gcc-only",  action="store_true")
    ap.add_argument("--seed-range", type=int, nargs=2, default=[1, 1000],
                    metavar=("LO", "HI"), help="random seed range (inclusive)")
    args = ap.parse_args()

    if not INJECT_EXE.exists():
        print(f"ERROR: {INJECT_EXE} not found. Build it with: nmake /f Makefile.msvc harness")
        sys.exit(1)

    lo, hi = args.seed_range
    seeds_msvc = sorted(random.sample(range(lo, hi + 1), args.count))
    seeds_gcc  = sorted(random.sample(range(lo, hi + 1), args.count))

    print("=" * 60)
    print(f"Seed sweep ({args.count} per compiler)")
    if not args.gcc_only:
        print(f"  MSVC seeds: {seeds_msvc}")
    if not args.msvc_only:
        print(f"  gcc  seeds: {seeds_gcc}")
    print(f"  timeout per run: {POP_TIMEOUT_S}s")
    print("=" * 60)

    all_results = {}
    if not args.gcc_only:
        all_results["MSVC"] = sweep("MSVC", seeds_msvc, build_msvc, generate_loader_msvc)
    if not args.msvc_only:
        all_results["gcc"] = sweep("gcc",  seeds_gcc,  build_gcc,  generate_loader_gcc)

    print_summary(all_results)


if __name__ == "__main__":
    main()

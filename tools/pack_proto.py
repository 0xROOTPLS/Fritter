"""
Prototype of exe2h's pack-on-extract pass.

Approach (validated empirically before porting to C):
  1. Parse PE: enumerate CODE sections and pdata function ranges.
  2. Find cross-section RIP-relative references using brute-force byte
     scan with pdata validation:
       - E8 disp32   CALL rel32      -> disp lands at a pdata fn start
       - REX? 8D ModR/M(mod=00 rm=101) disp32  LEA rip+disp32
       - REX? {88,89,8A,8B} ModR/M(mod=00 rm=101) disp32  MOV rip+disp32
     pdata function-start validation makes false-positive rate ~0.
  3. Decide a packed layout: try all permutations of the non-.text
     sections, pick the one that minimizes total blob size while
     keeping every "hot" section in a single 4 KiB page.
  4. Copy each section's bytes to the new offset and rewrite every
     cross-section disp32 to point to the new target offset.

Goal: produce a near-NOP-free blob (current MSVC build is 46% NOPs
with four >=2 KiB sleds; this should bring NOPs down to <5%).
"""

import struct
import sys
from itertools import permutations
from pathlib import Path

# === PE parsing ===

def parse_pe(path):
    data = Path(path).read_bytes()
    # DOS header e_lfanew at 0x3C
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    pe = e_lfanew
    sig = data[pe:pe+4]
    assert sig == b'PE\x00\x00', f"bad PE sig: {sig!r}"
    # IMAGE_FILE_HEADER at pe+4
    fh = pe + 4
    num_sections = struct.unpack_from('<H', data, fh + 2)[0]
    sz_opt = struct.unpack_from('<H', data, fh + 16)[0]
    opt = fh + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    is64 = (magic == 0x20B)
    # Section table follows optional header
    sec_off = opt + sz_opt
    sections = []
    for i in range(num_sections):
        ent = sec_off + i * 40
        name = data[ent:ent+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, ent + 8)
        chars = struct.unpack_from('<I', data, ent + 36)[0]
        sections.append({
            'name': name,
            'vaddr': vaddr,
            'vsize': vsize,
            'rsize': rsize,
            'raddr': raddr,
            'chars': chars,
            'is_code': bool(chars & 0x00000020),  # IMAGE_SCN_CNT_CODE
        })
    # DataDirectory: pdata is index 3 in some PE layouts; on x64 it's index 3 (EXCEPTION_TABLE)
    # OptionalHeader64 NumberOfRvaAndSizes is at opt+108 (for PE32+).
    # DataDirectory starts at opt+112
    dd_off = opt + (96 if not is64 else 112)
    # Index 3 = IMAGE_DIRECTORY_ENTRY_EXCEPTION (pdata)
    pdata_rva, pdata_size = struct.unpack_from('<II', data, dd_off + 3*8)
    return {
        'data': data,
        'sections': sections,
        'pdata_rva': pdata_rva,
        'pdata_size': pdata_size,
    }

def rva_to_offset(sections, rva):
    for s in sections:
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rsize']):
            return s['raddr'] + (rva - s['vaddr'])
    return None

def parse_pdata(pe):
    """Return list of (begin_rva, end_rva) for each function."""
    pdata_off = rva_to_offset(pe['sections'], pe['pdata_rva'])
    funcs = []
    n = pe['pdata_size'] // 12
    for i in range(n):
        begin, end, unwind = struct.unpack_from('<III', pe['data'], pdata_off + i*12)
        if begin == 0 and end == 0:
            continue
        funcs.append((begin, end))
    return funcs

# === Section -> bytes ===

def section_bytes(pe, sec):
    return pe['data'][sec['raddr']:sec['raddr'] + min(sec['vsize'], sec['rsize'])]

def section_of_rva(sections, rva, code_only=True):
    for s in sections:
        if code_only and not s['is_code']:
            continue
        if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
            return s
    return None

# === Cross-section reference finder ===

def find_cross_section_refs(pe):
    code_secs = [s for s in pe['sections'] if s['is_code']]
    funcs = parse_pdata(pe)
    func_starts = {begin for begin, _ in funcs}

    refs = []   # list of dicts: {kind, sec, offset_in_sec, disp_off_in_inst, target_rva, target_sec}

    for sec in code_secs:
        sb = section_bytes(pe, sec)
        sec_vaddr = sec['vaddr']
        i = 0
        L = len(sb)
        while i < L:
            b = sb[i]

            # E8 disp32 - CALL rel32 (5 bytes)
            if b == 0xE8 and i + 5 <= L:
                disp = struct.unpack_from('<i', sb, i+1)[0]
                cur_rva = sec_vaddr + i
                target_rva = (cur_rva + 5 + disp) & 0xFFFFFFFF
                if target_rva in func_starts:
                    tgt_sec = section_of_rva(pe['sections'], target_rva)
                    if tgt_sec and tgt_sec['name'] != sec['name']:
                        refs.append({
                            'kind': 'CALL', 'sec': sec, 'inst_off': i, 'disp_off': 1,
                            'inst_len': 5, 'target_rva': target_rva, 'target_sec': tgt_sec,
                        })

            # E9 disp32 - JMP rel32 (5 bytes) - same validation
            if b == 0xE9 and i + 5 <= L:
                disp = struct.unpack_from('<i', sb, i+1)[0]
                cur_rva = sec_vaddr + i
                target_rva = (cur_rva + 5 + disp) & 0xFFFFFFFF
                tgt_sec = section_of_rva(pe['sections'], target_rva)
                if tgt_sec and tgt_sec['name'] != sec['name'] and target_rva in func_starts:
                    refs.append({
                        'kind': 'JMP', 'sec': sec, 'inst_off': i, 'disp_off': 1,
                        'inst_len': 5, 'target_rva': target_rva, 'target_sec': tgt_sec,
                    })

            # 0F 8x disp32 - Jcc rel32 (6 bytes)
            if b == 0x0F and i + 6 <= L and (sb[i+1] & 0xF0) == 0x80:
                disp = struct.unpack_from('<i', sb, i+2)[0]
                cur_rva = sec_vaddr + i
                target_rva = (cur_rva + 6 + disp) & 0xFFFFFFFF
                tgt_sec = section_of_rva(pe['sections'], target_rva)
                if tgt_sec and tgt_sec['name'] != sec['name'] and target_rva in func_starts:
                    refs.append({
                        'kind': 'Jcc', 'sec': sec, 'inst_off': i, 'disp_off': 2,
                        'inst_len': 6, 'target_rva': target_rva, 'target_sec': tgt_sec,
                    })

            # LEA / MOV with RIP-relative addressing
            # Pattern: [REX] {opcode} {ModR/M with mod=00 rm=101} {disp32}
            # opcodes of interest: 8D (LEA), 88-8B (MOV r/m,r), most ALU 00-3D
            # We only validate by target landing in another section.
            for rex_len in (0, 1):
                if rex_len == 1:
                    if not (0x40 <= b <= 0x4F):
                        continue
                    base = i + 1
                else:
                    base = i
                if base + 6 > L:
                    continue
                op = sb[base]
                # Common opcodes that take ModR/M and reach memory
                if op == 0x8D:  # LEA
                    kind = 'LEA'
                elif op in (0x88, 0x89, 0x8A, 0x8B):  # MOV
                    kind = 'MOV'
                else:
                    continue
                modrm = sb[base + 1]
                if (modrm & 0xC7) != 0x05:
                    continue
                disp = struct.unpack_from('<i', sb, base + 2)[0]
                inst_len = (base + 6) - i
                cur_rva = sec_vaddr + i
                inst_end_rva = sec_vaddr + base + 6
                target_rva = (inst_end_rva + disp) & 0xFFFFFFFF
                tgt_sec = section_of_rva(pe['sections'], target_rva)
                if tgt_sec and tgt_sec['name'] != sec['name']:
                    refs.append({
                        'kind': kind, 'sec': sec, 'inst_off': i,
                        'disp_off': base + 2 - i, 'inst_len': inst_len,
                        'target_rva': target_rva, 'target_sec': tgt_sec,
                    })
                # Only check once per position - don't double-count rex/no-rex
                break

            i += 1

    return refs

# === Layout planner ===

PAGE = 0x1000

def section_fits_single_page(start, size):
    if size > PAGE:
        return False
    return (start >> 12) == ((start + size - 1) >> 12)

def plan_layout(code_secs, hot_sec_names):
    """Try all permutations of code_secs (keeping the .text-section-with-FritterLoader
       first), pick the layout with smallest total size where every hot section
       fits in a single page.
    """
    # Identify the "first" section: it must contain the loader entry point.
    # By convention this is the section containing RVA 0x1000 (.text$a content).
    code_secs_sorted = sorted(code_secs, key=lambda s: s['vaddr'])
    first = code_secs_sorted[0]
    rest = code_secs_sorted[1:]

    best_total = None
    best_layout = None
    for perm in permutations(rest):
        layout = []
        offset = 0
        # First section at 0
        layout.append((first, offset))
        offset += first['vsize']
        ok = True
        for sec in perm:
            sz = sec['vsize']
            if sec['name'] in hot_sec_names:
                # Check if would straddle a page
                if not section_fits_single_page(offset, sz):
                    # Bump to next page
                    offset = (offset + 0xFFF) & ~0xFFF
            layout.append((sec, offset))
            offset += sz
        if best_total is None or offset < best_total:
            best_total = offset
            best_layout = layout
    return best_layout, best_total

# === Pretty-print ===

def main(path):
    pe = parse_pe(path)
    code_secs = [s for s in pe['sections'] if s['is_code']]
    funcs = parse_pdata(pe)

    print(f"=== {path} ===")
    print(f"Code sections: {len(code_secs)}")
    for s in code_secs:
        print(f"  {s['name']:10s}  vaddr=0x{s['vaddr']:05X}  vsize=0x{s['vsize']:05X} ({s['vsize']} bytes)")
    print(f"pdata function count: {len(funcs)}")

    refs = find_cross_section_refs(pe)
    print(f"\nCross-section references found: {len(refs)}")
    by_kind = {}
    for r in refs:
        by_kind.setdefault(r['kind'], []).append(r)
    for kind, lst in sorted(by_kind.items()):
        print(f"  {kind}: {len(lst)}")

    # Layout planning
    if len(code_secs) > 1:
        hot = {'.hash_chain', '.cipher', '.aP_depack', '.hash_ch', '.aP_depa'}
        layout, total = plan_layout(code_secs, hot)
        print(f"\nProposed packed layout (total {total} bytes):")
        for sec, off in layout:
            page = off >> 12
            end = off + sec['vsize']
            end_page = (end - 1) >> 12
            note = f"page {page}" if page == end_page else f"pages {page}..{end_page}"
            print(f"  {sec['name']:10s} -> 0x{off:05X}..0x{end:05X}  ({note})")
        # Current size for comparison
        current_blob_size = max(s['vaddr'] + s['vsize'] for s in code_secs) - min(s['vaddr'] for s in code_secs)
        nops_now = current_blob_size - sum(s['vsize'] for s in code_secs)
        nops_packed = total - sum(s['vsize'] for s in code_secs)
        print(f"\nCurrent blob size: {current_blob_size} bytes ({nops_now} NOPs, {100*nops_now/current_blob_size:.1f}%)")
        print(f"Packed blob size:  {total} bytes ({nops_packed} NOPs, {100*nops_packed/total:.1f}%)")
        print(f"Savings:           {current_blob_size - total} bytes ({100*(current_blob_size-total)/current_blob_size:.1f}%)")

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'loader_peb1.exe')
